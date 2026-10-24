package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func epochChannelNames(configuration bool) (string, string) {
	if configuration {
		return "configuration_epoch_channel", "configuration_egress_epoch"
	}
	return "ownership_epoch_channel", "ownership_egress_epoch"
}

func epochChannelDefinitions(configuration bool, family string) []string {
	mapping, set := epochChannelNames(configuration)
	flags := ""
	if !configuration {
		flags = " flags timeout; timeout 90s;"
	}
	if family == "inet" {
		return []string{"map " + mapping + " { type mark : classid;" + flags + " size 1; }"}
	}
	if family == "netdev" {
		return []string{"set " + set + " { type classid;" + flags + " size 1; }"}
	}
	return nil
}

func epochChannelHeaders(configuration bool) (map[string]any, map[string]any) {
	mapping, set := epochChannelNames(configuration)
	first := guardSetHeader("inet", mapping, "mark", 1)
	first["map"] = "classid"
	second := guardSetHeader("netdev", set, "classid", 1)
	if !configuration {
		for _, header := range []map[string]any{first, second} {
			header["flags"], header["timeout"] = []string{"timeout"}, 90
		}
	}
	return first, second
}

func epochClassID(base uint32) string {
	return fmt.Sprintf("%x:%x", base>>16, base&0xffff)
}

func parseEpochClassID(value string) (uint32, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[0]) > 4 || len(parts[1]) > 4 {
		return 0, errors.New("firewall: malformed epoch class identifier")
	}
	high, firstErr := strconv.ParseUint(parts[0], 16, 16)
	low, secondErr := strconv.ParseUint(parts[1], 16, 16)
	if firstErr != nil || secondErr != nil {
		return 0, errors.New("firewall: invalid epoch class identifier")
	}
	base := uint32(high)<<16 | uint32(low) // #nosec G115 -- ParseUint limits both halves to 16 bits.
	if base == 0 || base&ownershipRuleMask != 0 || base>>policy.OwnershipRuleBits > policy.MaximumOwnershipEpoch || epochClassID(base) != value {
		return 0, errors.New("firewall: unaligned or noncanonical epoch class identifier")
	}
	return base, nil
}

func epochChannelChanges(configuration bool, epoch uint32, timeout int) ([]any, error) {
	mapping, set := epochChannelNames(configuration)
	operations := []any{
		map[string]any{"flush": map[string]any{"map": objectReference{Family: "inet", Table: ownedTable, Name: mapping}}},
		map[string]any{"flush": map[string]any{"set": objectReference{Family: "netdev", Table: ownedTable, Name: set}}},
	}
	if epoch == 0 && timeout == 0 {
		return operations, nil
	}
	if epoch == 0 || epoch > policy.MaximumOwnershipEpoch || configuration && timeout != 0 ||
		!configuration && (timeout < 1 || timeout > maximumElementLifetime) {
		return nil, errors.New("firewall: invalid epoch channel identity or lifetime")
	}
	base := epoch << policy.OwnershipRuleBits
	key, value := any(base), any(epochClassID(base))
	if !configuration {
		key = map[string]any{"elem": map[string]any{"val": base, "timeout": timeout}}
		value = map[string]any{"elem": map[string]any{"val": epochClassID(base), "timeout": timeout}}
	}
	for _, item := range []struct {
		family, name string
		values       []any
	}{
		{"inet", mapping, []any{[]any{key, epochClassID(base)}}},
		{"netdev", set, []any{value}},
	} {
		operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{
			"family": item.family, "table": ownedTable, "name": item.name, "elem": item.values,
		}}})
	}
	return operations, nil
}

func inspectEpochChannel(ctx context.Context, configuration bool, inet, netdev *guardTableObservation) error {
	mapping, set := epochChannelNames(configuration)
	values, pairs := netdev.sets[set].Elements, inet.sets[mapping].Elements
	baseSet := ownershipEpochSet
	if configuration {
		baseSet = configurationEpochSet
	} else {
		var err error
		values, err = listedGuardLeases(ctx, values)
		if err != nil {
			return err
		}
	}
	bases := inet.sets[baseSet].Elements
	if len(values) == 0 && len(pairs) == 0 && len(bases) == 0 {
		return ctx.Err()
	}
	if len(values) != 1 || len(pairs) != 1 || len(bases) != 1 {
		return errors.New("firewall: incomplete physical epoch channel")
	}
	var pair []json.RawMessage
	if err := json.Unmarshal(pairs[0], &pair); err != nil || len(pair) != 2 {
		return errors.New("firewall: malformed physical epoch map")
	}
	key, output, original, class := pair[0], pair[1], bases[0], values[0]
	if !configuration {
		keys, err := listedGuardLeases(ctx, []json.RawMessage{key})
		if err != nil {
			return err
		}
		originals, err := listedGuardLeases(ctx, bases)
		if err != nil {
			return err
		}
		if err := sameGuardElements(ctx, keys, originals); err != nil {
			return err
		}
		var timed struct {
			Value   json.RawMessage `json:"val"`
			Timeout int             `json:"timeout"`
		}
		if err := decodeNested(values[0], "elem", &timed, []string{"val", "timeout"}); err != nil {
			return err
		}
		class = timed.Value
		var baseline struct {
			Value   json.RawMessage `json:"val"`
			Timeout int             `json:"timeout"`
		}
		if err := decodeNested(originals[0], "elem", &baseline, []string{"val", "timeout"}); err != nil || timed.Timeout != baseline.Timeout {
			return errors.New("firewall: physical epoch lifetime differs from its source")
		}
		key, original = baseline.Value, baseline.Value
	}
	var first, second uint32
	var classID, mapped string
	if err := json.Unmarshal(key, &first); err != nil {
		return err
	}
	if err := json.Unmarshal(original, &second); err != nil || first != second {
		return errors.New("firewall: physical epoch map changed its admitted key")
	}
	if err := json.Unmarshal(class, &classID); err != nil {
		return err
	}
	if err := json.Unmarshal(output, &mapped); err != nil || classID != mapped {
		return errors.New("firewall: physical epoch mirrors differ")
	}
	base, err := parseEpochClassID(classID)
	if err != nil || base != first {
		return errors.New("firewall: physical epoch does not preserve the admitted generation")
	}
	return ctx.Err()
}
