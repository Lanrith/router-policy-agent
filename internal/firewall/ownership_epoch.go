package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	ownershipEpochSet  = "current_ownership_epoch"
	ownershipEpochMap  = "ownership_epoch_by_family"
	ownershipRuleMask  = uint32(1<<policy.OwnershipRuleBits) - 1
	ownershipEpochMask = uint32(math.MaxUint32) ^ ownershipRuleMask
)

func ownershipEpochDefinitions() []string {
	return []string{
		"set " + ownershipEpochSet + " { type mark; flags timeout; timeout 90s; size 1; }",
		"map " + ownershipEpochMap + " { type nf_proto : mark; flags timeout; timeout 90s; size 2; }",
	}
}

func ownershipEpochHeader(name string, mapping bool) map[string]any {
	datatype, size := "mark", 1
	if mapping {
		datatype, size = "nf_proto", 2
	}
	result := guardSetHeader("inet", name, datatype, size)
	result["flags"], result["timeout"] = []string{"timeout"}, 90
	if mapping {
		result["map"] = "mark"
	}
	return result
}

func ownershipEpochChanges(epoch uint32, timeout int) ([]any, error) {
	ref := func(name string) objectReference {
		return objectReference{Family: "inet", Table: ownedTable, Name: name}
	}
	changes := []any{
		map[string]any{"flush": map[string]any{"set": ref(ownershipEpochSet)}},
		map[string]any{"flush": map[string]any{"map": ref(ownershipEpochMap)}},
	}
	channel, err := epochChannelChanges(false, epoch, timeout)
	if err != nil {
		return nil, err
	}
	changes = append(changes, channel...)
	if epoch == 0 && timeout == 0 {
		return changes, nil
	}
	if epoch == 0 || epoch > policy.MaximumOwnershipEpoch || timeout < 1 || timeout > maximumElementLifetime {
		return nil, errors.New("firewall: invalid ownership epoch or deadline")
	}
	kernelEpoch := epoch << policy.OwnershipRuleBits
	element := func(value any) any {
		return map[string]any{"elem": map[string]any{"val": value, "timeout": timeout}}
	}
	for _, item := range []struct {
		name   string
		values []any
	}{
		{ownershipEpochSet, []any{element(kernelEpoch)}},
		{ownershipEpochMap, []any{[]any{element("ipv4"), kernelEpoch}, []any{element("ipv6"), kernelEpoch}}},
	} {
		changes = append(changes, map[string]any{"add": map[string]any{"element": map[string]any{
			"family": "inet", "table": ownedTable, "name": item.name, "elem": item.values,
		}}})
	}
	return changes, nil
}

func ownershipEpochTimeout(evidence policy.Ownership, utc time.Time) (int, error) {
	remaining, err := evidence.EpochRemaining(utc)
	if err != nil {
		return 0, err
	}
	timeout := int((remaining - preparationBudget - commandBudget) / time.Second)
	if timeout < 1 || timeout > maximumElementLifetime {
		return 0, errors.New("firewall: ownership epoch has insufficient remaining lifetime")
	}
	return timeout, nil
}

// Inspection checks only consistency of observed mirrors. It cannot turn a
// listing into fresh evidence or reconstruct the helper's consumed sequence.
func inspectOwnershipEpoch(ctx context.Context, inet *guardTableObservation) error {
	values, err := listedGuardLeases(ctx, inet.sets[ownershipEpochSet].Elements)
	if err != nil || len(values) > 1 {
		return errors.New("firewall: invalid ownership epoch observation")
	}
	mappings := inet.sets[ownershipEpochMap].Elements
	if len(values) == 0 && len(mappings) == 0 {
		return ctx.Err()
	}
	if len(values) != 1 || len(mappings) != 2 {
		return errors.New("firewall: incomplete ownership epoch mirrors")
	}
	var epoch struct {
		Value   uint32 `json:"val"`
		Timeout int    `json:"timeout"`
	}
	if err := decodeNested(values[0], "elem", &epoch, []string{"val", "timeout"}); err != nil {
		return err
	}
	if epoch.Value == 0 || epoch.Value&ownershipRuleMask != 0 ||
		epoch.Value>>policy.OwnershipRuleBits > policy.MaximumOwnershipEpoch {
		return errors.New("firewall: reserved ownership epoch observation")
	}
	seen := map[string]bool{}
	for _, mapping := range mappings {
		if err := ctx.Err(); err != nil {
			return err
		}
		var pair []json.RawMessage
		if err := json.Unmarshal(mapping, &pair); err != nil || len(pair) != 2 {
			return errors.New("firewall: malformed ownership epoch map")
		}
		var key struct {
			Value   string `json:"val"`
			Timeout int    `json:"timeout"`
			Expires uint64 `json:"expires"`
		}
		if err := decodeNested(pair[0], "elem", &key, []string{"val", "timeout", "expires"}); err != nil {
			return err
		}
		var value uint32
		if err := json.Unmarshal(pair[1], &value); err != nil || value != epoch.Value || key.Timeout != epoch.Timeout ||
			key.Expires > uint64(epoch.Timeout) || key.Value != "ipv4" && key.Value != "ipv6" || seen[key.Value] { // #nosec G115 -- listedGuardLeases bounds timeout to 1..87.
			return errors.New("firewall: ownership epoch map differs from its observed set")
		}
		seen[key.Value] = true
	}
	return ctx.Err()
}
