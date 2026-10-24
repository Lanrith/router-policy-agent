package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nat46StaticSourceSchema(schema *guardTableSchema, family string) {
	live := guardSetHeader(family, nativeNAT46StaticSourceLive, []string{"classid", "classid"}, 1024)
	live["flags"], live["timeout"] = []string{"timeout"}, 90
	schema.sets[nativeNAT46StaticSourceLive] = live
	if family == "inet" {
		header := guardSetHeader(family, nativeNAT46StaticSourceChannel, []string{"mark", "classid"}, 1024)
		header["map"], header["flags"], header["timeout"] = "classid", []string{"timeout"}, 90
		schema.maps[nativeNAT46StaticSourceChannel] = header
	}
}

// Observation can reject malformed or stale channel data, never renew it or
// supply a publication receipt. Positive rows must cover exactly the original
// geometry's low identities under the independently checked current epoch.
func (sources *nativeNAT46StaticSources) inspectSourceEpoch(ctx context.Context, inet, netdev *guardTableObservation) error {
	if ctx == nil || sources == nil || inet == nil || netdev == nil {
		return errors.New("firewall: missing nat46 source channel observation")
	}
	geometry, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	rows, err := nativeSourceMapRows(ctx, inet.sets[nativeNAT46StaticSourceChannel].Elements, 1024)
	if err != nil {
		return err
	}
	first, err := listedGuardLeases(ctx, inet.sets[nativeNAT46StaticSourceLive].Elements)
	if err != nil {
		return err
	}
	second, err := listedGuardLeases(ctx, netdev.sets[nativeNAT46StaticSourceLive].Elements)
	if err != nil {
		return err
	}
	if len(rows)+len(first)+len(second) == 0 {
		return ctx.Err()
	}
	epochs, err := listedGuardLeases(ctx, inet.sets[ownershipEpochSet].Elements)
	if err != nil {
		return err
	}
	var epoch struct {
		Value   uint32 `json:"val"`
		Timeout int    `json:"timeout"`
	}
	if len(epochs) != 1 || decodeNested(epochs[0], "elem", &epoch, []string{"val", "timeout"}) != nil || epoch.Value == 0 || epoch.Value&ownershipRuleMask != 0 || epoch.Value>>policy.OwnershipRuleBits > policy.MaximumOwnershipEpoch {
		return errors.New("firewall: nat46 source channel lacks current ownership epoch")
	}
	lows := []uint32{}
	for _, source := range geometry.Sources {
		lows = append(lows, source.ID&ownershipRuleMask)
	}
	slices.Sort(lows)
	lows = slices.Compact(lows)
	if len(rows) != len(lows) {
		return errors.New("firewall: nat46 source channel changed static identity inventory")
	}
	timeout := 0
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		var pair []json.RawMessage
		if json.Unmarshal(row, &pair) != nil || len(pair) != 2 {
			return errors.New("firewall: invalid nat46 source channel row")
		}
		var key nativeSourceTimed
		if decodeNested(pair[0], "elem", &key, []string{"val", "timeout"}) != nil || len(key.Value.Fields) != 2 || key.Timeout < 1 || key.Timeout > epoch.Timeout {
			return errors.New("firewall: nat46 source channel escaped epoch deadline")
		}
		if timeout == 0 {
			timeout = key.Timeout
		} else if timeout != key.Timeout {
			return errors.New("firewall: nat46 source channel split original deadlines")
		}
	}
	expectedRows, expectedLive := []json.RawMessage{}, []json.RawMessage{}
	for _, low := range lows {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := map[string]any{"concat": []any{epoch.Value, nativeLowClassID(low)}}
		row, err := json.Marshal([]any{nativeTimedValue(key, timeout), epochClassID(epoch.Value | low)})
		if err != nil {
			return err
		}
		expectedRows = append(expectedRows, row)
		live, err := json.Marshal(nativeTimedValue(map[string]any{"concat": []any{epochClassID(epoch.Value), nativeLowClassID(low)}}, timeout))
		if err != nil {
			return err
		}
		expectedLive = append(expectedLive, live)
	}
	if err := sameGuardElements(ctx, rows, expectedRows); err != nil {
		return err
	}
	for _, actual := range [][]json.RawMessage{first, second} {
		if err := sameGuardElements(ctx, actual, expectedLive); err != nil {
			return err
		}
	}
	return ctx.Err()
}
