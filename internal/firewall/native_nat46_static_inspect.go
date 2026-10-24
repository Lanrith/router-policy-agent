package firewall

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// staticInventory derives headers and permanent identity data independently
// from the opaque compiler geometry. It neither validates a whole caller graph
// nor turns the observed configuration channel into publication evidence.
func (sources *nativeNAT46StaticSources) staticInventory(ctx context.Context, family string) (*guardTableSchema, map[string][]json.RawMessage, error) {
	if sources == nil || ctx == nil || family != "inet" && family != "netdev" {
		return nil, nil, errors.New("firewall: missing static nat46 inventory dependencies")
	}
	snapshot, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	schema := &guardTableSchema{sets: map[string]map[string]any{}, maps: map[string]map[string]any{}, chains: map[string]map[string]any{}, rules: map[string][][]any{}}
	data := map[string][]json.RawMessage{nativeNAT46StaticBindings6: {}}
	schema.sets[nativeNAT46StaticBindings6] = guardSetHeader(family, nativeNAT46StaticBindings6, []string{"mark", "classid", "ipv6_addr"}, policy.MaximumNAT46StaticSources)
	names := nat46StaticInterfaces(snapshot)
	if family == "inet" {
		header := guardSetHeader(family, nativeNAT46StaticChannel, []string{"mark", "classid"}, 1024)
		header["map"] = "classid"
		schema.maps[nativeNAT46StaticChannel] = header
		for index := range names {
			name := fmt.Sprintf("native_n46_static_ids_%d", index)
			header := guardSetHeader(family, name, map[string]any{"typeof": nativeRawPayload(96)}, policy.MaximumNAT46StaticSources)
			header["map"] = "classid"
			schema.maps[name], data[name] = header, []json.RawMessage{}
		}
		rawType := map[string]any{"typeof": map[string]any{"concat": []any{guardMeta("mark"), guardMeta("priority"), nativeRawPayload(96)}}}
		schema.sets[nativeNAT46StaticBits4] = guardSetHeader(family, nativeNAT46StaticBits4, rawType, policy.MaximumNAT46StaticSources)
		data[nativeNAT46StaticBits4] = []json.RawMessage{}
	} else {
		schema.sets[nativeNAT46StaticReturn4] = guardSetHeader(family, nativeNAT46StaticReturn4, []string{"ifname", "mark", "classid", "ipv4_addr"}, policy.MaximumNAT46StaticSources)
		data[nativeNAT46StaticReturn4] = []json.RawMessage{}
	}
	indexes := map[string]int{}
	for index, name := range names {
		indexes[name] = index
	}
	for _, source := range snapshot.Sources {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		high, low := (source.ID>>10)<<13, nativeLowClassID(source.ID)
		bits := source.Original.As4()
		rows := map[string]any{nativeNAT46StaticBindings6: map[string]any{"concat": []any{high, low, source.Embedded.String()}}}
		if family == "inet" {
			rows[nativeNAT46StaticBits4] = map[string]any{"concat": []any{high, low, binary.BigEndian.Uint32(bits[:])}}
			rows[fmt.Sprintf("native_n46_static_ids_%d", indexes[source.Interface])] = []any{binary.BigEndian.Uint32(bits[:]), epochClassID(source.ID)}
		} else {
			rows[nativeNAT46StaticReturn4] = map[string]any{"concat": []any{source.Interface, high, low, source.Original.String()}}
		}
		for name, row := range rows {
			raw, err := json.Marshal(row)
			if err != nil {
				return nil, nil, errors.New("firewall: static nat46 identity encoding failed")
			}
			data[name] = append(data[name], raw)
		}
	}
	return schema, data, ctx.Err()
}

// Headers must already match staticInventory's fixed schema. This comparison
// rejects any changed permanent row, including a reassigned source ID. The
// mutable channel is checked separately against the current configuration.
func (sources *nativeNAT46StaticSources) inspectStaticIdentities(ctx context.Context, family string, observed *guardTableObservation) error {
	if observed == nil {
		return errors.New("firewall: missing static nat46 identity observation")
	}
	_, expected, err := sources.staticInventory(ctx, family)
	if err != nil {
		return err
	}
	for name, rows := range expected {
		actual, exists := observed.sets[name]
		if !exists {
			return errors.New("firewall: missing static nat46 identity object")
		}
		if err := sameGuardElements(ctx, actual.Elements, rows); err != nil {
			return err
		}
	}
	return ctx.Err()
}
