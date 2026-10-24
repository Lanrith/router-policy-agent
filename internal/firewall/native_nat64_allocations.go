package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const nativeNAT64ReadinessLifetime = 90 * time.Second

// nativeNAT64Readiness is sealed to this package. Its production implementation
// must verify the live translator and installed static mappings; configuration
// booleans and observed nftables objects cannot implement this interface.
type nativeNAT64Readiness interface {
	verifyNAT64Readiness(context.Context, *nativeNAT64Transport, []policy.NAT64Allocation) error
}

// preparedNAT64Allocations retains every original dependency used to mint its
// timed kernel publication. It is not a durable allocation record or permission.
type preparedNAT64Allocations struct {
	batch     preparedBatch
	transport *nativeNAT64Transport
	ledger    *policy.NAT64AllocationLedger
	readiness nativeNAT64Readiness
	entries   []policy.NAT64Allocation
	timeout   int
	digest    [sha256.Size]byte
	clear     bool
}

func prepareNativeNAT64Allocations(ctx context.Context, transport *nativeNAT64Transport, ledger *policy.NAT64AllocationLedger, readiness nativeNAT64Readiness) (*preparedNAT64Allocations, error) {
	started := time.Now()
	if ctx == nil || transport == nil || transport.geometry == nil || ledger == nil || readiness == nil {
		return nil, errors.New("firewall: missing NAT64 allocation publication dependencies")
	}
	entries, err := transport.geometry.ValidateLedger(ctx, transport.component, ledger)
	if err != nil {
		return nil, err
	}
	timeout := int((nativeNAT64ReadinessLifetime - preparationBudget - commandBudget) / time.Second)
	if timeout < 1 || timeout > maximumElementLifetime {
		return nil, errors.New("firewall: invalid NAT64 readiness lifetime")
	}
	prepared := &preparedNAT64Allocations{transport: transport, ledger: ledger, readiness: readiness, entries: entries, timeout: timeout}
	data, err := prepared.expectedData(ctx)
	if err != nil {
		return nil, err
	}
	now := started.UTC()
	prepared.batch = preparedBatch{data: data, preparedAt: now, startBefore: now.Add(preparationBudget), startedAt: started}
	prepared.digest = sha256.Sum256(data)
	return prepared, ctx.Err()
}

func (prepared *preparedNAT64Allocations) expectedData(ctx context.Context) ([]byte, error) {
	rows, err := prepared.elements(ctx)
	if err != nil {
		return nil, err
	}
	operations := []any{
		map[string]any{"flush": map[string]any{"map": objectReference{Family: "inet", Table: ownedTable, Name: prepared.transport.name + "_zones"}}},
		map[string]any{"flush": map[string]any{"map": objectReference{Family: "inet", Table: ownedTable, Name: prepared.transport.name + "_aliases"}}},
		map[string]any{"flush": map[string]any{"set": objectReference{Family: "inet", Table: ownedTable, Name: prepared.transport.name + "_active_aliases"}}},
		map[string]any{"flush": map[string]any{"set": objectReference{Family: "inet", Table: ownedTable, Name: prepared.transport.name + "_sources"}}},
	}
	for index, name := range (&nativeNAT64Tokens{transport: prepared.transport}).names() {
		kind := "map"
		if index == 4 {
			kind = "set"
		}
		operations = append(operations, map[string]any{"flush": map[string]any{kind: objectReference{Family: "inet", Table: ownedTable, Name: name}}})
	}
	if len(rows[prepared.transport.name+"_zones"]) != 0 {
		operations = append(operations,
			map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": ownedTable, "name": prepared.transport.name + "_zones", "elem": rows[prepared.transport.name+"_zones"]}}},
			map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": ownedTable, "name": prepared.transport.name + "_aliases", "elem": rows[prepared.transport.name+"_aliases"]}}},
			map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": ownedTable, "name": prepared.transport.name + "_active_aliases", "elem": rows[prepared.transport.name+"_active_aliases"]}}},
			map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": ownedTable, "name": prepared.transport.name + "_sources", "elem": rows[prepared.transport.name+"_sources"]}}})
	}
	data, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: NAT64 allocation publication exceeds its fixed boundary")
	}
	return data, ctx.Err()
}

// elements returns the exact pre-expiry rows derived from the same original
// dependencies as the publication. Kernel listings add an observation-only
// expires field; callers may remove that field but cannot use it as readiness.
func (prepared *preparedNAT64Allocations) elements(ctx context.Context) (map[string][]json.RawMessage, error) {
	if ctx == nil || prepared == nil || prepared.transport == nil || prepared.transport.geometry == nil || prepared.ledger == nil || prepared.readiness == nil || prepared.timeout < 1 || prepared.timeout > maximumElementLifetime {
		return nil, errors.New("firewall: missing original NAT64 allocation publication")
	}
	entries, err := prepared.transport.geometry.ValidateLedger(ctx, prepared.transport.component, prepared.ledger)
	if err != nil || !reflect.DeepEqual(entries, prepared.entries) {
		return nil, errors.New("firewall: NAT64 allocation ledger changed after readiness")
	}
	// Recheck the opaque live-process proof on every derivation. Preparation
	// and execution are separated by a bounded queueing window; a translator
	// that stopped or changed its installed static mappings in that window must
	// not inherit the earlier positive result.
	if err := prepared.readiness.verifyNAT64Readiness(ctx, prepared.transport, entries); err != nil {
		return nil, err
	}
	rows := map[string][]json.RawMessage{
		prepared.transport.name + "_zones":          {},
		prepared.transport.name + "_aliases":        {},
		prepared.transport.name + "_active_aliases": {},
		prepared.transport.name + "_sources":        {},
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		zone := nativeNAT64ZoneIdentity(entry.Identity)
		values := []any{
			[]any{nativeTimedValue(entry.Source.String(), prepared.timeout), zone},
			[]any{nativeTimedValue(entry.Alias.String(), prepared.timeout), entry.Source.String()},
			nativeTimedValue(entry.Alias.String(), prepared.timeout),
			nativeTimedValue(map[string]any{"concat": []any{zone, entry.Source.String()}}, prepared.timeout),
		}
		for index, name := range []string{prepared.transport.name + "_zones", prepared.transport.name + "_aliases", prepared.transport.name + "_active_aliases", prepared.transport.name + "_sources"} {
			encoded, err := json.Marshal(values[index])
			if err != nil {
				return nil, errors.New("firewall: NAT64 allocation row encoding failed")
			}
			rows[name] = append(rows[name], encoded)
		}
	}
	return rows, ctx.Err()
}

func validateNAT64AllocationPreparation(ctx context.Context, prepared *preparedNAT64Allocations) error {
	if ctx == nil || prepared == nil || sha256.Sum256(prepared.batch.data) != prepared.digest {
		return errors.New("firewall: missing or changed NAT64 allocation preparation")
	}
	if prepared.clear {
		if prepared.transport == nil || prepared.transport.geometry == nil || prepared.ledger != nil || prepared.readiness != nil || prepared.entries != nil || prepared.timeout != 0 ||
			!prepared.batch.preparedAt.IsZero() || !prepared.batch.startBefore.IsZero() || !prepared.batch.startedAt.IsZero() {
			return errors.New("firewall: NAT64 allocation revocation contains positive metadata")
		}
		expected, err := nat64AllocationClearData(ctx, prepared.transport)
		if err != nil || !bytes.Equal(expected, prepared.batch.data) {
			return errors.New("firewall: NAT64 allocation revocation differs from fixed empty replacement")
		}
		return ctx.Err()
	}
	if err := checkPreparation(&prepared.batch); err != nil {
		return err
	}
	expected, err := prepared.expectedData(ctx)
	if err != nil || !bytes.Equal(expected, prepared.batch.data) {
		return errors.New("firewall: NAT64 allocation preparation differs from original readiness")
	}
	return ctx.Err()
}

func prepareNativeNAT64AllocationClear(ctx context.Context, transport *nativeNAT64Transport) (*preparedNAT64Allocations, error) {
	data, err := nat64AllocationClearData(ctx, transport)
	if err != nil {
		return nil, err
	}
	return &preparedNAT64Allocations{batch: preparedBatch{data: data}, transport: transport, digest: sha256.Sum256(data), clear: true}, nil
}

func nat64AllocationClearData(ctx context.Context, transport *nativeNAT64Transport) ([]byte, error) {
	if ctx == nil || transport == nil || transport.geometry == nil {
		return nil, errors.New("firewall: missing NAT64 allocation revocation geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operations := []any{
		map[string]any{"flush": map[string]any{"map": objectReference{Family: "inet", Table: ownedTable, Name: transport.name + "_zones"}}},
		map[string]any{"flush": map[string]any{"map": objectReference{Family: "inet", Table: ownedTable, Name: transport.name + "_aliases"}}},
		map[string]any{"flush": map[string]any{"set": objectReference{Family: "inet", Table: ownedTable, Name: transport.name + "_active_aliases"}}},
		map[string]any{"flush": map[string]any{"set": objectReference{Family: "inet", Table: ownedTable, Name: transport.name + "_sources"}}},
	}
	for index, name := range (&nativeNAT64Tokens{transport: transport}).names() {
		kind := "map"
		if index == 4 {
			kind = "set"
		}
		operations = append(operations, map[string]any{"flush": map[string]any{kind: objectReference{Family: "inet", Table: ownedTable, Name: name}}})
	}
	return json.Marshal(map[string]any{"nftables": operations})
}

func (prepared preparedNAT64Allocations) MarshalJSON() ([]byte, error) {
	return nil, errors.New("firewall: original NAT64 allocation preparation cannot be serialized")
}
