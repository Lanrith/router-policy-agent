package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const nativeNAT46StaticChannel = "native_n46_static_epoch_channel"

type preparedNAT46StaticConfiguration struct {
	batch         preparedBatch
	geometry      policy.NAT46StaticGeometry
	configuration policy.OwnerConfiguration
	digest        [sha256.Size]byte
	clear         bool
}

// This separate component has no process operation or active helper writer.
// Integration must publish/clear it with the configuration epoch under the
// existing pinned profile, generation and writer fence.
func (sources *nativeNAT46StaticSources) prepareConfiguration(ctx context.Context, configuration policy.OwnerConfiguration) (*preparedNAT46StaticConfiguration, error) {
	if ctx == nil || sources == nil {
		return nil, errors.New("firewall: missing static nat46 configuration dependencies")
	}
	started := time.Now()
	data, err := nat46StaticConfigurationChanges(ctx, sources.evidence, configuration)
	if err != nil {
		return nil, err
	}
	now := started.UTC()
	return &preparedNAT46StaticConfiguration{batch: preparedBatch{data: data, preparedAt: now, startBefore: now.Add(preparationBudget), startedAt: started}, geometry: sources.evidence, configuration: configuration, digest: sha256.Sum256(data)}, ctx.Err()
}

func nat46StaticConfigurationChanges(ctx context.Context, geometry policy.NAT46StaticGeometry, configuration policy.OwnerConfiguration) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing static nat46 configuration context")
	}
	sources, err := geometry.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	current, err := configuration.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if current.Epoch == 0 || current.Epoch > policy.MaximumOwnershipEpoch || current.BaselineHash != sources.BaselineHash || len(sources.Sources) > policy.MaximumNAT46StaticSources {
		return nil, errors.New("firewall: static nat46 geometry and configuration differ")
	}
	lows := []uint32{}
	for _, source := range sources.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lows = append(lows, source.ID&ownershipRuleMask)
	}
	slices.Sort(lows)
	lows = slices.Compact(lows)
	ref := objectReference{Family: "inet", Table: ownedTable, Name: nativeNAT46StaticChannel}
	operations := []any{map[string]any{"flush": map[string]any{"map": ref}}}
	if len(lows) != 0 {
		base := current.Epoch << policy.OwnershipRuleBits
		rows := []any{}
		for _, low := range lows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			key := map[string]any{"concat": []any{base, nativeLowClassID(low)}}
			rows = append(rows, []any{key, epochClassID(base | low)})
		}
		operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": ownedTable, "name": nativeNAT46StaticChannel, "elem": rows}}})
	}
	raw, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil || len(raw) > 128<<10 {
		return nil, errors.New("firewall: static nat46 channel exceeded its fixed boundary")
	}
	return raw, ctx.Err()
}

func prepareNAT46StaticConfigurationClear(ctx context.Context) (*preparedNAT46StaticConfiguration, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing static nat46 revocation context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := nat46StaticConfigurationClearData()
	if err != nil {
		return nil, err
	}
	return &preparedNAT46StaticConfiguration{batch: preparedBatch{data: raw}, digest: sha256.Sum256(raw), clear: true}, nil
}

func nat46StaticConfigurationClearData() ([]byte, error) {
	return json.Marshal(map[string]any{"nftables": []any{map[string]any{"flush": map[string]any{"map": objectReference{Family: "inet", Table: ownedTable, Name: nativeNAT46StaticChannel}}}}})
}

func validateNAT46StaticConfiguration(ctx context.Context, prepared *preparedNAT46StaticConfiguration) error {
	if ctx == nil || prepared == nil || sha256.Sum256(prepared.batch.data) != prepared.digest {
		return errors.New("firewall: missing or changed static nat46 channel")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var expected []byte
	var err error
	if prepared.clear {
		if !prepared.batch.preparedAt.IsZero() || !prepared.batch.startBefore.IsZero() || !prepared.batch.startedAt.IsZero() {
			return errors.New("firewall: static nat46 revocation contains positive preparation metadata")
		}
		if _, err := prepared.geometry.Snapshot(ctx); err == nil {
			return errors.New("firewall: static nat46 revocation contains positive geometry")
		}
		if _, err := prepared.configuration.Snapshot(ctx); err == nil {
			return errors.New("firewall: static nat46 revocation contains positive configuration")
		}
		expected, err = nat46StaticConfigurationClearData()
	} else {
		if err := checkPreparation(&prepared.batch); err != nil {
			return err
		}
		expected, err = nat46StaticConfigurationChanges(ctx, prepared.geometry, prepared.configuration)
	}
	if err != nil || !bytes.Equal(expected, prepared.batch.data) {
		return errors.New("firewall: static nat46 channel differs from compiler-local evidence")
	}
	return ctx.Err()
}
