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

const nativeNAT46StaticSourceChannel = "native_n46_static_source_epoch_channel"
const nativeNAT46StaticSourceLive = "native_n46_static_source_live"

type preparedNAT46StaticOwnership struct {
	batch       preparedBatch
	geometry    policy.NAT46StaticGeometry
	publication *nativeSourcePublication
	utc         time.Time
	anchor      time.Time
	timeout     int
	digest      [sha256.Size]byte
	clear       bool
}

func nat46StaticSourceDefinition() string {
	return "map " + nativeNAT46StaticSourceChannel + " {type mark . classid : classid;flags timeout;timeout 90s;size 1024;}"
}

func nat46StaticSourceLiveDefinition() string {
	return "set " + nativeNAT46StaticSourceLive + " {type classid . classid;flags timeout;timeout 90s;size 1024;}"
}

// Epoch liveness is the original published lower deadline, not a new lease
// inferred from a listing or a later binding observation.
func (publication *nativeSourcePublication) epochRemaining(ctx context.Context, anchor time.Time) (time.Duration, error) {
	if ctx == nil || publication == nil || anchor.IsZero() || publication.startedAt.IsZero() || anchor.Before(publication.startedAt) || time.Since(anchor) < 0 || publication.epochTimeout < 1 || publication.epochTimeout > maximumElementLifetime {
		return 0, errors.New("firewall: missing original source epoch publication")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	remaining := publication.startedAt.Add(time.Duration(publication.epochTimeout) * time.Second).Sub(anchor)
	if remaining <= 0 {
		return 0, errors.New("firewall: source epoch publication expired")
	}
	return remaining, nil
}

// This channel supplies only static client geometry under a live SOURCE epoch.
// The mapped NAS target still needs its own exact current ownership proof, and
// every packet still needs current ordered permission and any delegated grant.
func (sources *nativeNAT46StaticSources) prepareSourceEpoch(ctx context.Context, publication *nativeSourcePublication, utc time.Time) (*preparedNAT46StaticOwnership, error) {
	if ctx == nil || sources == nil || publication == nil || utc.IsZero() {
		return nil, errors.New("firewall: missing nat46 source-epoch geometry dependencies")
	}
	started := time.Now()
	remaining, err := publication.epochRemaining(ctx, started)
	if err != nil {
		return nil, err
	}
	proofRemaining, err := publication.evidence.EpochRemaining(utc)
	if err != nil {
		return nil, err
	}
	timeout := int((min(remaining, proofRemaining) - preparationBudget - commandBudget) / time.Second)
	data, err := nat46StaticOwnershipChanges(ctx, sources.evidence, publication, timeout)
	if err != nil {
		return nil, err
	}
	return &preparedNAT46StaticOwnership{batch: preparedBatch{data: data, preparedAt: utc, startBefore: utc.Add(preparationBudget), startedAt: started}, geometry: sources.evidence, publication: publication, utc: utc, anchor: started, timeout: timeout, digest: sha256.Sum256(data)}, ctx.Err()
}

func nat46StaticOwnershipChanges(ctx context.Context, geometry policy.NAT46StaticGeometry, publication *nativeSourcePublication, timeout int) ([]byte, error) {
	if ctx == nil || publication == nil || timeout < 1 || timeout > maximumElementLifetime {
		return nil, errors.New("firewall: invalid nat46 static source-epoch publication")
	}
	sources, err := geometry.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	current, err := publication.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if current.BaselineHash != sources.BaselineHash || current.Epoch == 0 || current.Epoch > policy.MaximumOwnershipEpoch || len(current.Addresses) != len(publication.timeouts) || len(sources.Sources) > policy.MaximumNAT46StaticSources {
		return nil, errors.New("firewall: nat46 source geometry and ownership differ")
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
	ref := objectReference{Family: "inet", Table: ownedTable, Name: nativeNAT46StaticSourceChannel}
	operations := []any{map[string]any{"flush": map[string]any{"map": ref}}}
	for _, family := range []string{"inet", "netdev"} {
		operations = append(operations, map[string]any{"flush": map[string]any{"set": objectReference{Family: family, Table: ownedTable, Name: nativeNAT46StaticSourceLive}}})
	}
	rows := []any{}
	live := []any{}
	base := current.Epoch << policy.OwnershipRuleBits
	for _, low := range lows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := map[string]any{"concat": []any{base, nativeLowClassID(low)}}
		rows = append(rows, []any{nativeTimedValue(key, timeout), epochClassID(base | low)})
		liveKey := map[string]any{"concat": []any{epochClassID(base), nativeLowClassID(low)}}
		live = append(live, nativeTimedValue(liveKey, timeout))
	}
	if len(rows) > 0 {
		operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{"family": "inet", "table": ownedTable, "name": nativeNAT46StaticSourceChannel, "elem": rows}}})
		for _, family := range []string{"inet", "netdev"} {
			operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{"family": family, "table": ownedTable, "name": nativeNAT46StaticSourceLive, "elem": live}}})
		}
	}
	raw, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil || len(raw) > 384<<10 {
		return nil, errors.New("firewall: nat46 static source-epoch channel exceeds capacity")
	}
	return raw, ctx.Err()
}

func nat46StaticOwnershipClearData() ([]byte, error) {
	operations := []any{map[string]any{"flush": map[string]any{"map": objectReference{Family: "inet", Table: ownedTable, Name: nativeNAT46StaticSourceChannel}}}}
	for _, family := range []string{"inet", "netdev"} {
		operations = append(operations, map[string]any{"flush": map[string]any{"set": objectReference{Family: family, Table: ownedTable, Name: nativeNAT46StaticSourceLive}}})
	}
	return json.Marshal(map[string]any{"nftables": operations})
}

func prepareNAT46StaticOwnershipClear(ctx context.Context) (*preparedNAT46StaticOwnership, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing nat46 source geometry revocation context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := nat46StaticOwnershipClearData()
	if err != nil {
		return nil, err
	}
	return &preparedNAT46StaticOwnership{batch: preparedBatch{data: raw}, digest: sha256.Sum256(raw), clear: true}, nil
}

func validateNAT46StaticOwnership(ctx context.Context, prepared *preparedNAT46StaticOwnership) error {
	if ctx == nil || prepared == nil || sha256.Sum256(prepared.batch.data) != prepared.digest {
		return errors.New("firewall: missing or changed nat46 source geometry channel")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var expected []byte
	var err error
	if prepared.clear {
		if prepared.publication != nil || prepared.timeout != 0 || !prepared.utc.IsZero() || !prepared.anchor.IsZero() || !prepared.batch.preparedAt.IsZero() || !prepared.batch.startBefore.IsZero() || !prepared.batch.startedAt.IsZero() {
			return errors.New("firewall: nat46 source geometry revocation contains positive metadata")
		}
		if _, err := prepared.geometry.Snapshot(ctx); err == nil {
			return errors.New("firewall: nat46 source geometry revocation contains positive geometry")
		}
		expected, err = nat46StaticOwnershipClearData()
	} else {
		if err := checkPreparation(&prepared.batch); err != nil {
			return err
		}
		if !prepared.utc.Equal(prepared.batch.preparedAt) || !prepared.anchor.Equal(prepared.batch.startedAt) {
			return errors.New("firewall: nat46 source geometry anchors changed")
		}
		original, err := prepared.publication.epochRemaining(ctx, prepared.anchor)
		if err != nil {
			return err
		}
		current, err := prepared.publication.epochRemaining(ctx, time.Now())
		if err != nil {
			return err
		}
		proof, err := prepared.publication.evidence.EpochRemaining(prepared.utc)
		if err != nil {
			return err
		}
		duration := time.Duration(prepared.timeout) * time.Second
		if prepared.timeout < 1 || prepared.timeout > maximumElementLifetime || duration+preparationBudget+commandBudget > original || duration+commandBudget > min(current, proof) {
			return errors.New("firewall: nat46 source geometry escaped original epoch deadline")
		}
		expected, err = nat46StaticOwnershipChanges(ctx, prepared.geometry, prepared.publication, prepared.timeout)
		if err != nil {
			return err
		}
	}
	if err != nil || !bytes.Equal(expected, prepared.batch.data) {
		return errors.New("firewall: nat46 source geometry differs from original opaque evidence")
	}
	return ctx.Err()
}
