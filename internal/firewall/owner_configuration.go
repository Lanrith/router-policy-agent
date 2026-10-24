package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	configurationEpochSet = "current_configuration_epoch"
	configurationEpochMap = "configuration_epoch_by_family"
)

type preparedConfiguration struct {
	batch         preparedBatch
	evidence      policy.OwnerConfiguration
	baselineHash  string
	digest        [sha256.Size]byte
	clear         bool
	nat46         bool
	nat46Geometry policy.NAT46StaticGeometry
}

func configurationEpochDefinitions() []string {
	return []string{
		"set " + configurationEpochSet + " { type mark; size 1; }",
		"map " + configurationEpochMap + " { type nf_proto : mark; size 2; }",
	}
}

func configurationEpochHeader(mapping bool) map[string]any {
	if mapping {
		header := guardSetHeader("inet", configurationEpochMap, "nf_proto", 2)
		header["map"] = "mark"
		return header
	}
	return guardSetHeader("inet", configurationEpochSet, "mark", 1)
}

func configurationEpochChanges(epoch uint32) ([]byte, error) {
	if epoch > policy.MaximumOwnershipEpoch {
		return nil, errors.New("firewall: invalid owner configuration epoch")
	}
	ref := func(name string) objectReference {
		return objectReference{Family: "inet", Table: ownedTable, Name: name}
	}
	operations := []any{
		map[string]any{"flush": map[string]any{"set": ref(configurationEpochSet)}},
		map[string]any{"flush": map[string]any{"map": ref(configurationEpochMap)}},
	}
	channel, err := epochChannelChanges(true, epoch, 0)
	if err != nil {
		return nil, err
	}
	operations = append(operations, channel...)
	if epoch != 0 {
		base := epoch << policy.OwnershipRuleBits
		for _, item := range []struct {
			name   string
			values []any
		}{
			{configurationEpochSet, []any{base}},
			{configurationEpochMap, []any{[]any{"ipv4", base}, []any{"ipv6", base}}},
		} {
			operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{
				"family": "inet", "table": ownedTable, "name": item.name, "elem": item.values,
			}}})
		}
	}
	data, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil || len(data) > 4096 {
		return nil, errors.New("firewall: owner configuration transaction exceeds its fixed boundary")
	}
	return data, nil
}

func (renderer *renderer) prepareConfiguration(ctx context.Context, evidence policy.OwnerConfiguration) (*preparedConfiguration, error) {
	if ctx == nil || renderer == nil || renderer.compiler == nil {
		return nil, errors.New("firewall: missing configuration preparation dependencies")
	}
	started := time.Now()
	snapshot, err := evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot.BaselineHash != renderer.compiler.BaselineHash() || snapshot.Epoch == 0 {
		return nil, errors.New("firewall: configuration belongs to another baseline or has no consumed sequence")
	}
	data, err := configurationEpochChanges(snapshot.Epoch)
	if err != nil {
		return nil, err
	}
	now := started.UTC()
	return &preparedConfiguration{batch: preparedBatch{data: data, preparedAt: now,
		startBefore: now.Add(preparationBudget), startedAt: started}, evidence: evidence,
		baselineHash: snapshot.BaselineHash, digest: sha256.Sum256(data)}, nil
}

func prepareConfigurationClear(ctx context.Context) (*preparedConfiguration, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing configuration revocation context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := configurationEpochChanges(0)
	if err != nil {
		return nil, err
	}
	return &preparedConfiguration{batch: preparedBatch{data: data}, digest: sha256.Sum256(data), clear: true}, nil
}

func validateConfigurationPreparation(ctx context.Context, prepared *preparedConfiguration) error {
	if ctx == nil || prepared == nil || sha256.Sum256(prepared.batch.data) != prepared.digest {
		return errors.New("firewall: missing or changed configuration preparation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	epoch := uint32(0)
	if prepared.clear {
		if prepared.baselineHash != "" || !prepared.batch.preparedAt.IsZero() ||
			!prepared.batch.startedAt.IsZero() || !prepared.batch.startBefore.IsZero() {
			return errors.New("firewall: configuration revocation contains positive metadata")
		}
	} else {
		snapshot, err := prepared.evidence.Snapshot(ctx)
		if err != nil {
			return err
		}
		if snapshot.BaselineHash != prepared.baselineHash || snapshot.Epoch == 0 {
			return errors.New("firewall: configuration proof differs from preparation")
		}
		epoch = snapshot.Epoch
	}
	expected, err := prepared.expectedConfigurationData(ctx, epoch)
	if err != nil || !bytes.Equal(expected, prepared.batch.data) {
		return errors.New("firewall: configuration changes differ from helper-local proof")
	}
	return ctx.Err()
}

func inspectConfigurationEpoch(ctx context.Context, inet *guardTableObservation) error {
	if ctx == nil || inet == nil {
		return errors.New("firewall: missing configuration inspection context")
	}
	values := inet.sets[configurationEpochSet].Elements
	mappings := inet.sets[configurationEpochMap].Elements
	if len(values) == 0 && len(mappings) == 0 {
		return ctx.Err()
	}
	if len(values) != 1 || len(mappings) != 2 {
		return errors.New("firewall: incomplete configuration epoch mirrors")
	}
	var base uint32
	if err := json.Unmarshal(values[0], &base); err != nil || base == 0 || base&ownershipRuleMask != 0 ||
		base>>policy.OwnershipRuleBits > policy.MaximumOwnershipEpoch {
		return errors.New("firewall: invalid configuration epoch observation")
	}
	seen := map[string]bool{}
	for _, mapping := range mappings {
		if err := ctx.Err(); err != nil {
			return err
		}
		var pair []json.RawMessage
		if err := json.Unmarshal(mapping, &pair); err != nil || len(pair) != 2 {
			return errors.New("firewall: malformed configuration epoch map")
		}
		var key string
		var value uint32
		if err := json.Unmarshal(pair[0], &key); err != nil || key != "ipv4" && key != "ipv6" || seen[key] {
			return errors.New("firewall: invalid configuration epoch map key")
		}
		if err := json.Unmarshal(pair[1], &value); err != nil || value != base {
			return errors.New("firewall: configuration epoch map differs from its observed set")
		}
		seen[key] = true
	}
	return ctx.Err()
}
