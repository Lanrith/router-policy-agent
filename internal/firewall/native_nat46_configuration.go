package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// The configuration channel and static GID conversion are one transaction.
// Both derive from the same original configuration proof and compiler geometry;
// neither a listing nor a previously published scalar epoch can replace them.
func (renderer *renderer) prepareNativeNAT46Configuration(ctx context.Context, evidence policy.OwnerConfiguration, sources *nativeNAT46StaticSources) (*preparedConfiguration, error) {
	if sources == nil {
		return nil, errors.New("firewall: missing nat46 configuration geometry")
	}
	prepared, err := renderer.prepareConfiguration(ctx, evidence)
	if err != nil {
		return nil, err
	}
	prepared.nat46, prepared.nat46Geometry = true, sources.evidence
	snapshot, err := evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	prepared.batch.data, err = prepared.expectedConfigurationData(ctx, snapshot.Epoch)
	if err != nil {
		return nil, err
	}
	prepared.digest = sha256.Sum256(prepared.batch.data)
	return prepared, ctx.Err()
}

func prepareNativeNAT46ConfigurationClear(ctx context.Context) (*preparedConfiguration, error) {
	prepared, err := prepareConfigurationClear(ctx)
	if err != nil {
		return nil, err
	}
	prepared.nat46 = true
	prepared.batch.data, err = prepared.expectedConfigurationData(ctx, 0)
	if err != nil {
		return nil, err
	}
	prepared.digest = sha256.Sum256(prepared.batch.data)
	return prepared, ctx.Err()
}

func (prepared *preparedConfiguration) expectedConfigurationData(ctx context.Context, epoch uint32) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing configuration composition context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := configurationEpochChanges(epoch)
	if err != nil {
		return nil, err
	}
	geometry, geometryErr := prepared.nat46Geometry.Snapshot(ctx)
	if !prepared.nat46 {
		if geometryErr == nil {
			return nil, errors.New("firewall: unselected configuration contains positive nat46 geometry")
		}
		return data, ctx.Err()
	}
	var extra []byte
	if prepared.clear {
		if geometryErr == nil {
			return nil, errors.New("firewall: configuration revocation contains positive nat46 geometry")
		}
		if _, err := prepared.evidence.Snapshot(ctx); err == nil {
			return nil, errors.New("firewall: configuration revocation contains positive owner evidence")
		}
		extra, err = nat46StaticConfigurationClearData()
	} else {
		if geometryErr != nil || geometry.BaselineHash != prepared.baselineHash {
			return nil, errors.New("firewall: configuration lost original nat46 geometry")
		}
		owner, ownerErr := prepared.evidence.Snapshot(ctx)
		if ownerErr != nil || owner.Epoch != epoch || owner.BaselineHash != prepared.baselineHash {
			return nil, errors.New("firewall: nat46 conversion changed its original configuration epoch")
		}
		extra, err = nat46StaticConfigurationChanges(ctx, prepared.nat46Geometry, prepared.evidence)
	}
	if err != nil {
		return nil, err
	}
	var base, conversion struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &base) != nil || json.Unmarshal(extra, &conversion) != nil {
		return nil, errors.New("firewall: invalid original configuration composition")
	}
	base.Commands = append(base.Commands, conversion.Commands...)
	encoded, err := json.Marshal(base)
	if err != nil || len(encoded) > maximumBatch {
		return nil, errors.New("firewall: nat46 configuration transaction exceeds capacity")
	}
	return encoded, ctx.Err()
}
