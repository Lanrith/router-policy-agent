package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Selecting the translated layout requires explicit dependent revocation.
// Ordinary native layouts keep their original collection inventory. The mode
// carries the original model and previous receipt; observations cannot adopt
// an episode or supply positive ownership or grants.
func prepareNativeNAT46SourceRefresh(ctx context.Context, source *preparedOwnership, previous *nativeSourcePublication, observedEpoch uint32, model *nativeNAT46Model) (*preparedOwnership, error) {
	if model == nil || source == nil || source.nat46SourceModel != nil {
		return nil, errors.New("firewall: missing or repeated nat46 source mode")
	}
	prepared, err := prepareNativeSourceRefresh(ctx, source, previous, observedEpoch)
	if err != nil {
		return nil, err
	}
	next := *prepared
	next.nat46SourceModel, next.nat46Previous, next.nat46ObservedEpoch = model, previous, observedEpoch
	snapshot, err := next.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	next.batch.data, err = next.expectedData(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	next.digest = sha256.Sum256(next.batch.data)
	return &next, ctx.Err()
}

func prepareNativeNAT46OwnershipClear(ctx context.Context, model *nativeNAT46Model) (*preparedOwnership, error) {
	if model == nil {
		return nil, errors.New("firewall: missing nat46 source revocation mode")
	}
	prepared, err := prepareNativeOwnershipClear(ctx)
	if err != nil {
		return nil, err
	}
	prepared.nat46SourceModel = model
	prepared.batch.data, err = prepared.expectedData(ctx, policy.OwnershipSnapshot{})
	if err != nil {
		return nil, err
	}
	prepared.digest = sha256.Sum256(prepared.batch.data)
	return prepared, ctx.Err()
}

func (prepared *preparedOwnership) expectedNAT46SourceRefreshData(ctx context.Context, snapshot policy.OwnershipSnapshot, data []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing nat46 source transition context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	model := prepared.nat46SourceModel
	if model == nil {
		if prepared.nat46Previous != nil || prepared.nat46ObservedEpoch != 0 {
			return nil, errors.New("firewall: native source contains unselected translation metadata")
		}
		return data, nil
	}
	if !prepared.nativeSources || !generationHash(model.baselineHash) {
		return nil, errors.New("firewall: nat46 source mode requires original native geometry")
	}
	clearSource, clearGrants := true, true
	if prepared.clear {
		if prepared.nat46Previous != nil || prepared.nat46ObservedEpoch != 0 {
			return nil, errors.New("firewall: source revocation contains a positive previous receipt")
		}
	} else {
		if snapshot.BaselineHash != model.baselineHash || prepared.baselineHash != model.baselineHash || snapshot.Epoch == 0 {
			return nil, errors.New("firewall: nat46 source model differs from original ownership")
		}
		previous := prepared.nat46Previous
		if previous == nil {
			if prepared.nat46ObservedEpoch != 0 {
				return nil, errors.New("firewall: nat46 source listing cannot supply an uncached episode")
			}
		} else {
			old, err := previous.evidence.Snapshot(ctx)
			if err != nil {
				return nil, err
			}
			if old.BaselineHash != snapshot.BaselineHash || old.Epoch != snapshot.Epoch || old.Fingerprint != snapshot.Fingerprint || len(previous.timeouts) != len(prepared.timeouts) ||
				prepared.nat46ObservedEpoch != 0 && prepared.nat46ObservedEpoch != old.Epoch || previous.startedAt.IsZero() || prepared.batch.startedAt.Before(previous.startedAt) || previous.epochTimeout < 1 || previous.epochTimeout > maximumElementLifetime {
				return nil, errors.New("firewall: nat46 source episode changed without revocation")
			}
			gap := prepared.nat46ObservedEpoch == 0 || !prepared.batch.startedAt.Before(previous.startedAt.Add(time.Duration(previous.epochTimeout)*time.Second))
			clearSource = gap || prepared.epochTimeout < previous.epochTimeout
			clearGrants = gap || prepared.withdrawNativeIDs
		}
	}
	if !clearSource && !clearGrants {
		return data, nil
	}
	var transaction struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &transaction); err != nil {
		return nil, errors.New("firewall: invalid original source transition")
	}
	if clearSource {
		raw, err := nat46StaticOwnershipClearData()
		if err != nil {
			return nil, err
		}
		var clears struct {
			Commands []json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal(raw, &clears) != nil || len(clears.Commands) != 3 {
			return nil, errors.New("firewall: invalid fixed nat46 source revocations")
		}
		transaction.Commands = append(transaction.Commands, clears.Commands...)
	}
	if clearGrants {
		for _, ref := range nativeNAT46TargetGrantRefs() {
			command, err := json.Marshal(map[string]any{"flush": map[string]any{"set": ref}})
			if err != nil {
				return nil, err
			}
			transaction.Commands = append(transaction.Commands, command)
		}
	}
	encoded, err := json.Marshal(transaction)
	if err != nil || len(encoded) > maximumBatch {
		return nil, errors.New("firewall: nat46 source transition exceeds capacity")
	}
	return encoded, ctx.Err()
}
