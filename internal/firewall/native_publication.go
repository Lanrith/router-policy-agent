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

// nativeSourcePublication is a helper-local receipt minted only after the
// typed source transaction and its fenced post-commit inspection succeed.
// Its lower deadline bounds include time already spent preparing and queueing.
// A listing, persisted classifier or later observation cannot renew this receipt.
type nativeSourcePublication struct {
	evidence     policy.Ownership
	startedAt    time.Time
	timeouts     []int
	epochTimeout int
}

func nativeSourceReceipt(ctx context.Context, prepared *preparedOwnership) (*nativeSourcePublication, error) {
	if ctx == nil || prepared == nil || !prepared.nativeSources || prepared.clear || prepared.batch.startedAt.IsZero() || time.Since(prepared.batch.startedAt) < 0 {
		return nil, errors.New("firewall: missing verified native source publication")
	}
	snapshot, err := prepared.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot.BaselineHash != prepared.baselineHash || snapshot.Epoch == 0 || snapshot.Epoch > policy.MaximumOwnershipEpoch || len(snapshot.Addresses) != len(prepared.timeouts) || prepared.epochTimeout < 1 || prepared.epochTimeout > maximumElementLifetime {
		return nil, errors.New("firewall: invalid native source publication receipt")
	}
	data, err := prepared.expectedData(ctx, snapshot)
	if err != nil || sha256.Sum256(prepared.batch.data) != prepared.digest || !bytes.Equal(data, prepared.batch.data) {
		return nil, errors.New("firewall: source receipt differs from its typed publication")
	}
	return &nativeSourcePublication{evidence: prepared.evidence, startedAt: prepared.batch.startedAt, timeouts: slices.Clone(prepared.timeouts), epochTimeout: prepared.epochTimeout}, ctx.Err()
}

func (prepared *preparedOwnership) expectedData(ctx context.Context, snapshot policy.OwnershipSnapshot) ([]byte, error) {
	if prepared.withdrawNativeIDs && (!prepared.nativeSources || prepared.clear) {
		return nil, errors.New("firewall: ID withdrawal requires a positive native source publication")
	}
	data, err := ownershipPreparedData(ctx, snapshot, prepared.timeouts, prepared.epochTimeout, prepared.nativeSources)
	if err != nil {
		return nil, err
	}
	if prepared.withdrawNativeIDs {
		var decoded struct {
			Commands []json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, err
		}
		for _, command := range clearNativeIDGrants() {
			encoded, err := json.Marshal(command)
			if err != nil {
				return nil, err
			}
			decoded.Commands = append(decoded.Commands, encoded)
		}
		data, err = json.Marshal(decoded)
		if err != nil {
			return nil, err
		}
	}
	data, err = prepared.expectedNAT46SourceRefreshData(ctx, snapshot, data)
	if err != nil {
		return nil, err
	}
	return prepared.expectedNAT64SourceRefreshData(ctx, snapshot, data)
}

// The observed epoch is only a consistency check. A cached opaque receipt is
// required to keep an episode; a listing cannot adopt or reconstruct one.
// If the new lower source deadline shrinks, withdraw existing ID grants in
// the same transaction. Later source refreshes cannot revive those grants.
func prepareNativeSourceRefresh(ctx context.Context, prepared *preparedOwnership, previous *nativeSourcePublication, observedEpoch uint32) (*preparedOwnership, error) {
	if ctx == nil || prepared == nil || !prepared.nativeSources || prepared.clear {
		return nil, errors.New("firewall: missing native source refresh")
	}
	next, err := prepared.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if previous == nil {
		if observedEpoch != 0 {
			return nil, errors.New("firewall: uncached source episode requires revocation")
		}
		return prepared, ctx.Err()
	}
	old, err := previous.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if old.BaselineHash != next.BaselineHash || old.Epoch != next.Epoch || old.Fingerprint != next.Fingerprint || observedEpoch != 0 && observedEpoch != old.Epoch || len(previous.timeouts) != len(prepared.timeouts) {
		return nil, errors.New("firewall: changed source episode requires revocation")
	}
	// Inspected child grants retain their original configured timeout. A
	// smaller parent window also needs revocation when elapsed time makes the
	// new absolute deadline later: the old window must not exceed its parent.
	shrink := prepared.epochTimeout < previous.epochTimeout
	for index, timeout := range prepared.timeouts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		oldDeadline := previous.startedAt.Add(time.Duration(min(previous.timeouts[index], previous.epochTimeout)) * time.Second)
		newDeadline := prepared.batch.startedAt.Add(time.Duration(min(timeout, prepared.epochTimeout)) * time.Second)
		shrink = shrink || timeout < previous.timeouts[index] || newDeadline.Before(oldDeadline)
	}
	if !shrink {
		return prepared, nil
	}
	modified := *prepared
	modified.withdrawNativeIDs = true
	modified.batch.data, err = modified.expectedData(ctx, next)
	if err != nil {
		return nil, err
	}
	modified.digest = sha256.Sum256(modified.batch.data)
	return &modified, nil
}

func (receipt *nativeSourcePublication) remaining(ctx context.Context, index int, now time.Time) (time.Duration, error) {
	if ctx == nil || receipt == nil || now.IsZero() || receipt.startedAt.IsZero() || now.Before(receipt.startedAt) || index < 0 || index >= len(receipt.timeouts) {
		return 0, errors.New("firewall: invalid native source receipt deadline")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	timeout := min(receipt.timeouts[index], receipt.epochTimeout)
	if timeout < 1 || timeout > maximumElementLifetime {
		return 0, errors.New("firewall: invalid published source lifetime")
	}
	remaining := receipt.startedAt.Add(time.Duration(timeout) * time.Second).Sub(now)
	if remaining <= 0 {
		return 0, errors.New("firewall: published source deadline expired")
	}
	return remaining, nil
}

func (receipt nativeSourcePublication) MarshalJSON() ([]byte, error) {
	return nil, errors.New("firewall: native source publication cannot be serialized")
}

func (receipt *nativeSourcePublication) UnmarshalJSON(_ []byte) error {
	if receipt != nil {
		*receipt = nativeSourcePublication{}
	}
	return errors.New("firewall: native source publication cannot be deserialized")
}
