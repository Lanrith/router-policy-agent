package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// NAT64 source refreshes revoke every delegated translation projection in the
// same ownership transaction. A later guarded update must rederive grants from
// the newly verified source receipt; an old grant can never cross that fence.
func prepareNativeNAT64SourceRefresh(
	ctx context.Context,
	source *preparedOwnership,
	previous *nativeSourcePublication,
	observedEpoch uint32,
	transport *nativeNAT64Transport,
) (*preparedOwnership, error) {
	return prepareNativeNAT64AggregateSourceRefresh(ctx, source, previous, observedEpoch, []*nativeNAT64Transport{transport})
}

func prepareNativeNAT64AggregateSourceRefresh(
	ctx context.Context,
	source *preparedOwnership,
	previous *nativeSourcePublication,
	observedEpoch uint32,
	transports []*nativeNAT64Transport,
) (*preparedOwnership, error) {
	if len(transports) == 0 || source == nil || source.nat64Transport != nil || len(source.nat64Transports) != 0 {
		return nil, errors.New("firewall: missing or repeated NAT64 source mode")
	}
	prepared, err := prepareNativeSourceRefresh(ctx, source, previous, observedEpoch)
	if err != nil {
		return nil, err
	}
	return attachNativeNAT64SourceMode(ctx, prepared, transports)
}

func attachNativeNAT64SourceMode(ctx context.Context, prepared *preparedOwnership, transports []*nativeNAT64Transport) (*preparedOwnership, error) {
	if prepared == nil || prepared.nat64Transport != nil || len(prepared.nat64Transports) != 0 || len(transports) == 0 {
		return nil, errors.New("firewall: invalid NAT64 source mode attachment")
	}
	baselineHash := transports[0].baselineHash
	for _, transport := range transports {
		if transport == nil || transport.geometry == nil || !generationHash(transport.baselineHash) || transport.baselineHash != baselineHash {
			return nil, errors.New("firewall: inconsistent NAT64 source mode")
		}
	}
	next := *prepared
	next.nat64Transports = slices.Clone(transports)
	if len(transports) == 1 {
		next.nat64Transport = transports[0]
	}
	snapshot := policy.OwnershipSnapshot{}
	var err error
	if !next.clear {
		snapshot, err = next.evidence.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
	}
	next.batch.data, err = next.expectedData(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	next.digest = sha256.Sum256(next.batch.data)
	return &next, ctx.Err()
}

func prepareNativeNAT64OwnershipClear(ctx context.Context, transport *nativeNAT64Transport) (*preparedOwnership, error) {
	return prepareNativeNAT64AggregateOwnershipClear(ctx, []*nativeNAT64Transport{transport})
}

func prepareNativeNAT64AggregateOwnershipClear(ctx context.Context, transports []*nativeNAT64Transport) (*preparedOwnership, error) {
	if len(transports) == 0 {
		return nil, errors.New("firewall: missing NAT64 source revocation mode")
	}
	prepared, err := prepareNativeOwnershipClear(ctx)
	if err != nil {
		return nil, err
	}
	return attachNativeNAT64SourceMode(ctx, prepared, transports)
}

func preparedOwnershipNAT64Transports(prepared *preparedOwnership) ([]*nativeNAT64Transport, error) {
	if prepared == nil {
		return nil, errors.New("firewall: missing NAT64 source preparation")
	}
	transports := slices.Clone(prepared.nat64Transports)
	switch {
	case len(transports) == 0 && prepared.nat64Transport == nil:
		return nil, nil
	case len(transports) == 0:
		return []*nativeNAT64Transport{prepared.nat64Transport}, nil
	case len(transports) == 1 && prepared.nat64Transport != transports[0]:
		return nil, errors.New("firewall: singular NAT64 source selector changed")
	case len(transports) > 1 && prepared.nat64Transport != nil:
		return nil, errors.New("firewall: aggregate NAT64 source mode acquired a singular selector")
	}
	return transports, nil
}

func (prepared *preparedOwnership) expectedNAT64SourceRefreshData(
	ctx context.Context,
	snapshot policy.OwnershipSnapshot,
	data []byte,
) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing NAT64 source transition context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	transports, err := preparedOwnershipNAT64Transports(prepared)
	if err != nil {
		return nil, err
	}
	if len(transports) == 0 {
		return data, nil
	}
	baselineHash := transports[0].baselineHash
	if !prepared.nativeSources {
		return nil, errors.New("firewall: NAT64 source mode requires original native geometry")
	}
	for _, transport := range transports {
		if transport == nil || transport.geometry == nil || !generationHash(transport.baselineHash) || transport.baselineHash != baselineHash {
			return nil, errors.New("firewall: NAT64 source mode changed geometry")
		}
	}
	if !prepared.clear && (snapshot.BaselineHash != baselineHash || prepared.baselineHash != baselineHash || snapshot.Epoch == 0) {
		return nil, errors.New("firewall: NAT64 source model differs from original ownership")
	}
	var transaction struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &transaction); err != nil {
		return nil, errors.New("firewall: invalid original NAT64 source transition")
	}
	for _, ref := range nativeNAT64GrantRefs() {
		command, err := json.Marshal(map[string]any{"flush": map[string]any{"set": ref}})
		if err != nil {
			return nil, err
		}
		transaction.Commands = append(transaction.Commands, command)
	}
	encoded, err := json.Marshal(transaction)
	if err != nil || len(encoded) > maximumBatch {
		return nil, errors.New("firewall: NAT64 source transition exceeds capacity")
	}
	return encoded, ctx.Err()
}
