package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
)

// preparedNAT64State is one kernel transaction for every selected NAT64
// component. Individual allocation and token preparations retain their own
// opaque compiler, ledger, readiness and source proofs; this wrapper only
// joins their already bounded commands so another packet cannot observe a
// partially activated component set.
type preparedNAT64State struct {
	allocations []*preparedNAT64Allocations
	tokens      []*nativeNAT64Tokens
	data        []byte
	digest      [sha256.Size]byte
}

func prepareNativeNAT64State(
	ctx context.Context,
	allocations []*preparedNAT64Allocations,
	tokens []*nativeNAT64Tokens,
) (*preparedNAT64State, error) {
	if ctx == nil || len(allocations) == 0 && len(tokens) == 0 {
		return nil, errors.New("firewall: missing aggregate NAT64 state")
	}
	prepared := &preparedNAT64State{
		allocations: slices.Clone(allocations),
		tokens:      slices.Clone(tokens),
	}
	data, err := prepared.expectedData(ctx)
	if err != nil {
		return nil, err
	}
	prepared.data = data
	prepared.digest = sha256.Sum256(data)
	return prepared, ctx.Err()
}

func (prepared *preparedNAT64State) expectedData(ctx context.Context) ([]byte, error) {
	if ctx == nil || prepared == nil || len(prepared.allocations) == 0 && len(prepared.tokens) == 0 {
		return nil, errors.New("firewall: missing aggregate NAT64 state")
	}
	allocationComponents := make(map[string]*nativeNAT64Transport, len(prepared.allocations))
	tokenComponents := make(map[string]*nativeNAT64Transport, len(prepared.tokens))
	programs := make([][]byte, 0, len(prepared.allocations)+len(prepared.tokens))
	for _, allocation := range prepared.allocations {
		if allocation == nil || allocation.transport == nil || allocationComponents[allocation.transport.component] != nil {
			return nil, errors.New("firewall: invalid aggregate NAT64 allocation set")
		}
		if err := validateNAT64AllocationPreparation(ctx, allocation); err != nil {
			return nil, err
		}
		allocationComponents[allocation.transport.component] = allocation.transport
		programs = append(programs, allocation.batch.data)
	}
	for _, tokens := range prepared.tokens {
		if tokens == nil || tokens.transport == nil || tokenComponents[tokens.transport.component] != nil {
			return nil, errors.New("firewall: invalid aggregate NAT64 token set")
		}
		data, err := tokens.publicationData(ctx)
		if err != nil {
			return nil, err
		}
		tokenComponents[tokens.transport.component] = tokens.transport
		programs = append(programs, data)
	}
	if len(allocationComponents) != 0 && len(tokenComponents) != 0 {
		if len(allocationComponents) != len(tokenComponents) {
			return nil, errors.New("firewall: NAT64 allocation and token component sets differ")
		}
		for component, transport := range allocationComponents {
			if tokenComponents[component] != transport {
				return nil, errors.New("firewall: NAT64 allocation and token origins differ")
			}
		}
	}
	operations := make([]json.RawMessage, 0)
	for _, program := range programs {
		var transaction struct {
			Operations []json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(program, &transaction); err != nil || len(transaction.Operations) == 0 {
			return nil, errors.New("firewall: invalid aggregate NAT64 transaction")
		}
		operations = append(operations, transaction.Operations...)
	}
	data, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: aggregate NAT64 transaction exceeds capacity")
	}
	return data, ctx.Err()
}

func validateNAT64StatePreparation(ctx context.Context, prepared *preparedNAT64State) error {
	if ctx == nil || prepared == nil || sha256.Sum256(prepared.data) != prepared.digest {
		return errors.New("firewall: missing or changed aggregate NAT64 state")
	}
	expected, err := prepared.expectedData(ctx)
	if err != nil || !bytes.Equal(expected, prepared.data) {
		return errors.New("firewall: aggregate NAT64 state differs from original proofs")
	}
	return ctx.Err()
}

func (prepared preparedNAT64State) MarshalJSON() ([]byte, error) {
	return nil, errors.New("firewall: aggregate NAT64 state cannot be serialized")
}
