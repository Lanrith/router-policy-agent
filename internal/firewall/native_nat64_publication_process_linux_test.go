package firewall

import "testing"

func TestNAT64PublicationOperationsRejectWrongOrUntrustedPreparationBeforeExecution(t *testing.T) {
	t.Parallel()
	transport, ledger, entries := nat64AllocationFixture(t)
	readiness := &testNAT64Readiness{transport: transport, entries: entries, ready: true}
	allocations, err := prepareNativeNAT64Allocations(t.Context(), transport, ledger, readiness)
	if err != nil {
		t.Fatal(err)
	}
	changedAllocations := *allocations
	changedAllocations.readiness = nil
	_, states := nat64TokenFixture(t)
	tokens, err := newNativeNAT64Tokens(t.Context(), transport, states)
	if err != nil {
		t.Fatal(err)
	}
	changedTokens := *tokens
	changedTokens.entries = append([]nativeNAT64TokenEntry(nil), tokens.entries...)
	changedTokens.entries[0].token++
	state, err := prepareNativeNAT64State(t.Context(), []*preparedNAT64Allocations{allocations}, nil)
	if err != nil {
		t.Fatal(err)
	}
	changedState := *state
	changedState.data = append([]byte(nil), state.data...)
	changedState.data[0] ^= 1
	for _, input := range []commandInput{
		{op: applyNAT64Allocations},
		{op: applyNAT64Allocations, payload: allocations.batch.data},
		{op: applyNAT64Allocations, nat64Allocation: allocations, payload: allocations.batch.data},
		{op: applyNAT64Allocations, nat64Allocation: allocations, prepared: &allocations.batch},
		{op: applyNAT64Allocations, nat64Allocation: allocations, guarded: &preparedGuardBatch{}},
		{op: applyNAT64Allocations, nat64Allocation: allocations, ownership: &preparedOwnership{}},
		{op: applyNAT64Allocations, nat64Allocation: allocations, configuration: &preparedConfiguration{}},
		{op: applyNAT64Allocations, nat64Allocation: allocations, nat46Source: &preparedNAT46StaticOwnership{}},
		{op: applyNAT64Allocations, nat64Allocation: allocations, nat64Tokens: tokens},
		{op: applyNAT64Allocations, nat64Allocation: &changedAllocations},
		{op: applyNAT64Tokens},
		{op: applyNAT64Tokens, payload: []byte(`{"nftables":[]}`), nat64Tokens: tokens},
		{op: applyNAT64Tokens, nat64Tokens: tokens, prepared: &allocations.batch},
		{op: applyNAT64Tokens, nat64Tokens: tokens, guarded: &preparedGuardBatch{}},
		{op: applyNAT64Tokens, nat64Tokens: tokens, ownership: &preparedOwnership{}},
		{op: applyNAT64Tokens, nat64Tokens: tokens, configuration: &preparedConfiguration{}},
		{op: applyNAT64Tokens, nat64Tokens: tokens, nat46Source: &preparedNAT46StaticOwnership{}},
		{op: applyNAT64Tokens, nat64Tokens: tokens, nat64Allocation: allocations},
		{op: applyNAT64Tokens, nat64Tokens: &changedTokens},
		{op: applyNAT64State},
		{op: applyNAT64State, payload: state.data, nat64State: state},
		{op: applyNAT64State, nat64State: state, nat64Allocation: allocations},
		{op: applyNAT64State, nat64State: state, nat64Tokens: tokens},
		{op: applyNAT64State, nat64State: &changedState},
		{op: inspectOwned, nat64Allocation: allocations},
		{op: inspectOwned, nat64Tokens: tokens},
		{op: inspectOwned, nat64State: state},
		{op: applyOwned, nat64Allocation: allocations},
		{op: applyOwned, nat64Tokens: tokens},
		{op: applyOwned, nat64State: state},
	} {
		// No executable exists. Invalid requests must fail at validation, not
		// reach the child and hide their failure as an nftables error.
		if _, err := (&process{}).run(t.Context(), input); err == nil || err.Error() == "firewall: nftables operation failed" {
			t.Fatal("invalid NAT64 publication escaped its fixed operation")
		}
	}
}
