package firewall

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func aggregateNAT64StateTransports(t *testing.T) []*nativeNAT64Transport {
	t.Helper()
	b := nat64TransportFixture(t)
	secondPool := netip.MustParsePrefix("10.252.0.0/24")
	b.NAT64 = append(b.NAT64, policy.NAT64{
		ID: "nat64-private", Prefix: netip.MustParsePrefix("fdca:1a2b:e065::/96"), Scope: "private", SourcePool: &secondPool,
	})
	transports := make([]*nativeNAT64Transport, 0, len(b.NAT64))
	for _, component := range b.NAT64 {
		transport, err := newNativeNAT64Transport(t.Context(), b, component.ID)
		if err != nil {
			t.Fatal(err)
		}
		transports = append(transports, transport)
	}
	return transports
}

func TestAggregateNAT64StateIsOneExactKernelTransaction(t *testing.T) {
	t.Parallel()
	transports := aggregateNAT64StateTransports(t)
	allocations := make([]*preparedNAT64Allocations, 0, len(transports))
	tokens := make([]*nativeNAT64Tokens, 0, len(transports))
	for _, transport := range transports {
		allocation, err := prepareNativeNAT64AllocationClear(t.Context(), transport)
		if err != nil {
			t.Fatal(err)
		}
		registry, err := prepareNativeNAT64TokenClear(t.Context(), transport)
		if err != nil {
			t.Fatal(err)
		}
		allocations, tokens = append(allocations, allocation), append(tokens, registry)
	}
	prepared, err := prepareNativeNAT64State(t.Context(), allocations, tokens)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT64StatePreparation(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	var transaction struct {
		Operations []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(prepared.data, &transaction); err != nil || len(transaction.Operations) != 28 {
		t.Fatal("aggregate NAT64 state did not retain every component operation", len(transaction.Operations), err)
	}
	for _, transport := range transports {
		for _, suffix := range []string{"_zones", "_aliases", "_active_aliases", "_sources", "_tokens", "_token_epoch_pairs"} {
			if !bytes.Contains(prepared.data, []byte(transport.name+suffix)) {
				t.Fatal("aggregate NAT64 state omitted a selected component object", transport.component, suffix)
			}
		}
	}
	if _, err := json.Marshal(prepared); err == nil {
		t.Fatal("aggregate NAT64 state became serializable")
	}
}

func TestAggregateNAT64StateRejectsPartialDuplicateAndChangedOrigins(t *testing.T) {
	t.Parallel()
	transports := aggregateNAT64StateTransports(t)
	allocation, err := prepareNativeNAT64AllocationClear(t.Context(), transports[0])
	if err != nil {
		t.Fatal(err)
	}
	firstTokens, err := prepareNativeNAT64TokenClear(t.Context(), transports[0])
	if err != nil {
		t.Fatal(err)
	}
	secondTokens, err := prepareNativeNAT64TokenClear(t.Context(), transports[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeNAT64State(t.Context(), []*preparedNAT64Allocations{allocation}, []*nativeNAT64Tokens{secondTokens}); err == nil {
		t.Fatal("different NAT64 origins shared an aggregate transaction")
	}
	if _, err := prepareNativeNAT64State(t.Context(), nil, []*nativeNAT64Tokens{firstTokens, firstTokens}); err == nil {
		t.Fatal("duplicate NAT64 component shared an aggregate transaction")
	}
	prepared, err := prepareNativeNAT64State(t.Context(), []*preparedNAT64Allocations{allocation}, []*nativeNAT64Tokens{firstTokens})
	if err != nil {
		t.Fatal(err)
	}
	prepared.data = bytes.Replace(prepared.data, []byte(transports[0].name+"_zones"), []byte(transports[0].name+"_token"), 1)
	if err := validateNAT64StatePreparation(t.Context(), prepared); err == nil {
		t.Fatal("changed aggregate NAT64 transaction retained its original proof")
	}
}
