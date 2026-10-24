package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func nat64TokenFixture(t *testing.T) (*nativeNAT64Transport, []nativeNAT64TokenState) {
	t.Helper()
	transport, err := newNativeNAT64Transport(t.Context(), nat64TransportFixture(t), "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	return transport, []nativeNAT64TokenState{
		{epoch: 0x1c01, context: 0xd1000001, channel: 0x1c01},
		{epoch: 0x1c01, context: 0xd2000001, channel: 0x1c01},
		{epoch: 0x1c02, context: 0xd5000002, channel: 0x1c02},
		{epoch: 0x1c02, context: 0xd6000002, channel: 0x1c02},
	}
}

func TestNAT64TokenRegistryIsDeterministicAtomicAndNonSerializable(t *testing.T) {
	t.Parallel()
	transport, states := nat64TokenFixture(t)
	first, err := newNativeNAT64Tokens(t.Context(), transport, states)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(states)
	second, err := newNativeNAT64Tokens(t.Context(), transport, states)
	if err != nil {
		t.Fatal(err)
	}
	firstData, err := first.data(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := second.data(t.Context())
	if err != nil || !bytes.Equal(firstData, secondData) {
		t.Fatal("NAT64 token identities depend on caller order", err)
	}
	var batch struct {
		Commands []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(firstData, &batch); err != nil || len(batch.Commands) != 10 {
		t.Fatal("NAT64 token publication is not one complete replacement", err)
	}
	for index, command := range batch.Commands {
		if index < 5 && command["flush"] == nil || index >= 5 && command["add"] == nil || len(command) != 1 {
			t.Fatal("NAT64 token publication is not flush-before-add")
		}
	}
	lastToken := nativeNAT64TokenTag | uint32(len(states)) // #nosec G115 -- the token registry is bounded to 65,535 entries.
	if len(first.entries) != len(states) || first.entries[0].token != nativeNAT64TokenTag|1 || first.entries[len(first.entries)-1].token != lastToken {
		t.Fatal("NAT64 opaque token assignment escaped its bounded namespace")
	}
	states[0].context = 0
	if !bytes.Equal(firstData, mustNAT64TokenData(t, first)) {
		t.Fatal("caller mutation changed the original token registry")
	}
	if _, err := json.Marshal(first); err == nil {
		t.Fatal("original NAT64 token registry became serializable")
	}
	tokenClear, err := prepareNativeNAT64TokenClear(t.Context(), transport)
	if err != nil {
		t.Fatal(err)
	}
	clearData, err := tokenClear.data(t.Context())
	if err != nil || bytes.Contains(clearData, []byte(`"add"`)) {
		t.Fatal("NAT64 token revocation retained positive rows", err)
	}
	if _, err := json.Marshal(tokenClear); err == nil {
		t.Fatal("NAT64 token revocation became serializable")
	}
}

func mustNAT64TokenData(t *testing.T, tokens *nativeNAT64Tokens) []byte {
	t.Helper()
	data, err := tokens.data(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNAT64TokenRegistryRejectsUnownedOrIncoherentMetadata(t *testing.T) {
	t.Parallel()
	transport, states := nat64TokenFixture(t)
	invalid := []struct {
		name  string
		state nativeNAT64TokenState
	}{
		{"zero epoch", nativeNAT64TokenState{context: 0xd1000001, channel: 0x1c01}},
		{"unknown rule", nativeNAT64TokenState{epoch: 0x1fff, context: 0xd1000001, channel: 0x1c00}},
		{"unknown kind", nativeNAT64TokenState{epoch: 0x1c01, context: 0xf1000001, channel: 0x1c01}},
		{"pending NAT kind", nativeNAT64TokenState{epoch: 0x1c01, context: 0xa1000001, channel: 0x1c01}},
		{"local mutable context", nativeNAT64TokenState{epoch: 0x1c01, context: 0xd1010001, channel: 0x1c01}},
		{"different channel epoch", nativeNAT64TokenState{epoch: 0x1c01, context: 0xd1000001, channel: 0x2001}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newNativeNAT64Tokens(t.Context(), transport, []nativeNAT64TokenState{test.state}); err == nil {
				t.Fatal("unowned NAT64 metadata acquired a token")
			}
		})
	}
	if _, err := newNativeNAT64Tokens(t.Context(), transport, []nativeNAT64TokenState{states[0], states[0]}); err == nil {
		t.Fatal("duplicate NAT64 token state accepted")
	}
	if _, err := newNativeNAT64Tokens(t.Context(), transport, nil); err == nil {
		t.Fatal("empty positive NAT64 token registry accepted")
	}
	if _, err := newNativeNAT64Tokens(t.Context(), nil, states); err == nil {
		t.Fatal("NAT64 tokens detached from original transport")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newNativeNAT64Tokens(ctx, transport, states); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled NAT64 token construction continued", err)
	}
	registry, err := newNativeNAT64Tokens(t.Context(), transport, states)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.data(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled NAT64 token publication continued", err)
	}
	if _, err := prepareNativeNAT64TokenClear(ctx, transport); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled NAT64 token revocation continued", err)
	}
}
