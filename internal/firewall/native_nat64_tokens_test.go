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
	if err := json.Unmarshal(firstData, &batch); err != nil || len(batch.Commands) != 26 {
		t.Fatal("NAT64 token publication is not one complete replacement", err)
	}
	for index, command := range batch.Commands {
		if index < 19 && command["flush"] == nil || index >= 19 && command["add"] == nil || len(command) != 1 {
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

func TestNAT64ReplacementAndRevocationWithdrawEveryOldTuple(t *testing.T) {
	t.Parallel()
	transport, ledger, entries := nat64AllocationFixture(t)
	oldState := nativeNAT64TokenState{epoch: 0x1c00, context: 0xd3000000, channel: 0x1c00}
	newState := nativeNAT64TokenState{epoch: 0x2000, context: oldState.context, channel: 0x2000}
	oldTokens, err := newNativeNAT64Tokens(t.Context(), transport, []nativeNAT64TokenState{oldState})
	if err != nil {
		t.Fatal(err)
	}
	newTokens, err := newNativeNAT64Tokens(t.Context(), transport, []nativeNAT64TokenState{newState})
	if err != nil {
		t.Fatal(err)
	}
	if oldTokens.entries[0].token != newTokens.entries[0].token || oldTokens.entries[0].epoch == newTokens.entries[0].epoch {
		t.Fatal("fixture did not reassign an opaque token to a new authority epoch")
	}
	clearTokens, err := prepareNativeNAT64TokenClear(t.Context(), transport)
	if err != nil {
		t.Fatal(err)
	}
	allocations, err := prepareNativeNAT64Allocations(t.Context(), transport, ledger,
		&testNAT64Readiness{transport: transport, entries: entries, ready: true})
	if err != nil {
		t.Fatal(err)
	}
	clearAllocations, err := prepareNativeNAT64AllocationClear(t.Context(), transport)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"tokens replaced":      mustNAT64TokenData(t, newTokens),
		"tokens revoked":       mustNAT64TokenData(t, clearTokens),
		"allocations replaced": allocations.batch.data,
		"allocations revoked":  clearAllocations.batch.data,
	} {
		t.Run(name, func(t *testing.T) {
			var batch struct {
				Commands []struct {
					Flush struct {
						Map *objectReference `json:"map"`
					} `json:"flush"`
					Add json.RawMessage `json:"add"`
				} `json:"nftables"`
			}
			if err := json.Unmarshal(data, &batch); err != nil {
				t.Fatal(err)
			}
			withdrawn := map[string]bool{}
			for _, command := range batch.Commands {
				if len(command.Add) != 0 {
					break
				}
				if ref := command.Flush.Map; ref != nil && ref.Family == "inet" && ref.Table == ownedTable {
					withdrawn[ref.Name] = true
				}
			}
			for _, suffix := range []string{"_tcp_forward_proof", "_tcp_reply_proof", "_udp_forward_proof", "_udp_reply_proof", "_icmp_forward_proof", "_icmp_reply_proof", "_tcp_reply_origin_proof", "_udp_reply_origin_proof", "_icmp_reply_origin_proof", "_tcp_reply_identity_proof", "_udp_reply_identity_proof", "_icmp_reply_identity_proof"} {
				if !withdrawn[transport.name+suffix] {
					t.Fatal("new state could reinterpret a previous tuple before withdrawal", suffix)
				}
			}
		})
	}
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
