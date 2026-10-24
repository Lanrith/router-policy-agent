//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// This fixture proves that nft accepts and independently lists the joined
// NAT46/NAT64 graph. Packet semantics remain covered by the dedicated real
// TAYGA fixtures for each direction.
func TestKernelNamedCombinedTranslationLayout(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	b := nat46ForwardingBaseline(t)
	first := nat64TransportFixture(t).NAT64[0]
	secondPool := netip.MustParsePrefix("10.252.0.0/24")
	second := policy.NAT64{ID: "nat64-private", Prefix: netip.MustParsePrefix("fdca:1a2b:e065::/96"), Scope: "private", SourcePool: &secondPool}
	b.NAT64 = []policy.NAT64{first, second}
	for _, nat64 := range b.NAT64 {
		b.NetworkModel.Rules = append(b.NetworkModel.Rules, policy.NetworkRule{
			Action: "allow", Authorization: "owner", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b::/64")}}},
			To:   []policy.NetworkSelector{{Interface: nat64.ID, Addresses: []netip.Prefix{nat64.Prefix}}},
		})
	}
	layout, err := newNativeNAT46AccessLayout(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.interfaces {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		selected := name
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", selected)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	p, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error(err)
		}
	})
	for _, item := range []struct {
		family string
		op     operation
	}{{"inet", inspectOwned}, {"netdev", inspectGuardEgress}} {
		data, err := p.execute(ctx, item.op, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := layout.inspectTable(ctx, item.family, data); err != nil {
			t.Fatal("combined translator table differs from its frozen schema", item.family, err)
		}
	}
}
