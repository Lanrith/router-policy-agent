//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// This fixture qualifies the compiler-owned raw IPv6 half of NAT64 policy.
// The translator attachment is an observable veth: the separate real-TAYGA
// fixture qualifies address and transport conversion. No synthetic readiness
// used here is evidence that a production translator is running.
func TestKernelNamedNAT64ProjectedOrderAndRevocation(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	for _, name := range []string{"wan", "nat64-internal"} {
		arguments := []string{"link", "add", name, "type", "dummy"}
		if name == "nat64-internal" {
			arguments = []string{"link", "add", name, "type", "veth", "peer", "name", "n64peer"}
		}
		packetIP(ctx, t, arguments...)
		selected := name
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", selected)
		})
	}
	packetIP(ctx, t, "link", "set", "nat64-internal", "address", "02:00:00:00:01:64")
	packetIP(ctx, t, "link", "set", "n64peer", "address", "02:00:00:00:00:64")
	for _, name := range []string{"wan", "nat64-internal", "n64peer"} {
		packetIP(ctx, t, "link", "set", name, "up")
	}
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:e064::/96", "dev", "nat64-internal")
	for _, address := range []string{"fdca:1a2b:e064::af0:30a", "fdca:1a2b:e064::af0:30b"} {
		packetIP(ctx, t, "neighbor", "add", address, "lladdr", "02:00:00:00:00:64", "dev", "nat64-internal", "nud", "permanent")
	}

	b := nativeAccessBaseline(t)
	pool := netip.MustParsePrefix("10.251.0.0/24")
	b.NAT64 = []policy.NAT64{{
		ID: "nat64-internal", Prefix: netip.MustParsePrefix("fdca:1a2b:e064::/96"), Scope: "private", SourcePool: &pool,
		SourceMappings: []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}},
	}}
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan10"}},
			To:   []policy.NetworkSelector{{Interface: "wan", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.3.11/32")}}}},
		{Action: "allow", Authorization: "owner", Protocol: "udp", Ports: []uint16{6061},
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b::/64")}}},
			To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}},
	}
	layout, err := newNativeNAT64AccessLayout(ctx, b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
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

	transport := layout.native.nat64Transport
	ledger, err := transport.geometry.Capture(ctx, transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	preparedConfiguration, err := renderer.prepareConfiguration(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, preparedConfiguration.batch.data)
	readiness := &testNAT64Readiness{transport: transport, entries: entries, ready: true}
	prepareAllocations := func() *preparedNAT64Allocations {
		t.Helper()
		prepared, err := prepareNativeNAT64Allocations(ctx, transport, ledger, readiness)
		if err != nil {
			t.Fatal(err)
		}
		return prepared
	}
	allocations := prepareAllocations()
	tokens, err := deriveNativeNAT64Tokens(ctx, transport, layout.native, ledger, configuration, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := publisher.close(); err != nil {
			t.Error(err)
		}
	})
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Allocations, nat64Allocation: allocations})
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens})
	if _, err := publisher.inspectGuards(ctx, layout); err != nil {
		logNativeAccessSchema(ctx, t, layout)
		t.Fatal("NAT64 projected layout differs from its fixed schema", err)
	}
	packetNft(ctx, t, `table inet n64_projection_trace {
 counter forward_before {}
 counter forward_after_early {}
 counter confirm_before {}
 counter confirm_after {}
 counter post_before_floor {}
 counter post_after_export {}
 chain forward_before { type filter hook forward priority -151; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name forward_before; }
 chain forward_after_early { type filter hook forward priority -149; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name forward_after_early; }
 chain confirm_before { type filter hook forward priority 149; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name confirm_before; }
 chain confirm_after { type filter hook forward priority 151; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name confirm_after; }
 chain post_before_floor { type filter hook postrouting priority 199; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name post_before_floor; }
 chain post_after_export { type filter hook postrouting priority 202; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name post_after_export; }
}
table netdev n64_projection_trace {
 counter physical_before {}
 counter physical_after {}
 chain physical_before { type filter hook egress device "nat64-internal" priority -1; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name physical_before; }
 chain physical_after { type filter hook egress device "nat64-internal" priority 1; policy accept; ip6 daddr fdca:1a2b:e064::/96 counter name physical_after; }
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		if t.Failed() {
			for _, family := range []string{"inet", "netdev"} {
				t.Logf("NAT64 projected trace %s: %s", family, kernelFixtureCommand(cleanup, t, "list", "table", family, "n64_projection_trace"))
			}
			logNAT64IdentityFixture(cleanup, t)
		}
		packetNft(cleanup, t, "delete table inet n64_projection_trace; delete table netdev n64_projection_trace")
	})

	peer, wrong, translated := packetSocket(t, "peer0"), packetSocket(t, "device0"), packetSocket(t, "n64peer")
	allowed := netip.MustParseAddr("fdca:1a2b:e064::af0:30a")
	denied := netip.MustParseAddr("fdca:1a2b:e064::af0:30b")
	serial := uint16(50000)
	transmit := func(source, target netip.Addr, input packetEndpoint, expected bool, mutate func(*packetDatagram)) {
		t.Helper()
		serial++
		request := packetDatagram{source: source, destination: target, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: serial, destinationPort: 6061, payload: "projected-nat64"}
		if mutate != nil {
			mutate(&request)
		}
		sendPacket(ctx, t, input, packetFrame(t, request))
		wire := request
		wire.sourceMAC, wire.destinationMAC = "02:00:00:00:01:64", "02:00:00:00:00:64"
		receivePacket(ctx, t, translated, packetFrame(t, wire), expected)
	}
	transmit(entries[0].Source, allowed, peer, true, nil)
	transmit(entries[0].Source, denied, peer, false, nil)
	transmit(entries[0].Source.Next(), allowed, peer, false, nil)
	transmit(entries[0].Source, allowed, wrong, false, func(packet *packetDatagram) {
		packet.sourceMAC, packet.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
	})
	transmit(entries[0].Source, allowed, peer, false, func(packet *packetDatagram) { packet.destinationPort++ })
	transmit(entries[0].Source, allowed, peer, false, func(packet *packetDatagram) { packet.isTCP, packet.tcpFlags = true, 2 })

	allocationClear, err := prepareNativeNAT64AllocationClear(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Allocations, nat64Allocation: allocationClear})
	transmit(entries[0].Source, allowed, peer, false, nil)
	allocations = prepareAllocations()
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Allocations, nat64Allocation: allocations})
	transmit(entries[0].Source, allowed, peer, false, nil)
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens})
	transmit(entries[0].Source, allowed, peer, true, nil)

	tokenClear, err := prepareNativeNAT64TokenClear(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokenClear})
	transmit(entries[0].Source, allowed, peer, false, nil)
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens})
	transmit(entries[0].Source, allowed, peer, true, nil)

	configurationClear, err := prepareConfigurationClear(ctx)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, configurationClear.batch.data)
	transmit(entries[0].Source, allowed, peer, false, nil)
}
