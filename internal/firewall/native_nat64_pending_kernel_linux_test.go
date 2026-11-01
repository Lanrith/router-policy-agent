//go:build integration && kernel && linux

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// The observable translator veth has no process or live allocation. This tests
// connectivity demand from the original IPv6 packet, never translation or a
// forwarding permit. Every packet must remain behind the empty epoch guards.
func TestKernelNamedNAT64PendingRequiresOriginalPolicyAndSource(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupNAT64PendingLinks(ctx, t)
	b := nat64TransportFixture(t)
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "any", From: []policy.NetworkSelector{{Interface: "lan10"}},
			To: []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: sourceClassPrefixes("fdca:1a2b:e064::af0:30b/128")}}},
		{Action: "allow", Authorization: "owner", Protocol: "udp", Ports: []uint16{6061},
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64"), MAC: "02:00:00:00:00:10"}},
			To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}},
	}
	installNAT64PendingPolicy(ctx, t, b)
	peer, wrong, translator := packetSocket(t, "peer0"), packetSocket(t, "device0"), packetSocket(t, "n64peer")
	serial := uint16(54000)
	for _, test := range []struct {
		name, source, target, mac string
		port                      uint16
		wrongInterface            bool
		demand                    int
	}{
		{"earlier deny", "fdca:1a2b::20", "fdca:1a2b:e064::af0:30b", "02:00:00:00:00:10", 6061, false, 0},
		{"wrong listener", "fdca:1a2b::21", "fdca:1a2b:e064::af0:30a", "02:00:00:00:00:10", 6062, false, 0},
		{"wrong source MAC", "fdca:1a2b::22", "fdca:1a2b:e064::af0:30a", "02:00:00:00:00:ee", 6061, false, 0},
		{"wrong ingress", "fdca:1a2b::23", "fdca:1a2b:e064::af0:30a", "02:00:00:00:00:10", 6061, true, 0},
		{"prospective owner permission", "fdca:1a2b::10", "fdca:1a2b:e064::af0:30a", "02:00:00:00:00:10", 6061, false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			packetNft(ctx, t, "flush set inet "+ownedTable+" native_n64_0_pending")
			serial++
			input := peer
			if test.wrongInterface {
				input = wrong
			}
			packet := packetDatagram{source: netip.MustParseAddr(test.source), destination: netip.MustParseAddr(test.target),
				sourceMAC: test.mac, destinationMAC: "02:00:00:00:01:10", sourcePort: serial,
				destinationPort: test.port, payload: "prospective-demand-" + test.name}
			if test.wrongInterface {
				packet.destinationMAC = "02:00:00:00:01:13"
			}
			sendPacket(ctx, t, input, packetFrame(t, packet))
			receivePacket(ctx, t, translator, packetFrame(t, packet), false)
			listing := kernelFixtureCommand(ctx, t, "list", "set", "inet", ownedTable, "native_n64_0_pending")
			if got := elementCount(t, listing, "native_n64_0_pending"); got != test.demand {
				t.Fatalf("original IPv6 allocation demand = %d, want %d", got, test.demand)
			}
		})
	}
}

func setupNAT64PendingLinks(ctx context.Context, t *testing.T) {
	t.Helper()
	setupPacketLinks(ctx, t)
	for _, name := range []string{"wan", "nat64-internal"} {
		arguments := []string{"link", "add", name, "type", "dummy"}
		if name == "nat64-internal" {
			arguments = []string{"link", "add", name, "type", "veth", "peer", "name", "n64peer"}
		}
		packetIP(ctx, t, arguments...)
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	packetIP(ctx, t, "link", "set", "n64peer", "address", "02:00:00:00:00:64")
	for _, name := range []string{"wan", "nat64-internal", "n64peer"} {
		packetIP(ctx, t, "link", "set", name, "up")
	}
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:e064::/96", "dev", "nat64-internal")
	for _, address := range []string{"fdca:1a2b:e064::af0:30a", "fdca:1a2b:e064::af0:30b"} {
		packetIP(ctx, t, "neighbor", "add", address, "lladdr", "02:00:00:00:00:64", "dev", "nat64-internal", "nud", "permanent")
	}
}

func installNAT64PendingPolicy(ctx context.Context, t *testing.T, b policy.Baseline) {
	t.Helper()
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
}

func TestKernelNamedNAT64PendingPreservesLogicalDestinationOrder(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupNAT64PendingLinks(ctx, t)
	peer, translator := packetSocket(t, "peer0"), packetSocket(t, "n64peer")
	for _, test := range []struct {
		name, denied, allowed, authorization string
		demand                               int
	}{
		{"WAN deny does not suppress LAN demand", "wan", "lan13", "owner", 1},
		{"LAN deny does not suppress WAN demand", "lan13", "wan", "owner", 1},
		{"directory LAN demand is connectivity only", "wan", "lan13", "directory", 1},
		{"same LAN deny terminates", "lan13", "lan13", "owner", 0},
		{"same WAN deny terminates", "wan", "wan", "owner", 0},
		{"unscoped deny terminates every LAN path", "", "lan13", "owner", 0},
		{"unscoped deny terminates every WAN path", "", "wan", "owner", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := nat64TransportFixture(t)
			b.NetworkModel.Rules = []policy.NetworkRule{
				{Action: "deny", Authorization: "inherit", Protocol: "any", From: []policy.NetworkSelector{{Interface: "lan10"}},
					To: []policy.NetworkSelector{{Interface: test.denied, Addresses: sourceClassPrefixes("10.240.3.10/32")}}},
				{Action: "allow", Authorization: test.authorization, Protocol: "udp", Ports: []uint16{6061},
					From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64"), MAC: "02:00:00:00:00:10"}},
					To:   []policy.NetworkSelector{{Interface: test.allowed, Addresses: sourceClassPrefixes("10.240.3.10/32")}}},
			}
			installNAT64PendingPolicy(ctx, t, b)
			packet := packetDatagram{source: netip.MustParseAddr("fdca:1a2b::20"), destination: netip.MustParseAddr("fdca:1a2b:e064::af0:30a"),
				sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: 55000,
				destinationPort: 6061, payload: "logical-demand-" + test.name}
			sendPacket(ctx, t, peer, packetFrame(t, packet))
			receivePacket(ctx, t, translator, packetFrame(t, packet), false)
			listing := kernelFixtureCommand(ctx, t, "list", "set", "inet", ownedTable, "native_n64_0_pending")
			if got := elementCount(t, listing, "native_n64_0_pending"); got != test.demand {
				t.Fatalf("original IPv6 allocation demand = %d, want %d", got, test.demand)
			}
		})
	}
}
