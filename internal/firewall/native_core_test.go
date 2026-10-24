package firewall

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNativeCoreRADIUSSeparatesNASAccountingFromTheUpstreamProxy(t *testing.T) {
	t.Parallel()
	protocols, ports := nativeCoreTransport("radius")
	if !slices.Equal(protocols, []string{"udp"}) || !slices.Equal(ports, []uint16{1812, 1813}) {
		t.Fatal("RADIUS NAS transport omitted authentication or accounting")
	}
	protocols, ports = nativeCoreTransport("radius_proxy")
	if !slices.Equal(protocols, []string{"udp"}) || !slices.Equal(ports, []uint16{1812}) {
		t.Fatal("RADIUS proxy transport gained accounting or another protocol")
	}
	protocols, ports = nativeCoreTransport("logs")
	if !slices.Equal(protocols, []string{"tcp"}) || !slices.Equal(ports, []uint16{443}) {
		t.Fatal("log delivery transport is not exact HTTPS")
	}
	protocols, ports = nativeCoreTransport("discovery")
	if !slices.Equal(protocols, []string{"tcp", "udp"}) || !slices.Equal(ports, []uint16{53}) {
		t.Fatal("discovery DNS transport is not exact DNS")
	}
}

func nativeCoreBaseline(t *testing.T) policy.Baseline {
	t.Helper()
	b := nativeAccessBaseline(t)
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P03", Networks: []netip.Prefix{netip.MustParsePrefix("10.241.254.0/24"), netip.MustParsePrefix("fdca:1a2b:fe02::/64")}, Roles: []policy.Role{}})
	b.NetworkModel.CoreServices = []policy.CoreService{{Kind: "dns", Interface: "services0", Addresses: []netip.Addr{netip.MustParseAddr("10.241.254.10"), netip.MustParseAddr("fdca:1a2b:fe02::10")}, Clients: []policy.NetworkSelector{{Interface: "lan13", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.3.0/24"), netip.MustParsePrefix("fdca:1a2b:3::/64")}}}}}
	return b
}

func TestNativeCoreOwnsGeometryAndCannotBorrowAnOwnerEpoch(t *testing.T) {
	t.Parallel()
	if nativeCoreEpoch>>policy.OwnershipRuleBits != uint64(policy.MaximumOwnershipEpoch)+1 || nativeCoreEpoch&uint64(ownershipRuleMask) != 0 {
		t.Fatal("core admission overlaps a usable owner epoch or scope index")
	}
	b := nativeCoreBaseline(t)
	layout, err := newNativeAccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	before, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b.NetworkModel.CoreServices[0].Addresses[0] = netip.MustParseAddr("10.241.254.20")
	b.NetworkModel.CoreServices[0].Clients[0].Addresses[0] = netip.MustParsePrefix("0.0.0.0/0")
	after, err := layout.program(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("caller mutation changed compiled bootstrap geometry", err)
	}
	legacy, err := newGuardLayout(nativeCoreBaseline(t))
	if err != nil || legacy.native != nil {
		t.Fatal("core metadata activated the default helper layout", err)
	}
}

func TestNativeCoreBoundsTheCompletePhysicalExpansion(t *testing.T) {
	t.Parallel()
	b := nativeCoreBaseline(t)
	b.Zones[1].Networks = []netip.Prefix{netip.MustParsePrefix("10.242.0.0/16")}
	b.NetworkModel.Rules = []policy.NetworkRule{}
	service := &b.NetworkModel.CoreServices[0]
	service.Addresses = service.Addresses[:1]
	service.Clients = []policy.NetworkSelector{}
	for block := 0; block < 4; block++ {
		client := policy.NetworkSelector{Interface: "lan13"}
		for host := 0; host < 256; host++ {
			address := netip.AddrFrom4([4]byte{10, 242, byte(block), byte(host)}) // #nosec G115 -- both loops are bounded below 256.
			client.Addresses = append(client.Addresses, netip.PrefixFrom(address, 32))
		}
		service.Clients = append(service.Clients, client)
	}
	if _, err := newNativeAccessLayout(t.Context(), b); err == nil {
		t.Fatal("core copies across every physical hook escaped the generated rule bound")
	}
}

func TestNativeCoreRequiresExactMasqueradeSources(t *testing.T) {
	t.Parallel()
	b := nativeCoreBaseline(t)
	b.NetworkModel.CoreEgress = []policy.CoreEgress{{Kind: "dns", Interface: "services0", Address: netip.MustParseAddr("10.241.254.10"), Destinations: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Masquerade: true}}
	if _, err := newNativeAccessLayout(t.Context(), b); err == nil {
		t.Fatal("unqualified dynamic post-NAT source activated")
	}
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: []netip.Prefix{netip.MustParsePrefix("10.243.0.1/32")}, Roles: []policy.Role{}})
	b.NetworkModel.CoreEgress[0].TranslatedAddresses = []netip.Addr{netip.MustParseAddr("10.243.0.1")}
	layout, err := newNativeAccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	before, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b.NetworkModel.CoreEgress[0].Destinations[0] = netip.MustParsePrefix("192.0.2.1/32")
	b.NetworkModel.CoreEgress[0].TranslatedAddresses[0] = netip.MustParseAddr("10.243.0.2")
	after, err := layout.program(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("caller mutation changed native dependency", err)
	}
}
