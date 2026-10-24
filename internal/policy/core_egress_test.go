package policy

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func coreEgressBaseline(t *testing.T) Baseline {
	t.Helper()
	b := coreServiceBaseline(t)
	b.ProtectedNetworks = append(b.ProtectedNetworks, NetworkBlock{ProtectionID: "P01", Networks: prefixes("10.243.0.1/32"), Roles: []Role{}})
	b.NetworkModel.CoreEgress = []CoreEgress{{Kind: "dns", Interface: "services0", Address: netip.MustParseAddr("10.241.254.10"), Destinations: prefixes("0.0.0.0/0"), Masquerade: true, TranslatedAddresses: []netip.Addr{netip.MustParseAddr("10.243.0.1")}}}
	return b
}

func TestCoreEgressOwnsDependencyWithoutGrantingCapabilities(t *testing.T) {
	t.Parallel()
	b := coreEgressBaseline(t)
	compiler := testCompiler(t, b)
	before := compiler.BaselineHash()
	b.NetworkModel.CoreEgress[0].Address = netip.MustParseAddr("10.241.254.99")
	b.NetworkModel.CoreEgress[0].Destinations[0] = netip.MustParsePrefix("192.168.1.1/32")
	b.NetworkModel.CoreEgress[0].TranslatedAddresses[0] = netip.MustParseAddr("10.243.0.99")
	if compiler.BaselineHash() != before {
		t.Fatal("caller mutation changed core dependency")
	}
	_, input := namedFixture(t)
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("core dependency changed delegated capabilities", candidate.Denials, err)
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
}

func TestCoreEgressRejectsAmbiguousOrUnboundedDependencies(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"kind", "WAN interface", "wrong link", "duplicate", "component identity", "unprotected source", "router source", "client source", "mapped source", "empty destinations", "wrong family", "duplicate destination", "noncanonical destination", "partial recursive scope", "broad fallback", "local fallback", "fallback family", "translated family", "unprotected translated source", "client translated source", "duplicate translated source", "NAT without masquerade"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := coreEgressBaseline(t)
			p := &b.NetworkModel.CoreEgress[0]
			switch name {
			case "kind":
				p.Kind = "ssh"
			case "WAN interface":
				p.Interface = "wan"
			case "wrong link":
				p.Interface = "service1"
			case "duplicate":
				b.NetworkModel.CoreEgress = append(b.NetworkModel.CoreEgress, *p)
			case "component identity":
				p.Kind = "ntp"
			case "unprotected source":
				p.Address = netip.MustParseAddr("10.242.254.10")
			case "router source":
				p.Address = netip.MustParseAddr("10.243.0.1")
			case "client source":
				p.Address = netip.MustParseAddr("10.240.3.10")
			case "mapped source":
				p.Address = netip.MustParseAddr("::ffff:10.241.254.10")
			case "empty destinations":
				p.Destinations = nil
			case "wrong family":
				p.Destinations = prefixes("::/0")
			case "duplicate destination":
				p.Destinations = append(p.Destinations, p.Destinations[0])
			case "noncanonical destination":
				p.Destinations = []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}
			case "partial recursive scope":
				p.Destinations = prefixes("192.168.1.0/24")
			case "broad fallback":
				b.NetworkModel.CoreServices = nil
				p.Kind = "ntp_dns"
			case "local fallback":
				b.NetworkModel.CoreServices = nil
				p.Kind = "ntp_dns"
				p.Destinations = prefixes("10.240.3.10/32")
			case "fallback family":
				b.NetworkModel.CoreServices = nil
				p.Kind = "ntp_dns"
				p.Destinations = prefixes("2001:db8::53/128")
			case "translated family":
				p.TranslatedAddresses = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
			case "unprotected translated source":
				p.TranslatedAddresses = []netip.Addr{netip.MustParseAddr("10.243.0.99")}
			case "client translated source":
				p.TranslatedAddresses = []netip.Addr{netip.MustParseAddr("10.240.3.10")}
			case "duplicate translated source":
				p.TranslatedAddresses = append(p.TranslatedAddresses, p.TranslatedAddresses[0])
			case "NAT without masquerade":
				p.Masquerade = false
			}
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeBaseline(raw); err == nil {
				t.Fatal("unsafe service dependency accepted")
			}
		})
	}
}

func TestCoreEgressDynamicAddressingIsRepresentableWithoutInventingAnAddress(t *testing.T) {
	t.Parallel()
	b := coreEgressBaseline(t)
	b.NetworkModel.CoreEgress[0].TranslatedAddresses = nil
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBaseline(raw); err != nil {
		t.Fatal(err)
	}
	b.NetworkModel.CoreServices = nil
	b.NetworkModel.CoreEgress[0].Kind = "ntp_dns"
	b.NetworkModel.CoreEgress[0].Destinations = prefixes("9.9.9.9/32")
	raw, err = json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBaseline(raw); err != nil {
		t.Fatal("numeric resolver without recursive DNS rejected", err)
	}
}

func TestRADIUSProxyDependencyRequiresOneExactOrdinaryAttachment(t *testing.T) {
	t.Parallel()
	fixture := func() Baseline {
		b := coreServiceBaseline(t)
		b.NetworkModel.CoreServices[0].Kind = "radius"
		b.NetworkModel.CoreServices[0].Addresses = []netip.Addr{
			netip.MustParseAddr("10.241.254.30"), netip.MustParseAddr("fdca:1a2b:fe02::30"),
		}
		b.NetworkModel.CoreEgress = []CoreEgress{{Kind: "radius_proxy", Interface: "services0", DestinationInterface: "lan13", Address: netip.MustParseAddr("10.241.254.30"), Destinations: prefixes("10.240.3.32/32"), Masquerade: false}}
		return b
	}
	if _, err := New(fixture()); err != nil {
		t.Fatal("exact RADIUS proxy dependency rejected", err)
	}
	for _, test := range []struct {
		name   string
		change func(*CoreEgress)
	}{
		{"missing attachment", func(path *CoreEgress) { path.DestinationInterface = "" }},
		{"WAN attachment", func(path *CoreEgress) { path.DestinationInterface = "wan" }},
		{"wrong attachment", func(path *CoreEgress) { path.DestinationInterface = "lan12" }},
		{"broad destination", func(path *CoreEgress) { path.Destinations = prefixes("10.240.3.0/24") }},
		{"source NAT", func(path *CoreEgress) { path.Masquerade = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			b := fixture()
			test.change(&b.NetworkModel.CoreEgress[0])
			if _, err := New(b); err == nil {
				t.Fatal("unsafe RADIUS proxy dependency accepted")
			}
		})
	}
}

func TestLogDeliveryRequiresOneExactOrdinaryAttachment(t *testing.T) {
	t.Parallel()
	fixture := func() Baseline {
		b := coreServiceBaseline(t)
		b.NetworkModel.CoreEgress = []CoreEgress{{Kind: "logs", Interface: "services0", DestinationInterface: "lan13", Address: netip.MustParseAddr("fdca:1a2b:fe02::60"), Destinations: prefixes("fdca:1a2b:3::31/128"), Masquerade: false}}
		return b
	}
	if _, err := New(fixture()); err != nil {
		t.Fatal("exact log delivery dependency rejected", err)
	}
	for _, test := range []struct {
		name   string
		change func(*CoreEgress)
	}{
		{"missing attachment", func(path *CoreEgress) { path.DestinationInterface = "" }},
		{"WAN attachment", func(path *CoreEgress) { path.DestinationInterface = "wan" }},
		{"wrong attachment", func(path *CoreEgress) { path.DestinationInterface = "lan12" }},
		{"broad destination", func(path *CoreEgress) { path.Destinations = prefixes("fdca:1a2b:3::/64") }},
		{"source NAT", func(path *CoreEgress) { path.Masquerade = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			b := fixture()
			test.change(&b.NetworkModel.CoreEgress[0])
			if _, err := New(b); err == nil {
				t.Fatal("unsafe log delivery dependency accepted")
			}
		})
	}
}
