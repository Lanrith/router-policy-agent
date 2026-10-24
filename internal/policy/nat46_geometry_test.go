package policy

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
)

func nat46GeometryFixture(t *testing.T) (Baseline, Input) {
	t.Helper()
	b, input := namedFixture(t)
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	return b, input
}

func TestNAT46GeometryOwnsItsPrefixWithoutAddingPermission(t *testing.T) {
	t.Parallel()
	b, input := nat46GeometryFixture(t)
	compiler := testCompiler(t, b)
	before := compiler.BaselineHash()
	*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("fdca:1a2b:e047::/96")
	if compiler.BaselineHash() != before {
		t.Fatal("caller changed the owned translation geometry")
	}
	actual, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	b.NetworkModel.NAT46Prefix = nil
	expected, err := testCompiler(t, b).Compile(input)
	if err != nil || !reflect.DeepEqual(actual.Grants, expected.Grants) {
		t.Fatal("translation geometry changed delegated permission", err)
	}
	if err := compiler.CheckCandidate(t.Context(), actual); err != nil {
		t.Fatal(err)
	}
}

func TestNAT46GeometryRejectsDanglingAndOverlappingAllocations(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"disabled", "missing mappings", "ambiguous pools", "ipv4", "mapped", "public", "wrong length", "host bits", "native source", "native aliases", "services", "nat64", "chained target", "chained source", "duplicate target", "router"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, _ := nat46GeometryFixture(t)
			switch name {
			case "disabled":
				b.NAT46, b.NAT46Pools = nil, nil
			case "missing mappings":
				b.NAT46 = nil
			case "ambiguous pools":
				b.NAT46Pools = append(b.NAT46Pools, netip.MustParsePrefix("10.251.0.0/24"))
			case "ipv4":
				*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("10.249.0.0/24")
			case "mapped":
				*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("::ffff:10.249.0.0/120")
			case "public":
				*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("2001:db8:46::/96")
			case "wrong length":
				*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("fdca:1a2b:e046::/64")
			case "host bits":
				*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("fdca:1a2b:e046::1/96")
			case "native source":
				*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("fdca:1a2b:3::/96")
			case "native aliases":
				b.NAT46Pools = prefixes("10.240.3.0/24")
				b.NAT46[0].Alias = netip.MustParseAddr("10.240.3.50")
			case "services":
				b.NetworkModel.ServicePrefixes = prefixes("fdca:1a2b:e046::/96")
				b.ProtectedNetworks = append(b.ProtectedNetworks, NetworkBlock{ProtectionID: "P03", Networks: b.NetworkModel.ServicePrefixes})
			case "nat64":
				*b.NetworkModel.NAT46Prefix = b.NAT64[1].Prefix
			case "chained target":
				b.NAT46[0].Target = netip.MustParseAddr("fdca:1a2b:e046::10")
			case "chained source":
				pool := netip.MustParsePrefix("10.252.0.0/24")
				b.NAT64[1].SourcePool = &pool
				b.NAT64[1].SourceMappings = []NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b:e046::10"), Alias: netip.MustParseAddr("10.252.0.10"), Ready: true}}
			case "duplicate target":
				b.NAT46[1].Target = b.NAT46[0].Target
			case "router":
				b.ProtectedNetworks = append(b.ProtectedNetworks, NetworkBlock{ProtectionID: "P01", Networks: prefixes("fdca:1a2b:e046::1/128")})
			}
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeBaseline(raw); err == nil {
				t.Fatal("unsafe translator source geometry accepted")
			}
		})
	}
}
