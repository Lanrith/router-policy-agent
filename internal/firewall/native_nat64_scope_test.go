package firewall

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT64ProjectionPreservesIPv4DenyBeforeTranslatorPermit(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "any", From: []policy.NetworkSelector{{Interface: "lan10"}},
			To: []policy.NetworkSelector{{Interface: b.NetworkModel.UplinkInterface, Addresses: []netip.Prefix{netip.MustParsePrefix("185.156.175.51/32")}}}},
		{Action: "allow", Authorization: "owner", Protocol: "any", From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b::/64")}}},
			To: []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}},
	}
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := nativeNAT64ProjectedRules(t.Context(), rules, transport)
	if err != nil {
		t.Fatal(err)
	}
	denies, err := projected.scopes(t.Context(), 0, false, false)
	if err != nil || len(denies) != 1 || !strings.Contains(denies[0].text, "fdca:1a2b:e064::b99c:af33") {
		t.Fatal("IPv4 deny was not projected under the selected NAT64 prefix", denies, err)
	}
	if got := nativeNAT64IPv4Prefix(transport.prefix, projected.rules[0].To[0].Addresses[0]); got != netip.MustParsePrefix("185.156.175.51/32") {
		t.Fatal("NAT64 target projection is not reversible", got)
	}
	permits, err := projected.scopes(t.Context(), 1, false, false)
	if err != nil || len(permits) != 1 || !strings.Contains(permits[0].text, transport.prefix.String()) {
		t.Fatal("explicit translator permit disappeared during projection", permits, err)
	}
}

func TestNAT64ProjectionKeepsOriginalRuleIndicesAndRejectsOtherFamilies(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "sctp", From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}},
		{Action: "allow", Authorization: "owner", Protocol: "icmp", From: []policy.NetworkSelector{{Interface: "lan10"}},
			To: []policy.NetworkSelector{{Interface: b.NetworkModel.UplinkInterface, Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.3.0/24")}}}},
	}
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := nativeNAT64ProjectedRules(t.Context(), rules, transport)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected.rules) != 2 || len(projected.rules[0].From) != 0 || projected.rules[1].Protocol != "icmpv6" || projected.rules[1].Family != 6 {
		t.Fatal("NAT64 projection changed original rule indices or ICMP family", projected.rules)
	}
}
