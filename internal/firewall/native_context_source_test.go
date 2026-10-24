package firewall

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNativePhysicalSharingRetainsEveryOriginalPredicate(t *testing.T) {
	t.Parallel()
	set, err := newNativeRuleSet(nativeScopeBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	contexts := []nativePacketContext{
		{id: 1, chain: "class0", rawChain: "raw", iface: "lan10", mac: "02:00:00:00:00:10", family: 4},
		{id: 2, chain: "class1", rawChain: "raw", iface: "lan10", mac: "02:00:00:00:00:10", family: 4},
		{id: 3, chain: "ipv6", rawChain: "raw", iface: "lan10", mac: "02:00:00:00:00:10", family: 6},
		{id: 4, chain: "other_mac", rawChain: "raw", iface: "lan10", mac: "02:00:00:00:00:11", family: 4},
		{id: 5, chain: "other_interface", rawChain: "raw", iface: "lan13", mac: "02:00:00:00:00:10", family: 4},
	}
	for _, reply := range []bool{false, true} {
		groups := nativePhysicalContexts(contexts, reply)
		if len(groups) != 4 || !reflect.DeepEqual(groups[0].ids, []uint64{1, 2}) || contexts[0].natPhysicalChain(reply) == contexts[1].natPhysicalChain(reply) {
			t.Fatal("native sharing merged another attachment, family or rewritten source class")
		}
		seen := map[uint64]bool{}
		for _, group := range groups {
			expected, err := set.physicalScopes(t.Context(), 0, group.packet, reply, false)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range group.ids {
				actual, err := set.physicalScopes(t.Context(), 0, contexts[id-1], reply, false)
				if err != nil || seen[id] || !reflect.DeepEqual(actual, expected) {
					t.Fatal("group changed an original physical predicate or identity inventory", err)
				}
				seen[id] = true
			}
		}
		if len(seen) != len(contexts) {
			t.Fatal("physical sharing discarded an original context")
		}
	}
}

func TestNativeContextMACClassesRespectTheirIncomingAttachment(t *testing.T) {
	t.Parallel()
	b := nativeScopeBaseline(t)
	set, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nativeContextMACs(set, "lan10"), []string{"02:00:00:00:00:10"}) || len(nativeContextMACs(set, "lan13")) != 0 {
		t.Fatal("a MAC-specific selector escaped its paired incoming interface")
	}
	set.rules[0].From[0].Interface = ""
	for _, iface := range []string{"lan10", "lan13", "wan"} {
		if !reflect.DeepEqual(nativeContextMACs(set, iface), []string{"02:00:00:00:00:10"}) {
			t.Fatal("an unscoped MAC selector lost a reachable incoming interface")
		}
	}
}

func sourceContextAt(t *testing.T, classes []nativeContextSource, raw string) nativeContextSource {
	t.Helper()
	address := netip.MustParseAddr(raw)
	matches := []nativeContextSource{}
	for _, class := range classes {
		if class.family == 6 && address.Is6() {
			matches = append(matches, class)
			continue
		}
		if class.family != 4 || !address.Is4() {
			continue
		}
		if class.source != nil {
			if class.source.contains(address) {
				matches = append(matches, class)
			}
			continue
		}
		outside := true
		for _, pool := range class.pools {
			outside = outside && !pool.Contains(address)
		}
		if outside {
			matches = append(matches, class)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("address %s selected %d context classes", address, len(matches))
	}
	return matches[0]
}

func TestSourceContextRetainsOriginalAndReplyHostSelectors(t *testing.T) {
	t.Parallel()
	original := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "tcp", From: []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.10/32"), MAC: "02:00:00:00:00:13"}}, To: []policy.NetworkSelector{{Interface: "wan"}}}
	inbound := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "tcp", From: []policy.NetworkSelector{{Interface: "wan"}}, To: []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.11/32")}}}
	otherFamily := original
	otherFamily.Family = 6
	otherFamily.From = []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:3::/64")}}
	set := &nativeRuleSet{rules: []policy.NetworkRule{original, inbound, otherFamily}, uplinkNAT: []policy.UplinkNAT{{Interface: "lan13", Sources: sourceClassPrefixes("10.240.3.0/24")}}}
	classes, err := nativeContextSources(t.Context(), set, "lan13")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, address, mac string
		rule               policy.NetworkRule
		want               bool
	}{
		{"original exact source", "10.240.3.10", "02:00:00:00:00:13", original, true},
		{"original wrong source", "10.240.3.11", "02:00:00:00:00:13", original, false},
		{"original wrong MAC", "10.240.3.10", "02:00:00:00:00:14", original, false},
		{"reply exact original target", "10.240.3.11", "02:00:00:00:00:14", inbound, true},
		{"reply wrong original target", "10.240.3.10", "02:00:00:00:00:14", inbound, false},
		{"ordinary NAT source complement", "10.240.3.12", "02:00:00:00:00:13", original, false},
		{"non NAT IPv4 source", "10.241.3.10", "02:00:00:00:00:13", original, false},
		{"IPv6 source stays native", "fdca:1a2b:3::10", "02:00:00:00:00:13", otherFamily, true},
		{"IPv4 cannot borrow IPv6 context", "10.240.3.10", "02:00:00:00:00:13", otherFamily, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			class := sourceContextAt(t, classes, test.address)
			if class.relevant(test.rule, "lan13", test.mac) != test.want {
				t.Fatal("source context changed rule attachment, family, MAC or address scope")
			}
		})
	}
	if got := sourceContextAt(t, classes, "10.240.3.11"); got.source == nil || got.source.prefix.Bits() != 32 {
		t.Fatal("original target host boundary was lost in reply context")
	}
}

func TestSourceContextLeavesTranslatorFreeNativeGeometryUnchanged(t *testing.T) {
	t.Parallel()
	classes, err := nativeContextSources(t.Context(), &nativeRuleSet{}, "lan13")
	if err != nil || len(classes) != 1 || classes[0].family != 0 || classes[0].source != nil || classes[0].predicate.text != "" || len(classes[0].predicate.expressions) != 0 {
		t.Fatal("absent source NAT changed native context", err)
	}
}

func TestUplinkNATRequiresStaticAddressesAndKeepsDefaultInactive(t *testing.T) {
	t.Parallel()
	b := nativeCoreBaseline(t)
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: sourceClassPrefixes("10.243.0.1/32"), Roles: []policy.Role{}})
	b.NetworkModel.UplinkNAT = []policy.UplinkNAT{{Interface: "lan13", Sources: sourceClassPrefixes("10.240.3.0/24"), Addresses: []netip.Addr{netip.MustParseAddr("10.243.0.1")}}}
	layout, err := newNativeAccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal("static source NAT geometry rejected", err)
	}
	program, err := layout.program(t.Context())
	if err != nil || !strings.Contains(string(program), "hook postrouting priority 99") || !strings.Contains(string(program), "hook postrouting priority 101") {
		t.Fatal("missing all-packet source NAT guards", err)
	}
	defaultLayout, err := newGuardLayout(b)
	if err != nil || defaultLayout.native != nil {
		t.Fatal("source NAT component activated the unqualified default helper", err)
	}
	b.NetworkModel.UplinkNAT[0].Addresses = []netip.Addr{}
	if _, err := newNativeAccessLayout(t.Context(), b); err == nil || !strings.Contains(err.Error(), "qualified dynamic addresses") {
		t.Fatal("dynamic source NAT invented static address authority", err)
	}
}
