package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT64WireScopesKeepOriginalSourceAndFinalInterface(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{443},
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64"), MAC: "02:00:00:00:00:10"}},
		To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.10/32")}}}}
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := nativeNAT64EgressPolicies(t.Context(), rules, transport)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, iface, mac, outgoing string
		reply                      bool
		wanted                     bool
	}{
		{"original", "lan10", "02:00:00:00:00:10", "lan13", false, true},
		{"correlated reply", "lan10", "02:00:00:00:00:10", "lan13", true, true},
		{"wrong original interface", "wan", "02:00:00:00:00:10", "lan13", false, false},
		{"wrong MAC class", "lan10", "02:00:00:00:00:11", "lan13", false, false},
		{"complement MAC class", "lan10", "", "lan13", false, false},
		{"wrong final interface", "lan10", "02:00:00:00:00:10", "wan", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var selected nativeNAT64EgressPolicy
			for _, path := range paths {
				if path.iface == test.outgoing {
					selected = path
				}
			}
			scopes, err := nativeNAT64WireScopes(t.Context(), transport, selected,
				nativeSourceIdentity{iface: test.iface, mac: test.mac}, 0, test.reply)
			if err != nil || (len(scopes) != 0) != test.wanted {
				t.Fatal("wire predicate changed its endpoint conjunction", scopes, err)
			}
			if !test.wanted {
				return
			}
			expected := []string{`iifname "nat64-internal"`, `oifname "lan13"`,
				"ip saddr @native_n64_0_source_scope_0", "ip daddr 10.240.3.10", "tcp dport 443"}
			if test.reply {
				expected = []string{`oifname "nat64-internal"`, `iifname "lan13"`,
					"ip daddr @native_n64_0_source_scope_0", "ip saddr 10.240.3.10", "tcp sport 443"}
			}
			for _, value := range expected {
				if !strings.Contains(scopes[0].text, value) {
					t.Fatal("wire predicate omitted original identity or logical target", value, scopes[0].text)
				}
			}
			if strings.Contains(scopes[0].text, "accept") {
				t.Fatal("scope projection acquired packet authority")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := nativeNAT64WireScopes(ctx, transport, paths[0], nativeSourceIdentity{iface: "lan10"}, 0, false); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled wire projection proceeded", err)
	}
}

func TestNAT64AttachmentsRetainTheirTypedSourceFloor(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	layout, err := newNativeNAT64AccessLayout(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	name := layout.native.sourceGuards["nat64-internal"]
	for family, graph := range map[string]map[string][]nativeScope{"inet": layout.native.inet, "netdev": layout.native.netdev} {
		rules := nativeRulesText(graph[name])
		if len(rules) != 3 || rules[2] != "drop" {
			t.Fatal("translator floor is not bounded to its two source ranges", family, rules)
		}
		text := strings.Join(rules, "\n")
		for _, wanted := range []string{"ip saddr " + b.NAT64[0].SourcePool.String(), "ip6 saddr " + b.NAT64[0].Prefix.String()} {
			if !strings.Contains(text, wanted) {
				t.Fatal("translator source family lost its geometry", family, wanted, text)
			}
		}
		if strings.Contains(text, "accept") {
			t.Fatal("source attachment floor acquired authorization", family)
		}
		wan := strings.Join(nativeRulesText(graph[layout.native.sourceGuards["wan"]]), "\n")
		for _, forbidden := range []string{"ip saddr " + b.NAT64[0].SourcePool.String() + " drop", "ip6 saddr " + b.NAT64[0].Prefix.String() + " drop"} {
			if !strings.Contains(wan, forbidden) {
				t.Fatal("WAN can spoof translator source space", family, forbidden)
			}
		}
	}
}
