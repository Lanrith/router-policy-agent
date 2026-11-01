package firewall

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT64EgressPlansPreserveWholeOrderedRules(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "tcp", Ports: []uint16{443},
			From: []policy.NetworkSelector{{Interface: "lan10", MAC: "02:00:00:00:00:10"}},
			To:   []policy.NetworkSelector{{Interface: "wan", Addresses: sourceClassPrefixes("10.240.3.0/24")}}},
		{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{443, 444},
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
			To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.10/32")}}},
		{Action: "allow", Authorization: "owner", Protocol: "icmp", From: []policy.NetworkSelector{{Interface: "lan10"}},
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
	paths, err := nativeNAT64EgressPolicies(t.Context(), rules, transport)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != len(transport.destinations) || len(paths) < 3 {
		t.Fatal("final-egress inventory lost a native path")
	}
	for _, path := range paths {
		t.Run(path.iface, func(t *testing.T) {
			t.Parallel()
			if path.raw.baselineHash != rules.baselineHash || len(path.raw.rules) != len(rules.rules) {
				t.Fatal("final-egress projection lost immutable graph identity")
			}
			for index, original := range rules.rules {
				projected := path.raw.rules[index]
				if projected.Action != original.Action || projected.Authorization != original.Authorization ||
					!reflect.DeepEqual(projected.Ports, original.Ports) {
					t.Fatal("projection changed rule order, authorization or listener", index)
				}
				scopes, err := path.raw.scopes(t.Context(), index, false, false)
				if err != nil {
					t.Fatal(err)
				}
				wanted := index == 2 || index == 0 && path.iface == "wan" || index == 1 && path.iface == "lan13"
				if (len(scopes) != 0) != wanted {
					t.Fatal("logical destination leaked into another final interface", index, scopes)
				}
				for _, scope := range scopes {
					if !strings.Contains(scope.text, `oifname "nat64-internal"`) ||
						!strings.Contains(scope.text, `iifname "lan10"`) || strings.Contains(scope.text, "accept") {
						t.Fatal("raw projection lost attachment constraints or gained authority", scope.text)
					}
				}
				if index == 2 && projected.Protocol != "icmpv6" {
					t.Fatal("ICMP projection lost its original family")
				}
			}
		})
	}
}

func TestNAT64EgressPlansRejectMissingOrChangedOrigin(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*nativeRuleSet, *nativeNAT64Transport)
	}{
		{"missing baseline identity", func(set *nativeRuleSet, _ *nativeNAT64Transport) { set.baselineHash = "" }},
		{"foreign baseline", func(set *nativeRuleSet, _ *nativeNAT64Transport) { set.baselineHash = strings.Repeat("0", 64) }},
		{"missing final interfaces", func(_ *nativeRuleSet, transport *nativeNAT64Transport) { transport.destinations = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			set, selected := *rules, *transport
			test.edit(&set, &selected)
			if _, err := nativeNAT64EgressPolicies(t.Context(), &set, &selected); err == nil {
				t.Fatal("missing or changed graph origin accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := nativeNAT64EgressPolicies(ctx, rules, transport); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled final-egress projection proceeded", err)
	}
}

func TestNAT64RawProgramSharingRetainsFirstOriginAndCompleteOrder(t *testing.T) {
	t.Parallel()
	first := &nativeRuleSet{baselineHash: strings.Repeat("a", 64), rules: []policy.NetworkRule{{
		Action: "allow", Authorization: "owner", Protocol: "udp", Ports: []uint16{6061},
		From: []policy.NetworkSelector{{Interface: "lan10", MAC: "02:00:00:00:00:10"}},
		To:   []policy.NetworkSelector{{Interface: "nat64-internal"}},
	}}}
	for _, edit := range []func(*policy.NetworkRule){
		func(rule *policy.NetworkRule) { rule.Action = "deny" },
		func(rule *policy.NetworkRule) { rule.Authorization = "directory" },
		func(rule *policy.NetworkRule) { rule.Protocol = "tcp" },
		func(rule *policy.NetworkRule) { rule.Ports = []uint16{6062} },
		func(rule *policy.NetworkRule) { rule.From = []policy.NetworkSelector{{Interface: "lan11"}} },
		func(rule *policy.NetworkRule) { rule.From = []policy.NetworkSelector{{MAC: "02:00:00:00:00:11"}} },
		func(rule *policy.NetworkRule) {
			rule.To = []policy.NetworkSelector{{Addresses: sourceClassPrefixes("fdca:1a2b:e064::/96")}}
		},
	} {
		changed := &nativeRuleSet{baselineHash: first.baselineHash, rules: slices.Clone(first.rules)}
		edit(&changed.rules[0])
		duplicate := &nativeRuleSet{baselineHash: first.baselineHash, rules: first.rules}
		paths := []nativeNAT64EgressPolicy{{iface: "wan", raw: first}, {iface: "lan13", raw: duplicate},
			{iface: "lan11", raw: changed}, {iface: "lan12", raw: first}}
		programs, err := nativeNAT64RawPrograms(t.Context(), paths)
		if err != nil || len(programs) != 2 || programs[0] != first || programs[1] != changed {
			t.Fatal("sharing changed the first origin or merged a distinct ordered predicate", err)
		}
		if len(paths) != 4 || paths[1].iface != "lan13" || paths[1].raw != duplicate {
			t.Fatal("raw sharing changed the independent final-interface inventory")
		}
	}
}

func TestNAT64RawProgramSharingRejectsMissingForeignOrCancelledOrigin(t *testing.T) {
	t.Parallel()
	first := &nativeRuleSet{baselineHash: strings.Repeat("a", 64)}
	for _, paths := range [][]nativeNAT64EgressPolicy{
		nil, {{}}, {{raw: &nativeRuleSet{}}}, {{raw: first}, {}},
		{{raw: first}, {raw: &nativeRuleSet{baselineHash: strings.Repeat("b", 64)}}},
	} {
		if _, err := nativeNAT64RawPrograms(t.Context(), paths); err == nil {
			t.Fatal("sharing accepted a missing or foreign origin")
		}
	}
	paths := []nativeNAT64EgressPolicy{{raw: first}}
	var missing context.Context
	if _, err := nativeNAT64RawPrograms(missing, paths); err == nil {
		t.Fatal("sharing accepted a missing context")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := nativeNAT64RawPrograms(ctx, paths); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled raw program sharing proceeded", err)
	}
}
