package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nat46ContextFixture(t *testing.T) (*nativeNAT46Model, map[int][]nativePacketContext) {
	t.Helper()
	b := nativeNAT46ModelFixture(t)
	for index := 22; index <= 25; index++ {
		b.NAT46 = append(b.NAT46, policy.NAT46{ID: fmt.Sprintf("mapped-%d", index), Alias: netip.MustParseAddr(fmt.Sprintf("10.250.0.%d", index)), Target: netip.MustParseAddr(fmt.Sprintf("fdca:1a2b:2::%d", index)), Ready: true})
	}
	owner := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "any",
		From: []policy.NetworkSelector{{Interface: "lan10"}},
		To:   []policy.NetworkSelector{{Interface: "nat46", Addresses: sourceClassPrefixes("10.250.0.0/24")}}}
	b.NetworkModel.Rules = append(b.NetworkModel.Rules, owner)
	model, err := newNativeNAT46Model(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	return model, map[int][]nativePacketContext{
		0: {{id: 7, iface: "lan10", mac: "02:00:00:00:00:10", family: 4}},
		1: {{id: 9, iface: "lan10", mac: "02:00:00:00:00:10", family: 4}, {id: 18, iface: "lan10", mac: "02:00:00:00:00:10", family: 4}, {id: 20, iface: "lan10", family: 6}},
	}
}

func TestNAT46MappedContextsKeepMappingProtocolAndNativeIdentitySeparate(t *testing.T) {
	t.Parallel()
	model, original := nat46ContextFixture(t)
	plan, err := model.contextPlan(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.entries) != 19 || len(plan.groups) != 3 {
		t.Fatal("unexpected reachable mapping/protocol inventory", len(plan.entries), len(plan.groups), err)
	}
	seen := map[uint64]bool{}
	for _, entry := range plan.entries {
		if entry.packet.id <= 20 || seen[entry.packet.id] || slices.Contains(entry.originalIDs, uint64(20)) {
			t.Fatal("mapped context reused a native or IPv6 context")
		}
		seen[entry.packet.id] = true
		for _, wire := range []bool{false, true} {
			for _, reply := range []bool{false, true} {
				for _, physical := range []bool{false, true} {
					binding := entry.binding(model, wire, reply, physical)
					endpoint := model.mappings[entry.mapping].alias
					if wire {
						endpoint = model.mappings[entry.mapping].target
					}
					if !strings.Contains(binding.text, endpoint.String()) || !strings.Contains(binding.text, "oifname ") || strings.Contains(binding.text, "iifname ") == physical || strings.Contains(binding.text, "accept") {
						t.Fatal("binding lost its actual endpoint/attachment or gained a verdict", binding.text)
					}
					if wire && !strings.Contains(binding.text, model.prefix.String()) {
						t.Fatal("wire binding admitted a non-translator client")
					}
					if entry.protocol == "icmp" && (!strings.Contains(binding.text, "echo-") || !strings.Contains(binding.text, "code 0")) {
						t.Fatal("mapping context opened arbitrary control traffic")
					}
				}
			}
		}
	}
	permuted := map[int][]nativePacketContext{1: slices.Clone(original[1]), 0: slices.Clone(original[0])}
	slices.Reverse(permuted[1])
	other, err := model.contextPlan(t.Context(), permuted)
	if err != nil || !reflect.DeepEqual(plan, other) {
		t.Fatal("map or caller slice order changed immutable context allocation", err)
	}
	original[0][0].id, original[0][0].iface = 99, "wan0"
	if !reflect.DeepEqual(plan.entries[0].originalIDs, []uint64{7}) || plan.entries[0].packet.iface != "lan10" {
		t.Fatal("caller changed retained root context facts")
	}
}

func TestNAT46MappedContextCapacityAndInvalidInventoriesFailClosed(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"last available", "exhausted", "duplicate", "invalid id", "invalid family", "missing interface", "negative rule", "unknown rule"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			model, original := nat46ContextFixture(t)
			original[1] = []nativePacketContext{{id: 1022, iface: "lan10", family: 6}}
			valid := false
			switch name {
			case "last available":
				valid = true
			case "exhausted":
				original[1][0].id = 1023
			case "duplicate":
				original[1][0].id = 7
			case "invalid id":
				original[1][0].id = 1024
			case "invalid family":
				original[1][0].family = 5
			case "missing interface":
				original[1][0].iface = ""
			case "negative rule":
				original[-1] = original[1]
			case "unknown rule":
				original[2] = original[1]
			}
			plan, err := model.contextPlan(t.Context(), original)
			if valid {
				if err != nil || len(plan.entries) != 1 || plan.entries[0].packet.id != 1023 {
					t.Fatal("last reserved context was not usable", err)
				}
			} else if err == nil || plan != nil {
				t.Fatal("unsafe context inventory admitted")
			}
		})
	}
	model, original := nat46ContextFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := model.contextPlan(ctx, original); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context allocation continued", err)
	}
	for _, original := range []map[int][]nativePacketContext{nil, {0: {}}} {
		if original != nil {
			model.rules.rules[0].Action = "deny"
		}
		if _, err := model.contextPlan(t.Context(), original); err == nil {
			t.Fatal("missing or deny-rule context inventory admitted")
		}
	}
}

func TestNAT46MappedPolicySharesScopesButRetainsTerminalAuthorization(t *testing.T) {
	t.Parallel()
	model, original := nat46ContextFixture(t)
	plan, err := model.contextPlan(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	for index, group := range plan.groups {
		for _, reply := range []bool{false, true} {
			for _, physical := range []bool{false, true} {
				program, err := plan.wirePolicy(t.Context(), index, reply, physical)
				if err != nil {
					t.Fatal(err)
				}
				// A group with several original contexts emits the ordered source
				// predicate once. The branch then checks only IDs of that rule.
				ordered := program.chains[program.entry+"_ordered"]
				if len(group.entries) < 1 || len(ordered) > 8 {
					t.Fatal("context expansion duplicated ordered predicates")
				}
				for name, rules := range program.chains {
					if len(rules) == 0 || rules[len(rules)-1].text != "drop" || strings.Contains(name, "hook") {
						t.Fatal("shared policy acquired an open terminal path")
					}
					for _, rule := range rules {
						if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "ct mark set") {
							t.Fatal("shared scope acquired authority or changed immutable facts")
						}
					}
				}
			}
		}
	}
	handoff, err := plan.handoff(t.Context())
	expected := 1
	for _, entry := range plan.entries {
		if entry.rule == 0 { // The fixture's first rule requires a directory grant.
			expected++
		} else { // Its owner rule can use source or configuration epochs.
			expected += 2
		}
	}
	if err != nil || len(handoff["native_n46_select_context"]) != expected {
		t.Fatal("context handoff lost original namespace coverage", err)
	}
	for _, rule := range handoff["native_n46_select_context"][:expected-1] {
		if !strings.Contains(rule.text, "ct direction original") || !strings.Contains(rule.text, "0xfffffc00") || strings.Contains(rule.text, "priority set") || strings.Contains(rule.text, "ct mark set") {
			t.Fatal("handoff lost original direction or corrupted identity/epoch metadata")
		}
		delegated := strings.Contains(rule.text, "ct mark & 0x3ff == 0 ")
		if strings.Contains(rule.text, "0xd5000000") != delegated {
			t.Fatal("context remapping admitted another rule's authorization namespace")
		}
	}
}

func TestNAT46SharedScopesKeepPairedTargetsAndOnlyProjectSelectedAliases(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"native prefix", "native and alias", "alias pool", "one alias", "crossed target interfaces", "wrong alias interface", "wrong source mac", "wrong protocol", "echo"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := nativeNAT46ModelFixture(t)
			b.NetworkModel.Rules[0].To = []policy.NetworkSelector{{Interface: "lan12", Addresses: sourceClassPrefixes("fdca:1a2b:2::/64")}}
			original := nativePacketContext{iface: "lan10", mac: "02:00:00:00:00:10", family: 4}
			protocol, expected := "tcp", 1
			switch name {
			case "native and alias":
				b.NetworkModel.Rules[0].To = append(b.NetworkModel.Rules[0].To, policy.NetworkSelector{Interface: "nat46", Addresses: sourceClassPrefixes("10.250.0.0/24")})
				expected = 2
			case "alias pool":
				b.NetworkModel.Rules[0].To = []policy.NetworkSelector{{Interface: "nat46", Addresses: sourceClassPrefixes("10.250.0.0/24")}}
				expected = 2
			case "one alias":
				b.NetworkModel.Rules[0].To = []policy.NetworkSelector{{Interface: "nat46", Addresses: sourceClassPrefixes("10.250.0.20/32")}}
			case "crossed target interfaces":
				b.NetworkModel.Rules[0].To = []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:2::/64")}, {Interface: "lan12", Addresses: sourceClassPrefixes("fdca:1a2b:3::/64")}}
				expected = 0
			case "wrong alias interface":
				b.NetworkModel.Rules[0].To = []policy.NetworkSelector{{Interface: "lan12", Addresses: sourceClassPrefixes("10.250.0.0/24")}}
				expected = 0
			case "wrong source mac":
				original.mac, expected = "02:00:00:00:00:11", 0
			case "wrong protocol":
				protocol, expected = "udp", 0
			case "echo":
				protocol = "icmp"
				b.NetworkModel.Rules[0].Protocol, b.NetworkModel.Rules[0].Ports = "icmp", nil
			}
			model, err := newNativeNAT46Model(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			for _, reply := range []bool{false, true} {
				for _, physical := range []bool{false, true} {
					scopes, err := model.sharedWireScopes(t.Context(), 0, original, protocol, reply, physical)
					if err != nil || len(scopes) != expected {
						t.Fatal("sharing changed a reachable paired scope", len(scopes), expected, err)
					}
					for _, scope := range scopes {
						if strings.Contains(scope.text, "ether ") || strings.Contains(scope.text, "10.250.") || !strings.Contains(scope.text, "fdca:1a2b:e046::af0:a") {
							t.Fatal("shared scope lost original source or retained raw fields", scope.text)
						}
						if name == "native prefix" && !strings.Contains(scope.text, "fdca:1a2b:2::/64") {
							t.Fatal("sharing expanded a native prefix into per-mapping predicates")
						}
						if name == "one alias" && !strings.Contains(scope.text, "fdca:1a2b:2::20") || name == "echo" && (!strings.Contains(scope.text, "icmpv6 type echo-") || !strings.Contains(scope.text, "icmpv6 code 0")) {
							t.Fatal("alias selection or echo scope broadened", scope.text)
						}
					}
					if name == "native and alias" && (!slices.ContainsFunc(scopes, func(scope nativeScope) bool { return strings.Contains(scope.text, "fdca:1a2b:2::/64") }) || !slices.ContainsFunc(scopes, func(scope nativeScope) bool { return strings.Contains(scope.text, "fdca:1a2b:4::40") })) {
						t.Fatal("prefix sharing discarded an uncovered mapped target")
					}
				}
			}
		})
	}
}

func TestNAT46SourceHandoffGroupsKeepTheirOriginalAttachmentAndIdentityInventory(t *testing.T) {
	t.Parallel()
	sources, err := newNativeNAT46StaticSources(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	originals := []nativePacketContext{{iface: "lan10", family: 4, id: 7}, {iface: "lan10", family: 4, id: 8}}
	for _, directory := range []bool{false, true} {
		entry, graph, err := sources.sourceHandoffGroup(t.Context(), originals, directory)
		if err != nil || len(graph[entry]) != 3 {
			t.Fatal("valid source context group failed", err)
		}
		reversed := []nativePacketContext{originals[1], originals[0]}
		other, actual, err := sources.sourceHandoffGroup(t.Context(), reversed, directory)
		if err != nil || other != entry || !reflect.DeepEqual(graph, actual) {
			t.Fatal("caller order changed a context group's immutable identity", err)
		}
		for _, rule := range graph[entry] {
			if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "ct mark set") {
				t.Fatal("grouping acquired forwarding authority")
			}
		}
	}
	for _, name := range []string{"empty", "duplicate", "different interface", "ipv6", "exhausted"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			values := slices.Clone(originals)
			switch name {
			case "empty":
				values = nil
			case "duplicate":
				values[1].id = 7
			case "different interface":
				values[1].iface = "lan13"
			case "ipv6":
				values[1].family = 6
			case "exhausted":
				values[1].id = 1024
			}
			if _, _, err := sources.sourceHandoffGroup(t.Context(), values, false); err == nil {
				t.Fatal("invalid source group reached geometry lookup")
			}
		})
	}
}
