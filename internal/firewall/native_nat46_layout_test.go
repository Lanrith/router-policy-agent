package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

func nat46ForwardingBaseline(t *testing.T) policy.Baseline {
	t.Helper()
	b := nativeAccessBaseline(t)
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	b.NAT46 = []policy.NAT46{{ID: "mapped", Alias: netip.MustParseAddr("10.250.0.20"), Target: netip.MustParseAddr("fdca:1a2b:3::10"), Ready: true}}
	rule := policy.NetworkRule{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6053}, From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.0/24")}}, To: []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:3::/64")}}}
	udp, owner := rule, rule
	udp.Protocol = "udp"
	owner.Protocol, owner.Authorization, owner.Ports = "any", "owner", nil
	b.NetworkModel.Rules = []policy.NetworkRule{rule, udp, owner}
	return b
}

func TestNAT46JoinedLayoutKeepsRawAndWireAuthoritySeparate(t *testing.T) {
	t.Parallel()
	b := nat46ForwardingBaseline(t)
	layout, err := newNativeNAT46AccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	for family, graph := range map[string]map[string][]nativeScope{"inet": layout.native.inet, "netdev": layout.native.netdev} {
		depth, path := nativeTestChainDepth(graph)
		t.Logf("%s native validation depth %d: %v", family, depth, path)
		if depth >= 16 {
			t.Fatal("joined graph exceeds nft static validation depth", family, depth, path)
		}
	}
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"jump native_forward_floor", "jump native_source", "native_n46_raw_eligible", "native_n46_select_context", "native_translation_facts_restore", "native_n46_static_source_live", "native_n46_to4_tcp", "native_n46_to6_tcp", "native_n46_raw_policy", "native_n46_wire_policy", "native_n46_physical"} {
		if !bytes.Contains(program, []byte(required)) {
			t.Fatal("joined layout omitted a mandatory boundary", required)
		}
	}
	deferred := nativeRulesText(layout.native.inet["native_0_guard_forward_original_decision_state"])
	if len(deferred) != 2 || deferred[0] != "oifname != \"nat46\" jump native_grant" {
		t.Fatal("directory candidate changed ordinary native grant checks", deferred)
	}
	if layout.native.ruleCount(layout.interfaces) > nativeRuleCapacity {
		t.Fatal("joined program exceeded the complete native rule capacity")
	}
	b.NAT46[0].Target = netip.MustParseAddr("fdca:1a2b:3::99")
	b.NetworkModel.Rules[0].Ports[0] = 22
	after, err := layout.program(t.Context())
	if err != nil || !bytes.Equal(program, after) {
		t.Fatal("caller changed the completed immutable translator graph", err)
	}
	if _, err := newNativeAccessLayout(t.Context(), b); err == nil {
		t.Fatal("translator-only constructor silently activated ordinary native admission")
	}
	defaultLayout, err := newGuardLayout(b)
	if err != nil || defaultLayout.native != nil {
		t.Fatal("joined component changed installed profile admission", err)
	}
}

func TestNAT46JoinedLayoutRejectsUnqualifiedAttachmentsAndCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newNativeNAT46AccessLayout(ctx, nat46ForwardingBaseline(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled construction proceeded", err)
	}
	for _, name := range []string{"WAN", "reverse MAC"} {
		t.Run(name, func(t *testing.T) {
			b := nat46ForwardingBaseline(t)
			switch name {
			case "WAN":
				b.NAT46[0].Target = netip.MustParseAddr("2001:db8:999::10")
			case "reverse MAC":
				b.NetworkModel.Rules[2].From = []policy.NetworkSelector{{Interface: "lan13", MAC: "02:00:00:00:00:ee"}}
			}
			if _, err := newNativeNAT46AccessLayout(t.Context(), b); err == nil {
				t.Fatal("unqualified translator geometry was accepted", name)
			}
		})
	}
}

func TestNAT46TargetRemainsOnLANWithInternalCoreDependency(t *testing.T) {
	t.Parallel()
	b := nat46ForwardingBaseline(t)
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{
		ProtectionID: "P03", Networks: sourceClassPrefixes("10.241.254.0/24", "fdca:1a2b:fe02::/64"),
	})
	b.NetworkModel.CoreServices = []policy.CoreService{{
		Kind: "dns", Interface: "services0",
		Addresses: []netip.Addr{netip.MustParseAddr("10.241.254.10"), netip.MustParseAddr("fdca:1a2b:fe02::10")},
		Clients:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.0/24", "fdca:1a2b:3::/64")}},
	}}
	b.NetworkModel.CoreEgress = []policy.CoreEgress{{
		Kind: "logs", Interface: "services0", Address: netip.MustParseAddr("fdca:1a2b:fe02::60"),
		DestinationInterface: "lan13", Destinations: sourceClassPrefixes("fdca:1a2b:3::30/128"),
	}}
	layout, err := newNativeNAT46AccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(layout.native.serviceInterfaces, "lan13") || !slices.Contains(layout.native.serviceInterfaces, "services0") {
		t.Fatal("internal dependency confused the physical destination with the service namespace")
	}
}

func TestCombinedNAT64PoolsAndNAT46LayoutKeepIndependentAttachments(t *testing.T) {
	t.Parallel()
	b := nat46ForwardingBaseline(t)
	first := nat64TransportFixture(t).NAT64[0]
	secondPool := netip.MustParsePrefix("10.252.0.0/24")
	second := policy.NAT64{ID: "nat64-private", Prefix: netip.MustParsePrefix("fdca:1a2b:e065::/96"), Scope: "private", SourcePool: &secondPool}
	b.NAT64 = []policy.NAT64{first, second}
	for _, nat64 := range b.NAT64 {
		b.NetworkModel.Rules = append(b.NetworkModel.Rules, policy.NetworkRule{
			Action: "allow", Authorization: "owner", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
			To:   []policy.NetworkSelector{{Interface: nat64.ID, Addresses: []netip.Prefix{nat64.Prefix}}},
		})
	}
	layout, err := newNativeNAT46AccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	if layout.native.nat46Transport == nil || layout.native.nat64Transport != nil || len(layout.native.nat64Transports) != 2 {
		t.Fatal("combined layout detached one translator")
	}
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"native_n46_raw_policy", "native_n46_wire_policy", "native_n64_zone", "native_n64_export", "native_n64_0_tokens", "native_n64_1_tokens"} {
		if !bytes.Contains(program, []byte(required)) {
			t.Fatal("combined layout omitted an independently selected translator boundary", required)
		}
	}
	if !slices.Contains(layout.interfaces, "nat46") || !slices.Contains(layout.interfaces, first.ID) || !slices.Contains(layout.interfaces, second.ID) {
		t.Fatal("combined translator attachments were not independently hooked", layout.interfaces)
	}
	logical := guardChanges{}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	data, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	history := state.EmptyClassification()
	prepared, err := prepareLayoutGuards(t.Context(), &preparedBatch{data: data}, &history, layout)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.nat46Model == nil || prepared.nat64Transport != nil || len(prepared.nat64Transports) != 2 {
		t.Fatal("combined guard preparation detached a translator projection")
	}
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal("combined translator revocation transaction failed validation", err)
	}
}

func TestNAT46RawScopesKeepOriginalListenerAndReadyMapping(t *testing.T) {
	t.Parallel()
	b := nat46ForwardingBaseline(t)
	model, err := newNativeNAT46Model(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	for _, physical := range []bool{false, true} {
		scopes, err := model.sharedRawScopes(t.Context(), 0, nativePacketContext{iface: "lan10", family: 4}, "tcp", true, physical)
		if err != nil || len(scopes) != 1 || !strings.Contains(scopes[0].text, "ip saddr 10.250.0.20") || !strings.Contains(scopes[0].text, "tcp sport 6053") || !strings.Contains(scopes[0].text, "oifname \"lan10\"") {
			t.Fatal("raw reply broadened its original endpoint, attachment or listener", scopes, err)
		}
	}
}

// nft's static graph validator counts goto edges as well as jump edges.
func nativeTestChainDepth(graph map[string][]nativeScope) (int, []string) {
	var visit func(string, []string) []string
	visit = func(name string, prior []string) []string {
		if slices.Contains(prior, name) {
			panic(fmt.Sprintf("recursive native chain %v -> %s", prior, name))
		}
		path := append(slices.Clone(prior), name)
		longest := path
		for _, rule := range graph[name] {
			for _, expression := range rule.expressions {
				value, ok := expression.(map[string]any)
				if !ok {
					continue
				}
				for _, verdict := range []string{"jump", "goto"} {
					target, ok := value[verdict].(map[string]any)
					if !ok {
						continue
					}
					next, ok := target["target"].(string)
					if !ok {
						continue
					}
					candidate := visit(next, path)
					if len(candidate) > len(longest) {
						longest = candidate
					}
				}
			}
		}
		return longest
	}
	longest := []string{}
	for name := range graph {
		candidate := visit(name, nil)
		if len(candidate) > len(longest) {
			longest = candidate
		}
	}
	return len(longest) - 1, longest
}

func TestNativeNAT46ReverseEchoUsesTypedProtocol(t *testing.T) {
	t.Parallel()
	sources, err := newNativeNAT46StaticSources(t.Context(), nat46ForwardingBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	model := sources.model
	model.rules.rules = append(model.rules.rules, policy.NetworkRule{Action: "deny", Authorization: "inherit", Protocol: "any", From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}})
	for _, wire := range []bool{false, true} {
		for _, physical := range []bool{false, true} {
			scopes, err := model.reverseScopes(t.Context(), len(model.rules.rules)-1, nativeNAT46ContextGroup{iface: "lan10", protocol: "icmp"}, wire, physical)
			if err != nil || len(scopes) == 0 {
				t.Fatal("reverse echo predicate missing", err)
			}
			protocol := "icmp"
			if wire {
				protocol = "icmpv6"
			}
			for _, scope := range scopes {
				if strings.Contains(scope.text, "meta l4proto") || !strings.Contains(scope.text, protocol+" type echo-reply") || !strings.Contains(scope.text, protocol+" code 0") {
					t.Fatal("reverse echo protocol is not constrained by its typed fields", scope.text)
				}
			}
		}
	}
}
