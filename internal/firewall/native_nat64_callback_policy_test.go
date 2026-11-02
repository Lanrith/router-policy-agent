package firewall

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func callbackPolicyFixture(t *testing.T) (policy.Baseline, *nativeNAT64CallbackTransport, *nativeNAT64CallbackModel) {
	t.Helper()
	baseline := nat64TransportFixture(t)
	baseline.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b:3::10"), Alias: netip.MustParseAddr("10.251.0.20"), Ready: true}}
	base := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{6053, 6062},
		From: []policy.NetworkSelector{{Interface: "lan10", MAC: "02:00:00:00:00:10", Addresses: sourceClassPrefixes("10.240.0.0/24")}},
		To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:3::10/128")}}}
	deny, directory := base, base
	deny.Action = "deny"
	deny.From = []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.12/32")}}
	directory.Authorization, directory.Ports = "directory", []uint16{6062}
	baseline.NetworkModel.Rules = []policy.NetworkRule{deny, directory, base}
	transport, err := newNativeNAT64Transport(t.Context(), baseline, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	callback, err := newNativeNAT64CallbackTransport(t.Context(), transport)
	if err != nil {
		t.Fatal(err)
	}
	model, err := newNativeNAT64CallbackModel(t.Context(), baseline, callback)
	if err != nil {
		t.Fatal(err)
	}
	return baseline, callback, model
}

func TestNAT64CallbackPolicyRetainsOrderedPairedOwnerIntent(t *testing.T) {
	t.Parallel()
	baseline, _, model := callbackPolicyFixture(t)
	if len(model.mapped.rules.rules) != 3 || len(model.mapped.mappings) != 1 {
		t.Fatal("callback changed original rule or mapping inventory")
	}
	for index, original := range baseline.NetworkModel.Rules {
		actual := model.mapped.rules.rules[index]
		if actual.Action != original.Action || actual.Authorization != original.Authorization || actual.Protocol != original.Protocol ||
			!reflect.DeepEqual(actual.From, original.From) || !reflect.DeepEqual(actual.Ports, original.Ports) || len(actual.To) != 2 ||
			actual.To[1].Interface != "nat64-internal" || actual.To[1].Addresses[0].String() != "10.251.0.20/32" {
			t.Fatal("callback widened or detached original permission", index, actual)
		}
	}
	original := nativePacketContext{iface: "lan10", mac: "02:00:00:00:00:10", family: 4, id: 17}
	for _, reply := range []bool{false, true} {
		for _, physical := range []bool{false, true} {
			for _, index := range []int{1, 2} {
				program, err := model.wirePolicy(t.Context(), index, 0, original, "tcp", reply, physical)
				if err != nil {
					t.Fatal(err)
				}
				ordered := program.chains[program.entry+"_ordered"]
				if len(ordered) != 4 || !strings.Contains(ordered[0].text, "_rule_0") || !strings.Contains(ordered[1].text, "_rule_1") || ordered[3].text != "drop" {
					t.Fatal("callback lost first-match ordering", ordered)
				}
				if !strings.HasPrefix(program.entry, "native_n64_0_callback_") || strings.HasPrefix(program.grant, "native_n46_") {
					t.Fatal("callback borrowed NAT46 policy namespace")
				}
				if index == 2 && program.chains[program.entry+"_rule_1"][0].text != "drop" {
					t.Fatal("owner callback bypassed earlier directory requirement")
				}
				for _, rules := range program.chains {
					for _, rule := range rules {
						if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") || strings.Contains(rule.text, `"nat46"`) {
							t.Fatal("callback policy gained authority or another translator", rule.text)
						}
					}
				}
			}
		}
	}
	before := model.mapped.rules.rules[1].Ports[0]
	baseline.NetworkModel.Rules[1].Ports[0]++
	if model.mapped.rules.rules[1].Ports[0] != before {
		t.Fatal("owner mutation changed original callback policy")
	}
}

func TestNAT64CallbackPolicyKeepsComponentCallerClassAndPools(t *testing.T) {
	t.Parallel()
	for _, global := range []bool{false, true} {
		baseline, callback, _ := callbackPolicyFixture(t)
		if global {
			baseline.NAT64[0].Prefix, baseline.NAT64[0].Scope = netip.MustParsePrefix("64:ff9b::/96"), "global"
			transport, err := newNativeNAT64Transport(t.Context(), baseline, "nat64-internal")
			if err != nil {
				t.Fatal(err)
			}
			callback, err = newNativeNAT64CallbackTransport(t.Context(), transport)
			if err != nil {
				t.Fatal(err)
			}
		}
		model, err := newNativeNAT64CallbackModel(t.Context(), baseline, callback)
		if err != nil {
			t.Fatal(err)
		}
		for _, reply := range []bool{false, true} {
			program, err := model.wirePolicy(t.Context(), 2, 0, nativePacketContext{iface: "lan10", family: 4, id: 17}, "tcp", reply, false)
			if err != nil {
				t.Fatal(err)
			}
			class := program.chains[program.entry+"_caller_class"]
			field := "saddr"
			if reply {
				field = "daddr"
			}
			if class[len(class)-1].text != "drop" || !strings.Contains(class[0].text, "ip6 "+field) ||
				!strings.Contains(strings.Join(nativeRulesText(class), "\n"), model.callerPrefix(field, *baseline.NAT64[0].SourcePool).text+" drop") {
				t.Fatal("callback caller class lost direction or chained-pool exclusion", class)
			}
			if global != (len(model.callerClass.Allowed) == 1) {
				t.Fatal("public and private caller classes merged")
			}
		}
	}
}

func TestNAT64CallbackPolicyRejectsDetachedChangedAndCancelledOrigins(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*policy.Baseline, *nativeNAT64CallbackTransport)
	}{
		{"changed owner rule", func(b *policy.Baseline, _ *nativeNAT64CallbackTransport) {
			b.NetworkModel.Rules[2].Ports = []uint16{443}
		}},
		{"changed baseline prefix", func(b *policy.Baseline, _ *nativeNAT64CallbackTransport) {
			b.NAT64[0].Prefix = netip.MustParsePrefix("fdca:1a2b:e065::/96")
		}},
		{"detached geometry", func(_ *policy.Baseline, c *nativeNAT64CallbackTransport) { c.native.geometry = nil }},
		{"changed retained proof", func(_ *policy.Baseline, c *nativeNAT64CallbackTransport) {
			c.proof.legs[0].mapping.alias = netip.MustParseAddr("10.251.0.99")
		}},
		{"detached callback", func(_ *policy.Baseline, c *nativeNAT64CallbackTransport) { c.native.callbacks = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseline, callback, _ := callbackPolicyFixture(t)
			test.change(&baseline, callback)
			if _, err := newNativeNAT64CallbackModel(t.Context(), baseline, callback); err == nil {
				t.Fatal("changed callback origin accepted")
			}
		})
	}
	baseline, callback, model := callbackPolicyFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newNativeNAT64CallbackModel(ctx, baseline, callback); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled callback construction continued", err)
	}
	if _, err := model.wirePolicy(ctx, 2, 0, nativePacketContext{iface: "lan10", id: 17}, "tcp", false, false); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled callback policy continued", err)
	}
}
