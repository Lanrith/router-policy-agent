package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT46WireScopeRetainsPairedOriginalEndpoints(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"exact", "other source interface", "other source mac", "other source family", "other rule family", "other protocol", "unpaired native target", "unpaired alias target", "alias selector", "source subnet", "unbounded source"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := nativeNAT46ModelFixture(t)
			original := nativePacketContext{iface: "lan10", mac: "02:00:00:00:00:10", family: 4}
			expected := true
			switch name {
			case "other source interface":
				original.iface, expected = "lan13", false
			case "other source mac":
				original.mac, expected = "02:00:00:00:00:11", false
			case "other source family":
				original.family, expected = 6, false
			case "other rule family":
				b.NetworkModel.Rules[0].Family, expected = 6, false
			case "other protocol":
				b.NetworkModel.Rules[0].Protocol, expected = "udp", false
			case "unpaired native target":
				b.NetworkModel.Rules[0].To = []policy.NetworkSelector{
					{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:2::20/128")},
					{Interface: "lan12", Addresses: sourceClassPrefixes("fdca:1a2b:2::21/128")},
				}
				expected = false
			case "unpaired alias target":
				b.NetworkModel.Rules[0].To = []policy.NetworkSelector{{Interface: "nat46", Addresses: sourceClassPrefixes("fdca:1a2b:2::20/128")}}
				expected = false
			case "alias selector":
				for _, mapping := range b.NAT46 {
					if mapping.Target == netip.MustParseAddr("fdca:1a2b:2::20") {
						b.NetworkModel.Rules[0].To = []policy.NetworkSelector{{Interface: "nat46", Addresses: []netip.Prefix{netip.PrefixFrom(mapping.Alias, 32)}}}
					}
				}
			case "source subnet":
				b.NetworkModel.Rules[0].From[0].Addresses = sourceClassPrefixes("10.240.0.0/24")
			case "unbounded source":
				b.NetworkModel.Rules[0].From[0].Addresses = nil
			}
			model, err := newNativeNAT46Model(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			mappingIndex := -1
			for index, mapping := range model.mappings {
				if mapping.target == netip.MustParseAddr("fdca:1a2b:2::20") {
					mappingIndex = index
				}
			}
			for _, reply := range []bool{false, true} {
				for _, physical := range []bool{false, true} {
					scopes, err := model.wireScopes(t.Context(), 0, mappingIndex, original, "tcp", reply, physical)
					if err != nil || (len(scopes) == 1) != expected {
						t.Fatal("wire projection changed a paired endpoint", scopes, err)
					}
					if !expected {
						continue
					}
					text := scopes[0].text
					if !strings.Contains(text, "fdca:1a2b:2::20") || !strings.Contains(text, "6053") ||
						strings.Contains(text, "ether ") || strings.Contains(text, "accept") {
						t.Fatal("wire scope lost its target/listener or acquired authority", text)
					}
					if !physical && (!strings.Contains(text, "nat46") || !strings.Contains(text, "lan12")) {
						t.Fatal("wire scope lost its actual attachments", text)
					}
					for _, raw := range []string{"10.240.", "10.250."} {
						if strings.Contains(text, raw) {
							t.Fatal("wire projection retained an IPv4 field", text)
						}
					}
				}
			}
		})
	}
}

func TestNAT46WireEchoScopeDoesNotOpenOtherIPv6ControlTraffic(t *testing.T) {
	t.Parallel()
	b := nativeNAT46ModelFixture(t)
	b.NetworkModel.Rules[0].Protocol, b.NetworkModel.Rules[0].Ports = "icmp", nil
	model, err := newNativeNAT46Model(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	original := nativePacketContext{iface: "lan10", mac: "02:00:00:00:00:10", family: 4}
	for _, reply := range []bool{false, true} {
		scopes, err := model.wireScopes(t.Context(), 0, 0, original, "icmp", reply, false)
		if err != nil || len(scopes) != 1 || !strings.Contains(scopes[0].text, "icmpv6 type echo-") ||
			!strings.Contains(scopes[0].text, "icmpv6 code 0") || strings.Contains(scopes[0].text, "meta l4proto") {
			t.Fatal("echo projection became unrestricted ICMPv6", scopes, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := model.wireScopes(ctx, 0, 0, original, "icmp", false, false); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scope projection continued", err)
	}
}

func TestNAT46SourcePrefixPreservesEveryIPv4Bit(t *testing.T) {
	t.Parallel()
	translation := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	for _, test := range []struct{ original, embedded string }{
		{"0.0.0.0/0", "fdca:1a2b:e046::/96"},
		{"10.0.0.0/8", "fdca:1a2b:e046::a00:0/104"},
		{"10.240.128.0/17", "fdca:1a2b:e046::af0:8000/113"},
		{"10.240.0.10/32", "fdca:1a2b:e046::af0:a/128"},
	} {
		if actual := nativeNAT46SourcePrefix(translation, netip.MustParsePrefix(test.original)); actual.String() != test.embedded {
			t.Fatal("IPv4 source prefix changed during wire projection", actual, test.embedded)
		}
	}
}

func TestNAT46WirePolicyKeepsTerminalDirectoryAndOriginalRule(t *testing.T) {
	t.Parallel()
	b := nativeNAT46ModelFixture(t)
	deny, directory, owner := b.NetworkModel.Rules[0], b.NetworkModel.Rules[0], b.NetworkModel.Rules[0]
	deny.Action, deny.Authorization = "deny", "inherit"
	deny.From = []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.12/32")}}
	directory.Ports = []uint16{6062}
	owner.Authorization, owner.Ports = "owner", []uint16{6053, 6062}
	b.NetworkModel.Rules = []policy.NetworkRule{deny, directory, owner}
	model, err := newNativeNAT46Model(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	original := nativePacketContext{iface: "lan10", mac: "02:00:00:00:00:10", family: 4, id: 17}
	for _, originalRule := range []int{1, 2} {
		for _, reply := range []bool{false, true} {
			for _, physical := range []bool{false, true} {
				program, err := model.wirePolicy(t.Context(), originalRule, 0, original, "tcp", reply, physical)
				if err != nil {
					t.Fatal(err)
				}
				ordered := program.chains[program.entry+"_ordered"]
				if len(ordered) < 4 || !strings.Contains(ordered[0].text, "_rule_0") ||
					!strings.Contains(ordered[1].text, "_rule_1") || ordered[len(ordered)-1].text != "drop" {
					t.Fatal("ordered wire policy lost a preceding deny or directory rule")
				}
				for _, rules := range program.chains {
					for _, rule := range rules {
						if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") {
							t.Fatal("wire policy installed a forwarding verdict")
						}
					}
				}
				branch := program.chains[program.entry+"_rule_1"]
				if originalRule == 2 {
					if len(branch) != 1 || branch[0].text != "drop" {
						t.Fatal("an existing owner connection can fall through a matching directory requirement")
					}
				} else if len(branch) != 3 || !strings.Contains(branch[0].text, "jump "+program.grant) ||
					branch[2].text != "drop" {
					t.Fatal("directory decision can continue without a fresh grant")
				}
				if !physical && !strings.Contains(program.chains[program.entry][0].text, "ct mark & 0x3ff") {
					t.Fatal("wire policy lost its original connection rule")
				}
			}
		}
	}
}

func TestNAT46WirePolicyInheritanceAndEchoRemainBounded(t *testing.T) {
	t.Parallel()
	for _, authorization := range []string{"owner", "directory", "inherit"} {
		for _, protocol := range []string{"tcp", "icmp"} {
			b := nativeNAT46ModelFixture(t)
			b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[0].Role}
			b.NetworkModel.Rules[0].Authorization = authorization
			b.NetworkModel.Rules[0].Protocol = protocol
			if protocol == "icmp" {
				b.NetworkModel.Rules[0].Ports = nil
			}
			model, err := newNativeNAT46Model(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			original := nativePacketContext{iface: "lan10", mac: "02:00:00:00:00:10", family: 4}
			program, err := model.wirePolicy(t.Context(), 0, 0, original, protocol, false, false)
			if err != nil {
				t.Fatal(err)
			}
			branch := program.chains[program.entry+"_rule_0"]
			switch {
			case protocol == "icmp" && authorization != "owner":
				if len(branch) != 1 || branch[0].text != "drop" {
					t.Fatal("echo borrowed a TCP/UDP directory grant")
				}
			case authorization == "owner":
				if strings.Contains(strings.Join(nativeRulesText(branch), "\n"), program.grant) {
					t.Fatal("owner permission acquired a directory dependency")
				}
			default:
				if !strings.Contains(branch[0].text, "jump "+program.grant) {
					t.Fatal("managed network inheritance became an owner permission")
				}
			}
		}
	}
}

func TestNAT46WireGrantUsesOnlyOriginalDeviceNamespaceAndListener(t *testing.T) {
	t.Parallel()
	model, err := newNativeNAT46Model(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newNativeNAT46Transport(t.Context(), model)
	if err != nil {
		t.Fatal(err)
	}
	for _, leg := range transport.legs {
		rules := leg.wireSourceGrant()
		if leg.protocol == "icmp" {
			if len(rules) != 1 || rules[0].text != "drop" {
				t.Fatal("echo borrowed a directory listener")
			}
			continue
		}
		port := "dport"
		if leg.reply {
			port = "sport"
		}
		text := rules[0].text
		if len(rules) != 2 || rules[1].text != "drop" ||
			!strings.Contains(text, "native_id_lease_from4_"+leg.protocol) ||
			!strings.Contains(text, "meta priority . (meta mark & 0xe000) . "+leg.mapping.alias.String()+" . "+leg.protocol+" "+port) ||
			strings.Contains(text, "ct ") || strings.Contains(text, "accept") || strings.Contains(text, "0xf5") ||
			!strings.Contains(text, fmt.Sprintf("%#x", nativeDirectoryTag(leg.reply))) {
			t.Fatal("wire grant lost its source epoch, identity, namespace, alias or original listener", text)
		}
	}
}
