package firewall

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNativeCapacityDoesNotChargeUnreachableAttachmentsAndFamilies(t *testing.T) {
	t.Parallel()
	b := nativeAccessBaseline(t)
	for index := range 28 {
		b.Zones = append(b.Zones, policy.Zone{Role: policy.Role(fmt.Sprintf("segment%d", index)), VLAN: uint16(100 + index),
			Interfaces: []string{fmt.Sprintf("extra%d", index)}, Networks: sourceClassPrefixes(fmt.Sprintf("10.160.%d.0/24", index))})
	}
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: sourceClassPrefixes("10.243.0.1/32")})
	b.NetworkModel.UplinkNAT = []policy.UplinkNAT{{Interface: "lan13", Sources: sourceClassPrefixes("10.240.3.0/24"), Addresses: []netip.Addr{netip.MustParseAddr("10.243.0.1")}}}
	b.NetworkModel.Rules = []policy.NetworkRule{}
	for index := range 50 {
		b.NetworkModel.Rules = append(b.NetworkModel.Rules, policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{6061},
			From: []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes(fmt.Sprintf("10.240.3.%d/32", index+10))}},
			To:   []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.10/32")}}})
	}
	layout, err := newNativeAccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal("reachable program was rejected because of unused interfaces or families", err)
	}
	count := 0
	for _, contexts := range layout.native.contexts {
		count += len(contexts)
	}
	if count != 100 || layout.native.ruleCount(layout.interfaces) > nativeRuleCapacity {
		t.Fatal("unreachable contexts returned or the existing rule cap changed", count)
	}
	if _, err := layout.program(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The same source declarations cannot turn a cross-family raw rule into a
	// native permission or allocate packet contexts for it.
	rule := b.NetworkModel.Rules[0]
	rule.To[0].Addresses = sourceClassPrefixes("fdca:1a2b::10/128")
	if (nativeContextSource{family: 4}).relevant(rule, "lan13", "") ||
		(nativeContextSource{family: 6}).relevant(rule, "lan13", "") ||
		(nativeContextSource{}).relevant(rule, "lan13", "") {
		t.Fatal("unreachable cross-family pair acquired a native context")
	}
}
