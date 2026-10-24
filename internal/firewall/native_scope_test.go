package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeScopeBaseline(t *testing.T) policy.Baseline {
	t.Helper()
	baseline := namedOwnershipBaseline(t)
	baseline.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{6053},
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{
			netip.MustParsePrefix("10.240.0.10/32"), netip.MustParsePrefix("fdca:1a2b::10/128")}, MAC: "02:00:00:00:00:10"}},
		To: []policy.NetworkSelector{{Interface: "lan13", Addresses: []netip.Prefix{
			netip.MustParsePrefix("10.240.3.10/32"), netip.MustParsePrefix("fdca:1a2b:3::10/128")}}}}}
	return baseline
}

func TestNativePredicatesOwnTheValidatedRootModel(t *testing.T) {
	t.Parallel()
	baseline := nativeScopeBaseline(t)
	set, err := newNativeRuleSet(baseline)
	if err != nil {
		t.Fatal(err)
	}
	before, err := set.scopes(t.Context(), 0, false, false)
	if err != nil || len(before) != 2 {
		t.Fatal("dual-stack positive control did not compile", err)
	}
	baseline.NetworkModel.Rules[0].Ports[0] = 80
	baseline.NetworkModel.Rules[0].From[0].MAC = "02:00:00:00:00:ff"
	baseline.NetworkModel.Rules[0].From[0].Addresses[0] = netip.MustParsePrefix("0.0.0.0/0")
	after, err := set.scopes(t.Context(), 0, false, false)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("caller mutation changed owned predicates", err)
	}
}

func TestNativePredicatesRejectUnvalidatedFragments(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*policy.Baseline)
	}{
		{"missing named model", func(b *policy.Baseline) { b.NetworkModel = nil }},
		{"unknown interface", func(b *policy.Baseline) { b.NetworkModel.Rules[0].From[0].Interface = "outside" }},
		{"injected protocol", func(b *policy.Baseline) { b.NetworkModel.Rules[0].Protocol = "tcp accept" }},
		{"injected MAC", func(b *policy.Baseline) { b.NetworkModel.Rules[0].From[0].MAC += " accept" }},
		{"invalid prefix", func(b *policy.Baseline) { b.NetworkModel.Rules[0].To[0].Addresses[0] = netip.Prefix{} }},
		{"duplicate ports", func(b *policy.Baseline) { b.NetworkModel.Rules[0].Ports = []uint16{6053, 6053} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := nativeScopeBaseline(t)
			test.change(&baseline)
			if _, err := newNativeRuleSet(baseline); err == nil {
				t.Fatal("unsafe predicate fragment accepted")
			}
		})
	}
}

func TestNativePredicatesBoundExpansionAndHonorCancellation(t *testing.T) {
	t.Parallel()
	baseline := nativeScopeBaseline(t)
	baseline.NetworkModel.Rules[0].From[0].Addresses = nil
	baseline.NetworkModel.Rules[0].To[0].Addresses = nil
	for index := 1; index <= 32; index++ {
		baseline.NetworkModel.Rules[0].From[0].Addresses = append(baseline.NetworkModel.Rules[0].From[0].Addresses,
			netip.MustParsePrefix(fmt.Sprintf("10.240.0.%d/32", index)))
		baseline.NetworkModel.Rules[0].To[0].Addresses = append(baseline.NetworkModel.Rules[0].To[0].Addresses,
			netip.MustParsePrefix(fmt.Sprintf("10.240.3.%d/32", index)))
	}
	baseline.NetworkModel.Rules[0].Ports = nil
	for port := uint16(1); port <= 64; port++ {
		baseline.NetworkModel.Rules[0].Ports = append(baseline.NetworkModel.Rules[0].Ports, port)
	}
	set, err := newNativeRuleSet(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if scopes, err := set.scopes(t.Context(), 0, false, false); err == nil || scopes != nil {
		t.Fatal("oversized predicate product was truncated or rendered")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := set.scopes(ctx, 0, false, false); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled predicate generation continued", err)
	}
	for _, index := range []int{-1, 1} {
		if _, err := set.scopes(t.Context(), index, false, false); err == nil {
			t.Fatal("invalid rule index accepted")
		}
	}
}

func TestNativePhysicalScopeKeepsIncomingAddressAndInterfaceTogether(t *testing.T) {
	t.Parallel()
	b := nativeAccessBaseline(t)
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{6053}, From: []policy.NetworkSelector{
		{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.0.10/32"), netip.MustParsePrefix("fdca:1a2b::10/128")}},
		{Interface: "lan13", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.0.20/32"), netip.MustParsePrefix("fdca:1a2b::20/128")}},
	}, To: []policy.NetworkSelector{{Interface: "lan13", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.3.10/32"), netip.MustParsePrefix("fdca:1a2b:3::10/128")}}}}}
	set, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := set.physicalScopes(t.Context(), 0, nativePacketContext{iface: "lan10"}, false, false)
	if err != nil || len(scopes) != 2 {
		t.Fatal("physical source pairing lost its positive controls", err, len(scopes))
	}
	for _, scope := range scopes {
		if strings.Contains(scope.text, "0.20") || strings.Contains(scope.text, "::20") {
			t.Fatal("physical source borrowed another interface's address")
		}
	}
	reversed, err := set.physicalScopes(t.Context(), 0, nativePacketContext{iface: "lan10"}, true, false)
	if err != nil || len(reversed) != 0 {
		t.Fatal("reply context borrowed a different incoming attachment", err)
	}
}
