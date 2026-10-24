package policy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func sourceAliasFixture(t *testing.T) (Baseline, Input) {
	t.Helper()
	b, input := namedFixture(t)
	b.NAT46, b.NAT46Pools = nil, nil
	pool := netip.MustParsePrefix("10.252.0.0/24")
	b.NAT64[1].SourcePool = &pool
	b.NAT64[1].SourceMappings = []NAT64SourceMapping{{
		Source: netip.MustParseAddr("fdca:1a2b:2::10"), Alias: netip.MustParseAddr("10.252.0.84"), Ready: true,
	}}
	input.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("10.240.3.10")
	input.Bindings.Records[0].Addresses[0].Source = "kea_dhcp4"
	rule := testRule()
	rule.Direction = FromDevice
	rule.Peer.Addresses = []string{"fdca:1a2b:2::10/128"}
	group := accessGroup(t, "access", false, rule)
	raw := strings.ReplaceAll(*group.Policy, "untrusted", "devices")
	group.Policy = &raw
	input.Directory.Groups[1] = group
	b.NetworkModel.Rules = []NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6053},
		From: []NetworkSelector{{Interface: "lan13", Addresses: prefixes("10.240.3.0/24")}},
		To:   []NetworkSelector{{Interface: "lan12", Addresses: prefixes("fdca:1a2b:2::10/128")}}}}
	return b, input
}

func TestNAT64SourceAliasIsIndependentOfNAT46AndNeverGrantsAccess(t *testing.T) {
	t.Parallel()
	b, input := sourceAliasFixture(t)
	compiler := testCompiler(t, b)
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatalf("NAT64-only callback ceiling: %+v, %v", candidate, err)
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	peer := candidate.Grants[0].Peer
	if len(peer.Variants) != 2 || !slices.Contains(peer.Variants, netip.MustParseAddr("10.252.0.84")) ||
		!slices.Contains(peer.Variants, netip.MustParseAddr("fdca:1a2b:2::10")) {
		t.Fatal("NAT64 source identity lost its exact independent alias")
	}
	resolved, err := Resolve(b, netip.MustParseAddr("10.252.0.84"))
	if err != nil || resolved.Real != peer.Real || !slices.Equal(resolved.Variants, peer.Variants) {
		t.Fatal("alias decoding differs from its native counterpart", err)
	}
	b.NetworkModel.Rules = nil
	candidate, err = testCompiler(t, b).Compile(input)
	if err != nil || len(candidate.Grants) != 0 {
		t.Fatal("retained source allocation supplied permission", err)
	}
}

func TestNAT64SourceAliasesRejectUnknownUnreadyAndChainedRepresentations(t *testing.T) {
	t.Parallel()
	b, _ := sourceAliasFixture(t)
	for _, raw := range []string{"10.252.0.85", "10.252.0.1", "fdca:1a2b:64::afc:54"} {
		if _, err := Resolve(b, netip.MustParseAddr(raw)); err == nil {
			t.Fatal("unmapped or chained source alias accepted", raw)
		}
	}
	b.NAT64[1].SourceMappings[0].Ready = false
	if _, err := Resolve(b, netip.MustParseAddr("10.252.0.84")); err == nil {
		t.Fatal("unready source alias became a native peer")
	}
	endpoint, err := Resolve(b, netip.MustParseAddr("fdca:1a2b:2::10"))
	if err != nil || len(endpoint.Variants) != 1 {
		t.Fatal("unready source mapping created an available alias", err)
	}
}

func TestNAT64SourceMappingValidationAndAliasAnchors(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*Baseline){
		func(b *Baseline) { b.NAT64[1].SourcePool = nil },
		func(b *Baseline) { b.NetworkModel = nil },
		func(b *Baseline) {
			b.NAT64[1].SourceMappings = append(b.NAT64[1].SourceMappings, b.NAT64[1].SourceMappings[0])
		},
		func(b *Baseline) { pool := netip.MustParsePrefix("10.240.3.0/24"); b.NAT64[1].SourcePool = &pool },
		func(b *Baseline) { b.NAT46Pools = prefixes("10.252.0.0/24") },
		func(b *Baseline) { b.NAT64[1].SourceMappings[0].Alias = netip.MustParseAddr("10.252.0.1") },
		func(b *Baseline) { b.NAT64[1].SourceMappings[0].Alias = netip.MustParseAddr("10.252.0.255") },
		func(b *Baseline) { b.NAT64[1].SourceMappings[0].Source = netip.MustParseAddr("fdca:1a2b:64::af0:30a") },
	} {
		b, _ := sourceAliasFixture(t)
		mutate(&b)
		if _, err := New(b); err == nil {
			t.Fatal("invalid NAT64 source mapping accepted")
		}
	}
	b, input := sourceAliasFixture(t)
	raw := strings.ReplaceAll(*input.Directory.Groups[1].Policy, "fdca:1a2b:2::10/128", "10.252.0.84/32")
	input.Directory.Groups[1].Policy = &raw
	// This root directory ceiling intentionally permits either exact peer.
	b.NetworkModel.Rules[0].To[0].Addresses = prefixes("fdca:1a2b:2::/64")
	candidate, err := testCompiler(t, b).Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatalf("initial source alias anchor: %+v, %v", candidate, err)
	}
	input.Ledger = candidate.Ledger
	b.NAT64[1].SourceMappings[0].Source = netip.MustParseAddr("fdca:1a2b:2::11")
	candidate, err = testCompiler(t, b).Compile(input)
	if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 || candidate.Denials[0].Code != "unready_or_changed_alias" {
		t.Fatal("retargeting a source alias transferred a directory capability", err)
	}
}
