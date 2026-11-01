package firewall

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT64TargetLookupPreservesCompleteRuleAndDirection(t *testing.T) {
	t.Parallel()
	transport := &nativeNAT64Transport{name: "n64_width", ruleCount: 1024}
	tokens := &nativeNAT64Tokens{transport: transport}
	for rule := uint32(0); rule < 2048; rule++ {
		tokens.targets = append(tokens.targets, nativeNAT64TargetEntry{
			nativeNAT64TargetBinding: nativeNAT64TargetBinding{rule: rule, context: 1, iface: "lan13", peer: netip.MustParseAddr("10.240.3.10")},
			token:                    rule + 1,
		})
	}
	rows, err := tokens.targetElements(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		var pair []json.RawMessage
		if err := json.Unmarshal(row, &pair); err != nil || len(pair) != 2 {
			t.Fatal("invalid target lookup row", err)
		}
		key := string(pair[0])
		if seen[key] {
			t.Fatal("distinct ordered rules or directions share a target lookup key", key)
		}
		seen[key] = true
	}
	if len(seen) != 2048 {
		t.Fatal("target lookup lost part of the admitted rule space", len(seen))
	}
	for _, test := range []struct {
		index int
		reply bool
		key   string
	}{{0, false, "none"}, {512, false, "0:400"}, {1023, true, "0:7ff"}} {
		access := &nativeAccess{inet: map[string][]nativeScope{}}
		chain := access.compileNAT64TargetDecision(transport, test.index, "owner", test.reply)
		if !strings.HasSuffix(access.inet[chain][0].text, "set "+test.key) {
			t.Fatal("wire lookup truncated the ordered rule/direction key", access.inet[chain][0].text)
		}
	}
}

func newNAT64TargetTokenFixture(t *testing.T, configurationEpoch, ownershipEpoch uint32, authorization string, scope ...string) nat64TokenPlanFixture {
	t.Helper()
	b := nat64TransportFixture(t)
	if len(scope) != 0 {
		b.NAT64[0].Scope = scope[0]
	}
	b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[1].Role}
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: authorization, Protocol: "tcp", Ports: []uint16{443},
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64"), MAC: "02:00:00:00:00:10"}},
		To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.0/24")}}}}
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}}
	layout, err := newNativeNAT64AccessLayout(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	transport := layout.native.nat64Transport
	ledger, err := transport.geometry.Capture(t.Context(), transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(t.Context(), configurationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Round(0).UTC()
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "nat64-target", ObservedAt: now, Complete: true, Records: []binding.Record{{MAC: "02:00:00:00:00:13", NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: "target-association", Addresses: []binding.Address{{IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "target-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}}
	evidence, err := compiler.CompileOwnership(t.Context(), snapshot, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = evidence.InEpoch(t.Context(), ownershipEpoch)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := renderer.prepareNativeOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := nativeSourceReceipt(t.Context(), owned)
	if err != nil {
		t.Fatal(err)
	}
	return nat64TokenPlanFixture{baseline: b, transport: transport, access: layout.native, ledger: ledger, configuration: configuration, sources: sources}
}

func TestNAT64GlobalComponentCannotMintPrivateTargetAuthority(t *testing.T) {
	t.Parallel()
	f := newNAT64TargetTokenFixture(t, 7, 9, "owner", "global")
	tokens, err := deriveNativeNAT64Tokens(t.Context(), f.transport, f.access, f.ledger, f.configuration, f.sources, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens.targets) != 0 {
		t.Fatal("global translator minted authority for a private target")
	}
}

func TestNAT64TargetTokensBindIndependentAuthorityAndRejectRetargeting(t *testing.T) {
	t.Parallel()
	for _, authorization := range []string{"owner", "directory", "inherit"} {
		t.Run(authorization, func(t *testing.T) {
			t.Parallel()
			f := newNAT64TargetTokenFixture(t, 7, 9, authorization)
			tokens, err := deriveNativeNAT64Tokens(t.Context(), f.transport, f.access, f.ledger, f.configuration, f.sources, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if len(tokens.targets) != 2 {
				t.Fatal("target direction or canonical context was lost", len(tokens.targets))
			}
			for _, entry := range tokens.targets {
				if entry.state.originMarker() != 7<<policy.OwnershipRuleBits || entry.state.epoch != 9<<policy.OwnershipRuleBits || entry.state.channel != 9<<policy.OwnershipRuleBits|1 || entry.peer != netip.MustParseAddr("10.240.3.10") || entry.iface != "lan13" {
					t.Fatal("target borrowed configuration authority or lost its exact owned address")
				}
				directory := authorization != "owner"
				if uint64(entry.state.context&0xff000000) != nativeNAT64TargetTag(directory, entry.rule%2 != 0) {
					t.Fatal("target changed the winning rule's authorization")
				}
			}
			if _, err := tokens.publicationData(t.Context()); err != nil {
				t.Fatal("compiler-derived target registry rejected", err)
			}
			original := tokens.targets[0]
			tokens.targets[0].peer = netip.MustParseAddr("10.240.3.11")
			if _, err := tokens.publicationData(t.Context()); err == nil {
				t.Fatal("caller retargeted a positive target lookup")
			}
			tokens.targets[0] = original
			tokens.targets[0].state.origin = 8 << policy.OwnershipRuleBits
			if _, err := tokens.publicationData(t.Context()); err == nil {
				t.Fatal("caller substituted the physical configuration origin")
			}
		})
	}
}

func TestNAT64TargetTokensRequireFreshOwnershipAfterConfiguration(t *testing.T) {
	t.Parallel()
	for _, epoch := range []uint32{6, 7} {
		f := newNAT64TargetTokenFixture(t, 7, epoch, "owner")
		if _, err := deriveNativeNAT64Tokens(t.Context(), f.transport, f.access, f.ledger, f.configuration, f.sources, time.Now().UTC()); err == nil {
			t.Fatal("target accepted a preceding or equal ownership epoch", epoch)
		}
	}
	f := newNAT64TargetTokenFixture(t, 7, 9, "owner")
	f.sources.startedAt = time.Now().Add(-2 * time.Minute)
	if _, err := deriveNativeNAT64Tokens(t.Context(), f.transport, f.access, f.ledger, f.configuration, f.sources, time.Now().UTC()); err == nil {
		t.Fatal("target ownership deadline was renewed by token preparation")
	}
}
