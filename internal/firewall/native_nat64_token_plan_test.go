package firewall

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

type nat64TokenPlanFixture struct {
	baseline      policy.Baseline
	transport     *nativeNAT64Transport
	access        *nativeAccess
	ledger        *policy.NAT64AllocationLedger
	configuration policy.OwnerConfiguration
	sources       *nativeSourcePublication
}

func newNAT64TokenPlanFixture(t *testing.T, withSources bool) nat64TokenPlanFixture {
	t.Helper()
	b := nat64TransportFixture(t)
	b.NetworkModel.Rules = []policy.NetworkRule{{
		Action: "allow", Authorization: "inherit", Protocol: "any",
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b::/64")}}},
		To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}},
	}}
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}}
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := transport.geometry.Capture(t.Context(), transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newNativeAccessGeometry(t.Context(), b, rules, []string{transport.component})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	fixture := nat64TokenPlanFixture{baseline: b, transport: transport, access: layout.native, ledger: ledger, configuration: configuration}
	if !withSources {
		return fixture
	}
	now := time.Now().Round(0).UTC()
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "nat64-token-source", ObservedAt: now, Complete: true,
		Records: []binding.Record{{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10,
			AssociatedAt: now, AssociationID: "nat64-association", Addresses: []binding.Address{{IP: netip.MustParseAddr("fdca:1a2b::10"),
				Source: "qualified_ipv6", OwnershipID: "nat64-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}}
	evidence, err := compiler.CompileOwnership(t.Context(), snapshot, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = evidence.InEpoch(t.Context(), 9)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sources, err = nativeSourceReceipt(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestNAT64TokensAreDerivedFromCompilerOwnedConfigurationAndSources(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, true)
	tokens, err := deriveNativeNAT64Tokens(t.Context(), fixture.transport, fixture.access, fixture.ledger, fixture.configuration, fixture.sources, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens.entries) != 6 {
		t.Fatal("NAT64 registry omitted a compiler-valid owner, configuration, or directory state", len(tokens.entries))
	}
	kinds := []uint32{}
	for _, entry := range tokens.entries {
		kinds = append(kinds, entry.context&0xff000000)
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []uint32{0xd1000000, 0xd2000000, 0xd3000000, 0xd4000000, 0xd5000000, 0xd6000000}) {
		t.Fatal("NAT64 registry changed its independently checked authorization classes", kinds)
	}
	data, err := tokens.publicationData(t.Context())
	if err != nil || !bytes.Equal(data, mustNAT64TokenData(t, tokens)) {
		t.Fatal("compiler-derived NAT64 registry did not reproduce its fixed publication", err)
	}
	configurationOnly := newNAT64TokenPlanFixture(t, false)
	staticTokens, err := deriveNativeNAT64Tokens(t.Context(), configurationOnly.transport, configurationOnly.access, configurationOnly.ledger, configurationOnly.configuration, nil, time.Now().UTC())
	if err != nil || len(staticTokens.entries) != 2 {
		t.Fatal("configuration-only NAT64 registry acquired dynamic identity or lost static state", len(staticTokens.entries), err)
	}
	for _, entry := range staticTokens.entries {
		if kind := entry.context & 0xff000000; kind != 0xd3000000 && kind != 0xd4000000 {
			t.Fatal("configuration-only NAT64 registry acquired an ownership or directory class", kind)
		}
	}
}

func TestNAT64TokenDerivationRepresentsNoPermitAsTypedRevocation(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	b.NetworkModel.Rules = []policy.NetworkRule{{
		Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{443},
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b::/64")}}},
		To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}},
	}}
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}}
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := transport.geometry.Capture(t.Context(), transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newNativeAccessGeometry(t.Context(), b, rules, []string{transport.component})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := deriveNativeNAT64Tokens(t.Context(), transport, layout.native, ledger, configuration, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !tokens.clear || len(tokens.entries) != 0 || tokens.origin != nil {
		t.Fatal("directory-only NAT64 without a current source was not represented as an explicit token revocation")
	}
	data, err := tokens.publicationData(t.Context())
	if err != nil || bytes.Contains(data, []byte(`"add"`)) {
		t.Fatal("zero-permit NAT64 token plan was not a valid clear-only publication", err)
	}
}

func TestNAT64TokenDerivationDoesNotActivateReservedMapping(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, true)
	fixture.transport.mappings[0].Ready = false
	tokens, err := deriveNativeNAT64Tokens(t.Context(), fixture.transport, fixture.access, fixture.ledger,
		fixture.configuration, fixture.sources, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !tokens.clear || len(tokens.entries) != 0 || tokens.origin != nil {
		t.Fatal("reserved inactive NAT64 allocation acquired a configuration, owner, or directory token")
	}
	data, err := tokens.publicationData(t.Context())
	if err != nil || bytes.Contains(data, []byte(`"add"`)) {
		t.Fatal("inactive NAT64 allocation was not represented as an explicit token revocation", err)
	}
}

func TestNAT64TokenDerivationAcceptsLiveAllocatorMappingOutsideRetainedList(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, true)
	fixture.transport.mappings[0].Ready = false
	records := append(slices.Clone(fixture.transport.mappings), policy.NAT64SourceMapping{
		Source: netip.MustParseAddr("fdca:1a2b::11"), Alias: netip.MustParseAddr("10.251.0.11"),
	})
	ledger, err := fixture.transport.geometry.Capture(t.Context(), fixture.transport.component, nil, records)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := deriveNativeNAT64Tokens(t.Context(), fixture.transport, fixture.access, ledger,
		fixture.configuration, fixture.sources, time.Now().UTC())
	if err != nil || tokens.clear || len(tokens.entries) == 0 {
		t.Fatal("verified allocator-created mapping did not receive its separately authorized token", err)
	}
}

func TestNAT64TokenPublicationRejectsCallerStatesAndChangedOrigins(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, true)
	tokens, err := deriveNativeNAT64Tokens(t.Context(), fixture.transport, fixture.access, fixture.ledger, fixture.configuration, fixture.sources, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := newNativeNAT64Tokens(t.Context(), fixture.transport, []nativeNAT64TokenState{{epoch: 0x1c00, context: 0xd3000000, channel: 0x1c00}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.publicationData(t.Context()); err == nil {
		t.Fatal("caller-enumerated NAT64 metadata reached the privileged publication boundary")
	}
	changed := *tokens
	changed.entries = slices.Clone(tokens.entries)
	changed.entries[0].channel++
	if _, err := changed.publicationData(t.Context()); err == nil {
		t.Fatal("changed NAT64 metadata retained its compiler origin")
	}
	changed = *tokens
	changed.origin = &nativeNAT64TokenOrigin{transport: fixture.transport, access: fixture.access, ledger: fixture.ledger}
	if _, err := changed.publicationData(t.Context()); err == nil {
		t.Fatal("incomplete NAT64 origin regenerated positive rows")
	}
	tokenClear, err := prepareNativeNAT64TokenClear(t.Context(), fixture.transport)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := tokenClear.publicationData(t.Context()); err != nil || bytes.Contains(data, []byte(`"add"`)) {
		t.Fatal("typed NAT64 revocation failed its fixed publication boundary", err)
	}
}

func TestNAT64TokenDerivationRejectsDetachedOrExpiredDependencies(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, true)
	other := newNAT64TokenPlanFixture(t, false)
	changedAccess := *fixture.access
	changedAccess.baselineHash = "different-baseline"
	changedBaseline := fixture.baseline
	changedBaseline.Generation = "different-baseline"
	changedCompiler, err := policy.New(changedBaseline)
	if err != nil {
		t.Fatal(err)
	}
	changedConfiguration, err := changedCompiler.CompileOwnerConfiguration(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		transport     *nativeNAT64Transport
		access        *nativeAccess
		ledger        *policy.NAT64AllocationLedger
		configuration policy.OwnerConfiguration
		sources       *nativeSourcePublication
		utc           time.Time
	}{
		{"different access", fixture.transport, &changedAccess, fixture.ledger, fixture.configuration, fixture.sources, time.Now().UTC()},
		{"different ledger", fixture.transport, fixture.access, other.ledger, fixture.configuration, fixture.sources, time.Now().UTC()},
		{"different configuration", fixture.transport, fixture.access, fixture.ledger, changedConfiguration, fixture.sources, time.Now().UTC()},
		{"local time", fixture.transport, fixture.access, fixture.ledger, fixture.configuration, fixture.sources, time.Now()},
		{"expired source", fixture.transport, fixture.access, fixture.ledger, fixture.configuration, fixture.sources, time.Now().UTC().Add(2 * time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := deriveNativeNAT64Tokens(t.Context(), test.transport, test.access, test.ledger, test.configuration, test.sources, test.utc); err == nil {
				t.Fatal("detached or expired NAT64 token dependency accepted")
			}
		})
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := deriveNativeNAT64Tokens(cancelled, fixture.transport, fixture.access, fixture.ledger, fixture.configuration, fixture.sources, time.Now().UTC()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled NAT64 token derivation continued", err)
	}
}
