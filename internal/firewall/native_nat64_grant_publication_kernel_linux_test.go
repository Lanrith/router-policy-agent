//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// The dummy links qualify actual backend transactions and independent profile
// inspection. Separate joined fixtures qualify packets through real TAYGA.
func TestKernelNamedNAT64DynamicGrantPublicationFences(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	b := nat64TransportFixture(t)
	b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[0].Role}
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6061},
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
		To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}}}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	profileData, err := json.Marshal(profileEnvelope{SchemaVersion: 1, Baseline: raw, ReviewedRuleset: json.RawMessage(reviewedArtifactFixture)})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := decodePinnedProfile(ctx, profileData, routerProfileDigest(profileData))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newNativeNAT64AccessLayout(ctx, b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	profile.layout = layout
	for _, name := range layout.interfaces {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program)+reviewedKernelFixture)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet reviewed_floor; delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	executor, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := executor.close(); err != nil {
			t.Error(err)
		}
	})
	gate, root, _ := generationGateFixture(t)
	expected := writerGenerationFixture()
	expected.FloorHash = profile.ruleset.digest
	writeGenerationFixture(t, root, expected)
	backend, err := newGuardedBackend(backendOptions{profile: profile, executor: executor, generation: gate, expected: expected, clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Round(0).UTC()
	bindings := binding.Snapshot{SchemaVersion: 1, Generation: "dynamic-nat64-owner", ObservedAt: now, Complete: true,
		Records: []binding.Record{{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10, AssociatedAt: now, AssociationID: "dynamic-nat64-association",
			Addresses: []binding.Address{{IP: netip.MustParseAddr("fdca:1a2b::10"), Source: "qualified_ipv6", OwnershipID: "dynamic-nat64-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}}
	ownership, err := profile.renderer.compiler.CompileOwnership(ctx, bindings, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	ownership, err = ownership.InEpoch(ctx, 19)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := profile.renderer.compiler.CompileOwnerConfiguration(ctx, 17)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.refreshConfiguration(ctx, configuration); err != nil {
		t.Fatal(err)
	}
	if err := backend.refreshOwnership(ctx, ownership); err != nil {
		t.Fatal(err)
	}
	transport := layout.native.nat64Transport
	ledger, err := transport.geometry.Capture(ctx, transport.component, nil, []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10")}})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof := &testNAT64Readiness{transport: transport, entries: entries, ready: true}
	if err := backend.activateNAT64(ctx, ledger, proof, configuration); err != nil {
		t.Fatal(err)
	}
	placement, err := json.Marshal(map[string]any{"schema_version": 1, "kind": "placement", "vlan_role": b.Zones[0].Role})
	if err != nil {
		t.Fatal(err)
	}
	access, err := json.Marshal(map[string]any{"schema_version": 1, "kind": "access", "vlan_role": b.Zones[0].Role, "temporary": false,
		"rules": []policy.Rule{{ID: "listener", Direction: policy.FromDevice, Peer: policy.Peer{Addresses: []string{"fdca:1a2b:e064::af0:30a/128"}}, Protocol: "tcp", DestinationPorts: []uint16{6061}, Reason: "Synthetic dynamic NAT64 listener"}}})
	if err != nil {
		t.Fatal(err)
	}
	placementText, accessText := string(placement), string(access)
	directory := policy.DirectorySnapshot{ObservedAt: now, Complete: true,
		Groups:  []policy.Group{{ID: "placement", Name: "Synthetic placement", IsNetwork: true, Policy: &placementText}, {ID: "listener", Name: "Synthetic listener", IsNetwork: true, Policy: &accessText}},
		Devices: []policy.Device{{ID: "dynamic-source", MAC: "02:00:00:00:00:10", Active: true, GroupIDs: []string{"placement", "listener"}}}}
	authorization, err := profile.renderer.compiler.CompileAuthorization(ctx, policy.Input{Directory: directory, Bindings: bindings, Now: time.Now().UTC()}, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(ctx)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("dynamic backend fixture lost its compiled grant", err, candidate.Denials)
	}
	history := state.Classification{MACs: []string{"02:00:00:00:00:10"}, IPv4: []string{}, IPv6: []string{"fdca:1a2b::10"}}
	assertGrants := func(present bool) {
		t.Helper()
		if _, err := profile.inspect(ctx, executor); err != nil {
			t.Fatal("independent dynamic backend inspection failed", err)
		}
		for _, family := range []string{"inet", "netdev"} {
			for _, name := range []string{"native_n64_from4_tcp", "native_n64_from6_tcp"} {
				listed := string(kernelFixtureCommand(ctx, t, "list", "set", family, ownedTable, name))
				if strings.Contains(listed, `"elem"`) != present {
					t.Fatal("dynamic grant mirror differs", family, name, present)
				}
			}
		}
	}
	if err := backend.apply(ctx, authorization, history); err != nil {
		t.Fatal("dynamic original backend grant failed", err)
	}
	assertGrants(true)
	queued, source, err := backend.prepareApplication(ctx, authorization, history)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued.nat64GrantOrigins) != 1 {
		t.Fatal("backend did not retain its original runtime activation")
	}
	if err := backend.activateNAT64(ctx, ledger, proof, configuration); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.commitApplication(ctx, queued, source); err == nil || !strings.Contains(err.Error(), "activation changed") {
		t.Fatal("queued grant adopted a replacement runtime activation", err)
	}
	if err := backend.apply(ctx, authorization, history); err != nil {
		t.Fatal(err)
	}
	assertGrants(true)
	proof.ready = false
	if err := backend.apply(ctx, authorization, history); err == nil {
		t.Fatal("stopped translator admitted a grant")
	}
	assertGrants(false)
	// Revocation never needs a fresh positive readiness proof.
	if err := backend.seal(ctx, history); err != nil {
		t.Fatal("lost translator readiness blocked revocation", err)
	}
	assertGrants(false)
}
