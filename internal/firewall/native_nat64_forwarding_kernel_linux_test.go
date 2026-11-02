//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// This joins compiler-owned first-match policy, live allocation publication,
// exact tuple correlation and a real TAYGA process. Configuration and dynamic
// source ownership are separate modes so each can be revoked independently.
func TestKernelNamedNAT64JoinedTAYGAConfiguration(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "configuration", false, false)
}

func TestKernelNamedNAT64JoinedTAYGAOwner(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "owner", false, false)
}

func TestKernelNamedNAT64JoinedTAYGADirectory(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "directory", false, false)
}

func TestKernelNamedNAT64JoinedFinalInterfaceDenial(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "configuration", true, false)
}

func TestKernelNamedNAT64JoinedDistinctFinalRules(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "configuration", true, true)
}

func TestKernelNamedNAT64JoinedOwnerDirectoryPaths(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "split", true, true)
}

func TestKernelNamedNAT64JoinedTargetOwner(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "target", true, true)
}

func TestKernelNamedNAT64JoinedTargetDirectory(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "target_directory", true, true)
}

func TestKernelNamedNAT64JoinedRecipientGrant(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "recipient", true, true)
}

func TestKernelNamedNAT64JoinedRecipientGrantWithCallerHistory(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "recipient_cohort", true, true)
}

func TestKernelNamedNAT64JoinedSourceGrantToOwnedTarget(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "paired_directory", true, true)
}

func TestKernelNamedNAT64JoinedOwnedTargetExpiry(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "paired_directory_expiry", true, true)
}

func TestKernelNamedNAT64JoinedOwnedCallerAndTarget(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "paired_owner", true, true)
}

func TestKernelNamedNAT64JoinedDynamicSourceGrant(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "dynamic_directory", false, false)
}

func TestKernelNamedNAT64JoinedDynamicTargetGrant(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "dynamic_target_directory", true, true)
}

func TestKernelNamedNAT64JoinedDynamicRecipientGrant(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "dynamic_recipient", true, true)
}

func TestKernelNamedNAT64JoinedDynamicRecipientWithCallerHistory(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "dynamic_recipient_cohort", true, true)
}

func TestKernelNamedNAT64JoinedDynamicSourceGrantToOwnedTarget(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "dynamic_paired_directory", true, true)
}

func testKernelNamedNAT64JoinedTAYGA(t *testing.T, authorization string, finalInterface, separateRules bool) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	dynamic := strings.HasPrefix(authorization, "dynamic_")
	authorization = strings.TrimPrefix(authorization, "dynamic_")
	recipient := authorization == "recipient" || authorization == "recipient_cohort"
	pairedOwner := authorization == "paired_owner"
	targetExpiry := authorization == "paired_directory_expiry"
	pairedDirectory := authorization == "paired_directory" || targetExpiry
	if authorization != "configuration" && authorization != "owner" && authorization != "directory" && authorization != "split" && authorization != "target" && authorization != "target_directory" && !recipient && !pairedOwner && !pairedDirectory {
		t.Fatal("unknown NAT64 fixture authorization", authorization)
	}
	targetOwned := authorization == "target" || authorization == "target_directory" || recipient || pairedOwner || pairedDirectory
	sourceOwned := authorization != "configuration" && (!targetOwned || recipient || pairedOwner || pairedDirectory)
	directory := authorization == "directory" || authorization == "split" || authorization == "target_directory" || recipient || pairedDirectory
	portBase := uint16(48000)
	if finalInterface {
		// These tests share one disposable netns. Link/table cleanup does not
		// erase conntrack, so retain distinct tuples for the additional graph.
		portBase = 44000
	}
	if separateRules {
		portBase = 42000
	}
	switch authorization {
	case "owner":
		portBase = 52000
	case "directory":
		portBase = 56000
	case "split":
		portBase = 40000
	case "target":
		portBase = 38000
	case "target_directory":
		portBase = 36000
	case "recipient":
		portBase = 34000
	case "recipient_cohort":
		portBase = 32000
	case "paired_owner":
		portBase = 30000
	case "paired_directory":
		portBase = 28000
	case "paired_directory_expiry":
		portBase = 26000
	}
	if dynamic {
		switch authorization {
		case "directory":
			portBase = 24000
		case "target_directory":
			portBase = 22000
		case "recipient":
			portBase = 20000
		case "recipient_cohort":
			portBase = 18000
		case "paired_directory":
			portBase = 16000
		default:
			t.Fatal("unsupported dynamic grant fixture", authorization)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	links := []struct {
		router, endpoint, routerMAC, endpointMAC, address string
	}{
		{"lan10", "peer0", "02:00:00:00:01:10", "02:00:00:00:00:10", "fdca:1a2b::1/64"},
		{"lan11", "wrongpeer", "02:00:00:00:01:11", "02:00:00:00:00:11", "fdca:1a2b:1::1/64"},
		{"wan", "wanpeer", "02:00:00:00:01:13", "02:00:00:00:00:13", "10.240.3.1/24"},
	}
	if finalInterface {
		links = append(links, struct{ router, endpoint, routerMAC, endpointMAC, address string }{
			"lan13", "lanpeer", "02:00:00:00:01:14", "02:00:00:00:00:14", "10.240.4.1/24"})
	}
	for _, link := range links {
		packetIP(ctx, t, "link", "add", link.router, "type", "veth", "peer", "name", link.endpoint)
		selected := link.router
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", selected)
		})
		packetIP(ctx, t, "link", "set", link.router, "address", link.routerMAC)
		packetIP(ctx, t, "link", "set", link.endpoint, "address", link.endpointMAC)
		if link.router != "wan" && link.router != "lan13" {
			packetIP(ctx, t, "-6", "address", "add", link.address, "dev", link.router, "nodad")
		} else {
			packetIP(ctx, t, "address", "add", link.address, "dev", link.router)
		}
		packetIP(ctx, t, "link", "set", link.router, "up")
		packetIP(ctx, t, "link", "set", link.endpoint, "up")
	}
	packetIP(ctx, t, "neighbor", "add", "fdca:1a2b::10", "lladdr", "02:00:00:00:00:10", "dev", "lan10", "nud", "permanent")
	for _, target := range []string{"10.240.3.10", "10.240.3.11"} {
		packetIP(ctx, t, "neighbor", "add", target, "lladdr", "02:00:00:00:00:13", "dev", "wan", "nud", "permanent")
	}
	if finalInterface {
		for _, address := range []string{"10.240.4.10", "10.240.4.11"} {
			packetIP(ctx, t, "neighbor", "add", address, "lladdr", "02:00:00:00:00:14", "dev", "lan13", "nud", "permanent")
		}
	}
	packetIP(ctx, t, "tuntap", "add", "dev", "nat64-internal", "mode", "tun")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "nat64-internal")
	})
	packetIP(ctx, t, "link", "set", "nat64-internal", "up")
	packetIP(ctx, t, "address", "add", "10.251.0.1/32", "dev", "nat64-internal")
	packetIP(ctx, t, "-6", "address", "add", "fdca:1a2b:ffff::64/128", "dev", "nat64-internal", "nodad")
	packetIP(ctx, t, "route", "add", "10.251.0.0/24", "dev", "nat64-internal")
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:e064::/96", "dev", "nat64-internal")

	b := nativeAccessBaseline(t)
	if finalInterface {
		b.Zones[1].Networks = sourceClassPrefixes("10.240.4.0/24")
	} else {
		b.Zones = b.Zones[:1]
	}
	b.NetworkModel.ManagedNetworks = []policy.Role{}
	if sourceOwned {
		b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[0].Role}
	}
	if targetOwned {
		b.NetworkModel.ManagedNetworks = append(b.NetworkModel.ManagedNetworks, b.Zones[1].Role)
	}
	pool := netip.MustParsePrefix("10.251.0.0/24")
	b.NAT64 = []policy.NAT64{{
		ID: "nat64-internal", Prefix: netip.MustParsePrefix("fdca:1a2b:e064::/96"), Scope: "private", SourcePool: &pool,
		SourceMappings: []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}},
	}}
	allocatedMappings := b.NAT64[0].SourceMappings
	if dynamic {
		b.NAT64[0].SourceMappings = nil
	}
	allowAuthorization := "owner"
	if directory {
		allowAuthorization = "directory"
	}
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "any", From: []policy.NetworkSelector{{Interface: "lan10"}},
			To: []policy.NetworkSelector{{Interface: "wan", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.3.11/32")}}}},
		{Action: "allow", Authorization: allowAuthorization, Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b::/64")}}},
			To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}},
	}
	if finalInterface {
		b.NetworkModel.Rules = append([]policy.NetworkRule{
			{Action: "deny", Authorization: "inherit", Protocol: "any",
				From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64"), MAC: "02:00:00:00:00:10"}},
				To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.4.10/32")}}},
			{Action: "deny", Authorization: "inherit", Protocol: "any",
				From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::11/128")}},
				To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.4.11/32")}}},
		}, b.NetworkModel.Rules...)
	}
	if separateRules {
		// The raw carrier first matches translator rule 5. IPv4 routing
		// independently selects WAN rule 3 or mixed-family LAN rule 4.
		b.NetworkModel.Rules = append(b.NetworkModel.Rules[:3],
			policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "any",
				From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
				To:   []policy.NetworkSelector{{Interface: "wan"}}},
			policy.NetworkRule{Action: "allow", Authorization: allowAuthorization, Protocol: "any",
				From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
				To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.4.0/24")}}},
			b.NetworkModel.Rules[3])
	}
	layout, err := newNativeNAT64AccessLayout(ctx, b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	packetNft(ctx, t, `table inet n64_layout_floor {
 chain mandatory { type filter hook forward priority 0; policy drop;
	  meta mark & 0xff000000 { 0xd1000000, 0xd2000000, 0xd3000000, 0xd4000000, 0xd5000000, 0xd6000000, 0xd7000000, 0xd8000000, 0xd9000000, 0xda000000 } accept
 }
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		defer func() {
			packetNft(cleanup, t, "delete table inet n64_layout_floor; delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
		}()
		if t.Failed() {
			logNAT64IdentityFixture(cleanup, t)
			for _, name := range []string{"n64_wire_reply_entry", "n64_fact_restore", "n64_fact_restore_current", "n64_fact_epoch", "n64_fact_reply_kind"} {
				t.Logf("joined NAT64 internal counter %s: %s", name, kernelFixtureCommand(cleanup, t, "list", "counter", "inet", ownedTable, name))
			}
			for _, name := range []string{"n64_scope_entry", "n64_phys_iif", "n64_phys_udp", "n64_phys_mark", "n64_physical_admitted", "n64_final_configuration", "n64_priority_restore"} {
				t.Logf("joined NAT64 internal counter %s: %s", name, kernelFixtureCommand(cleanup, t, "list", "counter", "netdev", ownedTable, name))
			}
		}
	})

	transport := layout.native.nat64Transport
	ledger, err := transport.geometry.Capture(ctx, transport.component, nil, allocatedMappings)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	translatorComponent := b.NAT64[0]
	if dynamic {
		// Runtime allocation supplies native translator mappings; the immutable
		// authorization baseline above deliberately contains none of them.
		translatorComponent.SourceMappings = allocatedMappings
	}
	readiness := startNAT64IdentityTranslator(ctx, t, translatorComponent, transport, entries)
	var grantOrigins []*nativeNAT64GrantOrigin
	if dynamic {
		if len(transport.mappings) != 0 {
			t.Fatal("dynamic fixture retained configured source aliases")
		}
		grantOrigins = []*nativeNAT64GrantOrigin{{transport: transport, ledger: ledger, readiness: readiness}}
	}
	allocations, err := prepareNativeNAT64Allocations(ctx, transport, ledger, readiness)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(ctx, 17)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	preparedConfiguration, err := renderer.prepareConfiguration(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, preparedConfiguration.batch.data)
	var sources *nativeSourcePublication
	var ownershipBindings binding.Snapshot
	publishOwnership := func(epoch uint32, targetMAC string) {
		now := time.Now().Round(0).UTC()
		snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "nat64-owner", ObservedAt: now, Complete: true,
			Records: []binding.Record{{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10,
				AssociatedAt: now, AssociationID: "nat64-owner-association", Addresses: []binding.Address{{IP: netip.MustParseAddr("fdca:1a2b::10"),
					Source: "qualified_ipv6", OwnershipID: "nat64-owner-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}}
		if targetOwned {
			targets := []binding.Record{{MAC: targetMAC, NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: "nat64-target-association", Addresses: []binding.Address{{IP: netip.MustParseAddr("10.240.4.11"), Source: "kea_dhcp4", OwnershipID: "nat64-target-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}
			if targetExpiry {
				targets[0].Addresses[0].ValidUntil = now.Add(10 * time.Second)
			}
			if sourceOwned {
				snapshot.Records = append(snapshot.Records, targets...)
			} else {
				snapshot.Records = targets
			}
		}
		if recipient || pairedOwner || pairedDirectory {
			// An unused IPv6 identity sorts before the caller. Its UID cannot
			// become the caller or be confused with the IPv4 target's UID.
			snapshot.Records = append(snapshot.Records, binding.Record{MAC: "02:00:00:00:00:09", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10,
				AssociatedAt: now, AssociationID: "unused-owned-caller", Addresses: []binding.Address{{IP: netip.MustParseAddr("fdca:1a2b::9"), Source: "qualified_ipv6", OwnershipID: "unused-owned-caller-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}})
		}
		proof, compileErr := compiler.CompileOwnership(ctx, snapshot, now, policy.CaptureAge())
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		proof, compileErr = proof.InEpoch(ctx, epoch)
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		owned, prepareErr := renderer.prepareNativeOwnership(ctx, proof, now)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		owned, prepareErr = prepareNativeNAT64SourceRefresh(ctx, owned, sources, 0, transport)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		executeGuardFixture(ctx, t, owned.batch.data)
		sources, err = nativeSourceReceipt(ctx, owned)
		if err != nil {
			t.Fatal(err)
		}
		ownershipBindings = snapshot
	}
	if sourceOwned || targetOwned {
		publishOwnership(19, "02:00:00:00:00:14")
	}

	tokens, err := deriveNativeNAT64Tokens(ctx, transport, layout.native, ledger, configuration, sources, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := publisher.close(); err != nil {
			t.Error(err)
		}
	})
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Allocations, nat64Allocation: allocations})
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens})
	grantPeer := "fdca:1a2b:e064::af0:30a"
	if authorization == "split" || pairedDirectory {
		grantPeer = "fdca:1a2b:e064::af0:40b"
	}
	publishDirectory := func(timeout int, enabled bool, protocols ...string) {
		t.Helper()
		if len(protocols) == 0 {
			protocols = []string{"tcp", "udp"}
		}
		anchor := policy.CaptureAge()
		utc := time.Now().UTC()
		_, _, _, input := renderFixture(t)
		input.Now, input.Directory.ObservedAt, input.Bindings = utc, utc, ownershipBindings
		role, mac, peer, direction := b.Zones[0].Role, "02:00:00:00:00:10", grantPeer, policy.FromDevice
		if targetOwned && !pairedDirectory {
			role, mac, peer, direction = b.Zones[1].Role, "02:00:00:00:00:14", "fdca:1a2b::10", policy.ToDevice
		}
		placement, marshalErr := json.Marshal(map[string]any{"schema_version": 1, "kind": "placement", "vlan_role": role})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		placementText := string(placement)
		input.Directory.Groups = []policy.Group{{ID: "placement", Name: "Synthetic device placement", IsNetwork: true, Policy: &placementText}}
		input.Directory.Devices = []policy.Device{{ID: "grant-device", MAC: mac, Active: enabled, GroupIDs: []string{"placement"}}}
		history := &state.Classification{MACs: []string{mac}, IPv4: []string{}, IPv6: []string{}}
		if pairedOwner {
			value := state.EmptyClassification()
			history = &value
		}
		// A temporary policy supplies expiry; no rendered grant is edited.
		expires := utc.Add(time.Duration(timeout)*time.Second + preparationBudget + commandBudget + time.Second - time.Nanosecond)
		for _, protocol := range protocols {
			rule := policy.Rule{ID: "listener", Direction: direction, Peer: policy.Peer{Addresses: []string{peer + "/128"}}, Protocol: protocol,
				DestinationPorts: []uint16{6061}, Reason: "Synthetic translated listener", ExpiresAt: &expires}
			data, marshalErr := json.Marshal(map[string]any{"schema_version": 1, "kind": "access", "vlan_role": role, "temporary": true, "rules": []policy.Rule{rule}})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			policyText := string(data)
			group := policy.Group{ID: "listener-" + protocol, Name: "Synthetic translated listener", IsNetwork: true, Policy: &policyText}
			input.Directory.Groups = append(input.Directory.Groups, group)
			input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, group.ID)
		}
		if authorization == "recipient_cohort" {
			history.MACs = append([]string{"02:00:00:00:00:10"}, history.MACs...)
			data, marshalErr := json.Marshal(map[string]any{"schema_version": 1, "kind": "placement", "vlan_role": b.Zones[0].Role})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			policyText := string(data)
			input.Directory.Groups = append(input.Directory.Groups, policy.Group{ID: "caller-placement", Name: "Synthetic caller placement", IsNetwork: true, Policy: &policyText})
			input.Directory.Devices = append(input.Directory.Devices, policy.Device{ID: "owned-caller", MAC: "02:00:00:00:00:10", Active: true, GroupIDs: []string{"caller-placement"}})
		}
		authorization, compileErr := compiler.CompileAuthorization(ctx, input, anchor)
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		candidate, compileErr := authorization.Snapshot(ctx)
		want := 0
		if enabled {
			want = len(protocols)
		}
		if compileErr != nil || len(candidate.Grants) != want {
			t.Fatal("raw directory policy did not compile its exact grants", compileErr, candidate.Denials, len(candidate.Grants), want)
		}
		addresses, compileErr := compiler.ClassifyBindings(ctx, input.Bindings, history.MACs, utc)
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		for _, address := range addresses {
			if address.Is4() {
				history.IPv4 = append(history.IPv4, address.String())
			} else {
				history.IPv6 = append(history.IPv6, address.String())
			}
		}
		slices.Sort(history.IPv4)
		slices.Sort(history.IPv6)
		logicalBatch, compileErr := renderer.prepare(ctx, replacement{authorization: authorization, now: utc, cohort: history.MACs})
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		mapped, prepareErr := prepareMappedGuards(ctx, logicalBatch, history, nil)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		guarded, prepareErr := prepareNativeNAT64Guards(ctx, mapped, sources, transport, utc, grantOrigins...)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		if _, applyErr := publisher.run(ctx, commandInput{op: applyGuarded, guarded: guarded}); applyErr != nil {
			t.Fatal(applyErr)
		}
	}
	if directory {
		publishDirectory(43, true)
	}
	if _, err := publisher.inspectGuards(ctx, layout); err != nil {
		logNativeAccessSchema(ctx, t, layout)
		t.Fatal("joined NAT64 layout differs from its fixed schema", err)
	}
	if targetOwned {
		monitorNAT64TargetTrace(ctx, t)
	}
	packetNft(ctx, t, `table inet n64_join_trace {
	chain raw_start { type filter hook prerouting priority -301; policy accept;
	 iifname "lan10" ip6 saddr fdca:1a2b::10 udp dport 6061 meta nftrace set 1
	 iifname "nat64-internal" ip saddr 10.251.0.0/24 udp dport 6061 meta nftrace set 1
	 iifname "lan13" ip saddr 10.240.4.11 udp sport 6061 meta nftrace set 1
	 iifname "nat64-internal" ip6 saddr fdca:1a2b:e064::/96 udp sport 6061 meta nftrace set 1
	}
 counter wire_before {}
 counter wire_after_early {}
 counter wire_before_confirm {}
 counter wire_after_confirm {}
 counter wire_post {}
 chain wire_before { type filter hook forward priority -151; policy accept; iifname "nat64-internal" ip saddr 10.251.0.0/24 counter name wire_before; }
 chain wire_after_early { type filter hook forward priority -149; policy accept; iifname "nat64-internal" ip saddr 10.251.0.0/24 counter name wire_after_early; }
 chain wire_before_confirm { type filter hook forward priority 149; policy accept; iifname "nat64-internal" ip saddr 10.251.0.0/24 counter name wire_before_confirm; }
 chain wire_after_confirm { type filter hook forward priority 151; policy accept; iifname "nat64-internal" ip saddr 10.251.0.0/24 counter name wire_after_confirm; }
 chain wire_post { type filter hook postrouting priority 202; policy accept; oifname "wan" ip saddr 10.251.0.0/24 counter name wire_post; }
}

table netdev n64_join_trace {
 counter wire_physical_before {}
 counter wire_physical_after {}
 counter raw_reply_physical_before {}
 counter raw_reply_physical_after {}
 chain wire_physical_before { type filter hook egress device "wan" priority -1; policy accept; ip saddr 10.251.0.0/24 counter name wire_physical_before; }
 chain wire_physical_after { type filter hook egress device "wan" priority 1; policy accept; ip saddr 10.251.0.0/24 counter name wire_physical_after; }
 chain raw_reply_physical_before { type filter hook egress device "lan10" priority -1; policy accept; ip6 saddr fdca:1a2b:e064::/96 counter name raw_reply_physical_before; }
 chain raw_reply_physical_after { type filter hook egress device "lan10" priority 1; policy accept; ip6 saddr fdca:1a2b:e064::/96 counter name raw_reply_physical_after; }
}`)
	packetNft(ctx, t, `add counter inet n64_join_trace wire_reply_before
add counter inet n64_join_trace wire_reply_after
add counter inet n64_join_trace wire_reply_before_confirm
add counter inet n64_join_trace wire_reply_after_confirm
add counter inet n64_join_trace wire_reply_post
add counter inet n64_join_trace raw_reply_before
add counter inet n64_join_trace raw_reply_after
add rule inet n64_join_trace wire_before ip daddr 10.251.0.0/24 counter name wire_reply_before
add rule inet n64_join_trace wire_after_early ip daddr 10.251.0.0/24 counter name wire_reply_after
add rule inet n64_join_trace wire_before_confirm ip daddr 10.251.0.0/24 counter name wire_reply_before_confirm
add rule inet n64_join_trace wire_after_confirm ip daddr 10.251.0.0/24 counter name wire_reply_after_confirm
add rule inet n64_join_trace wire_post oifname "nat64-internal" ip daddr 10.251.0.0/24 counter name wire_reply_post
add rule inet n64_join_trace wire_before iifname "nat64-internal" ip6 saddr fdca:1a2b:e064::/96 counter name raw_reply_before
add rule inet n64_join_trace wire_after_early iifname "nat64-internal" ip6 saddr fdca:1a2b:e064::/96 counter name raw_reply_after`)
	packetNft(ctx, t, `add counter netdev `+ownedTable+` n64_scope_entry
add counter netdev `+ownedTable+` n64_phys_iif
add counter netdev `+ownedTable+` n64_phys_udp
add counter netdev `+ownedTable+` n64_phys_mark
add counter netdev `+ownedTable+` n64_physical_admitted
add counter netdev `+ownedTable+` n64_final_configuration
add counter netdev `+ownedTable+` n64_priority_restore
insert rule netdev `+ownedTable+` native_scope_gate ip saddr 10.251.0.0/24 counter name n64_scope_entry
insert rule netdev `+ownedTable+` native_scope_gate iifname "nat64-internal" counter name n64_phys_iif
insert rule netdev `+ownedTable+` native_scope_gate meta l4proto udp counter name n64_phys_udp
insert rule netdev `+ownedTable+` native_scope_gate meta mark & 0xff000000 == 0xd3000000 counter name n64_phys_mark
insert rule netdev `+ownedTable+` native_physical_admitted ip saddr 10.251.0.0/24 counter name n64_physical_admitted
insert rule netdev `+ownedTable+` native_final_configuration ip saddr 10.251.0.0/24 counter name n64_final_configuration
insert rule netdev `+ownedTable+` restore_owner_priority ip saddr 10.251.0.0/24 counter name n64_priority_restore`)
	packetNft(ctx, t, `add counter inet `+ownedTable+` n64_wire_reply_entry
add counter inet `+ownedTable+` n64_fact_restore
add counter inet `+ownedTable+` n64_fact_restore_current
add counter inet `+ownedTable+` n64_fact_epoch
add counter inet `+ownedTable+` n64_fact_reply_kind
insert rule inet `+ownedTable+` native_n64_wire_reply counter name n64_wire_reply_entry
insert rule inet `+ownedTable+` native_translation_facts_restore counter name n64_fact_restore
insert rule inet `+ownedTable+` native_translation_facts_restore_current counter name n64_fact_restore_current
insert rule inet `+ownedTable+` native_translation_facts_epoch counter name n64_fact_epoch
insert rule inet `+ownedTable+` native_translation_facts_reply_kind counter name n64_fact_reply_kind`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		if t.Failed() {
			for _, family := range []string{"inet", "netdev"} {
				t.Logf("joined NAT64 trace %s: %s", family, kernelFixtureCommand(cleanup, t, "list", "table", family, "n64_join_trace"))
			}
		}
		packetNft(cleanup, t, "delete table inet n64_join_trace; delete table netdev n64_join_trace")
	})

	if separateRules {
		packetNft(ctx, t, `add counter inet n64_join_trace selected_raw_rule
add counter inet n64_join_trace selected_wan_rule
add counter inet n64_join_trace selected_lan_rule
add rule inet n64_join_trace wire_post oifname "nat64-internal" ip6 daddr fdca:1a2b:e064::/96 ct mark & 0x3ff == 5 counter name selected_raw_rule
add rule inet n64_join_trace wire_post oifname "wan" ip saddr 10.251.0.0/24 ct direction original ct mark & 0x3ff == 3 counter name selected_wan_rule
add rule inet n64_join_trace wire_post oifname "lan13" ip saddr 10.251.0.0/24 ct direction original ct mark & 0x3ff == 4 counter name selected_lan_rule`)
	}
	if targetOwned {
		kind := "false"
		if directory {
			kind = "true"
		}
		chain := "native_n64_0_udp_forward_target_physical_true_" + kind
		for index, name := range []string{chain, chain + "_current", chain + "_configuration"} {
			counter := fmt.Sprintf("n64_target_stage_%d", index)
			packetNft(ctx, t, "add counter netdev "+ownedTable+" "+counter+"; insert rule netdev "+ownedTable+" "+name+" counter name "+counter)
		}
	}
	client, wrong, internet := packetSocket(t, "peer0"), packetSocket(t, "wrongpeer"), packetSocket(t, "wanpeer")
	source, alias := entries[0].Source, entries[0].Alias
	target, encoded := netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("fdca:1a2b:e064::af0:30a")
	targetRouterMAC, targetPeerMAC := "02:00:00:00:01:13", "02:00:00:00:00:13"
	if targetOwned {
		internet = packetSocket(t, "lanpeer")
		target = netip.MustParseAddr("10.240.4.11")
		encoded = netip.MustParseAddr("fdca:1a2b:e064::af0:40b")
		targetRouterMAC, targetPeerMAC = "02:00:00:00:01:14", "02:00:00:00:00:14"
	}
	if finalInterface {
		lan := packetSocket(t, "lanpeer")
		request := packetDatagram{source: source, destination: netip.MustParseAddr("fdca:1a2b:e064::af0:40a"),
			sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: portBase - 1, destinationPort: 6061, payload: "denied-final-LAN-through-NAT64"}
		sendPacket(ctx, t, client, packetFrame(t, request))
		rejectNATPayload(ctx, t, lan, request.payload)
		request.destination, request.sourcePort, request.payload = netip.MustParseAddr("fdca:1a2b:e064::af0:40b"), portBase-2, "allowed-final-LAN-with-other-source-deny"
		sendPacket(ctx, t, client, packetFrame(t, request))
		wire := request
		wire.source, wire.destination = alias, netip.MustParseAddr("10.240.4.11")
		wire.sourceMAC, wire.destinationMAC = "02:00:00:00:01:14", "02:00:00:00:00:14"
		receivePacket(ctx, t, lan, packetFrame(t, wire), true, 61)
		if separateRules {
			reply := wire
			reply.source, reply.destination = wire.destination, wire.source
			reply.sourcePort, reply.destinationPort = wire.destinationPort, wire.sourcePort
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:14", "02:00:00:00:01:14"
			reply.payload = "distinct-LAN-rule-return"
			sendPacket(ctx, t, lan, packetFrame(t, reply))
			reply.source, reply.destination = request.destination, source
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:01:10", "02:00:00:00:00:10"
			receivePacket(ctx, t, client, packetFrame(t, reply), true, 61)
			if targetExpiry {
				// Keep the caller and its source grant live while only the
				// target's original ownership deadline expires in the kernel.
				deadline := time.Now().Add(10 * time.Second)
				for strings.Contains(string(kernelFixtureCommand(ctx, t, "list", "set", "inet", ownedTable, nativeSourceEpoch4)), `"elem"`) {
					if time.Now().After(deadline) {
						t.Fatal("target ownership did not expire at its original deadline")
					}
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(100 * time.Millisecond):
					}
				}
				for _, name := range []string{nativeSourceLive6, "native_n64_from4_udp", "native_n64_from6_udp"} {
					if !strings.Contains(string(kernelFixtureCommand(ctx, t, "list", "set", "inet", ownedTable, name)), `"elem"`) {
						t.Fatal("target expiry also lost the independent current caller or grant", name)
					}
				}
				reply.source, reply.destination = wire.destination, wire.source
				reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:14", "02:00:00:00:01:14"
				reply.payload = "return-after-target-ownership-expiry"
				sendPacket(ctx, t, lan, packetFrame(t, reply))
				rejectNATPayload(ctx, t, client, reply.payload)
				request.sourcePort += 77
				request.payload = "fresh-request-after-target-ownership-expiry"
				sendPacket(ctx, t, client, packetFrame(t, request))
				rejectNATPayload(ctx, t, lan, request.payload)
				return
			}
		}
	}
	denied := packetDatagram{source: source, destination: netip.MustParseAddr("fdca:1a2b:e064::af0:30b"), sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
		sourcePort: portBase, destinationPort: 6061, payload: "projected-deny-" + authorization}
	sendPacket(ctx, t, client, packetFrame(t, denied))
	rejectNATPayload(ctx, t, internet, denied.payload)

	serial := portBase + 1
	for _, protocol := range []string{"udp", "tcp", "echo"} {
		serial++
		request := packetDatagram{source: source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: serial, destinationPort: 6061, payload: "joined-nat64-" + protocol}
		if protocol == "tcp" {
			request.isTCP, request.tcpFlags, request.sequence, request.payload = true, 2, 100, ""
		}
		if protocol == "echo" {
			request.isICMP, request.icmpType, request.icmpData = true, 128, uint32(serial)<<16|1
		}
		sendPacket(ctx, t, client, packetFrame(t, request))
		if directory && authorization != "split" && protocol == "echo" {
			rejectNATPayload(ctx, t, internet, request.payload)
			continue
		}
		wire := request
		wire.source, wire.destination = alias, target
		wire.sourceMAC, wire.destinationMAC = targetRouterMAC, targetPeerMAC
		if request.isICMP {
			wire.icmpType = 8
		}
		receivePacket(ctx, t, internet, packetFrame(t, wire), true, 61)

		reply := packetDatagram{source: target, destination: alias, sourceMAC: targetPeerMAC, destinationMAC: targetRouterMAC,
			sourcePort: 6061, destinationPort: serial, payload: "joined-return-" + protocol}
		if request.isTCP {
			reply.isTCP, reply.tcpFlags, reply.sequence, reply.acknowledgment, reply.payload = true, 18, 200, 101, ""
		}
		if request.isICMP {
			reply.isICMP, reply.icmpType, reply.icmpData = true, 0, request.icmpData
		}
		sendPacket(ctx, t, internet, packetFrame(t, reply))
		rawReply := reply
		rawReply.source, rawReply.destination = encoded, source
		rawReply.sourceMAC, rawReply.destinationMAC = "02:00:00:00:01:10", "02:00:00:00:00:10"
		if reply.isICMP {
			rawReply.icmpType = 129
		}
		receivePacket(ctx, t, client, packetFrame(t, rawReply), true, 61)
	}

	if targetOwned {
		probeTarget := func(name string, port uint16, tcp, allowed bool) {
			t.Helper()
			t.Run(name, func(t *testing.T) {
				request := packetDatagram{source: source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: port, destinationPort: 6061, payload: "target-" + name}
				if tcp {
					request.isTCP = true
					request.tcpFlags = 2
					request.sequence = 100
					request.payload = ""
				}
				sendPacket(ctx, t, client, packetFrame(t, request))
				wire := request
				wire.source, wire.destination = alias, target
				wire.sourceMAC, wire.destinationMAC = targetRouterMAC, targetPeerMAC
				receivePacket(ctx, t, internet, packetFrame(t, wire), allowed, 61)
			})
		}
		if directory {
			publishDirectory(43, true, "tcp")
			probeTarget("target-TCP-grant-denies-UDP", portBase+20, false, false)
			probeTarget("target-TCP-grant-allows-TCP", portBase+21, true, true)
			publishDirectory(43, true)
			probeTarget("fresh-target-UDP-grant", portBase+22, false, true)
		} else {
			publishDirectory(0, false)
			probeTarget("target-owner-survives-directory-withdrawal", portBase+23, false, true)
		}
		t.Run("target-reply-rejects-wrong-MAC", func(t *testing.T) {
			reply := packetDatagram{source: target, destination: alias, sourceMAC: "02:00:00:00:00:15", destinationMAC: targetRouterMAC, sourcePort: 6061, destinationPort: portBase + 2, payload: "wrong-target-source-MAC"}
			before := guardFixtureCounter(ctx, t, "n64_join_trace", "wire_reply_before")
			sendPacket(ctx, t, internet, packetFrame(t, reply))
			reply.source, reply.destination = encoded, source
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:01:10", "02:00:00:00:00:10"
			receivePacket(ctx, t, client, packetFrame(t, reply), false, 61)
			if guardFixtureCounter(ctx, t, "n64_join_trace", "wire_reply_before") <= before {
				t.Fatal("wrong-MAC reply did not reach the early guard")
			}
		})
		t.Run("managed-target-without-current-ownership", func(t *testing.T) {
			packetIP(ctx, t, "neighbor", "add", "10.240.4.12", "lladdr", targetPeerMAC, "dev", "lan13", "nud", "permanent")
			request := packetDatagram{source: source, destination: netip.MustParseAddr("fdca:1a2b:e064::af0:40c"), sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: portBase + 24, destinationPort: 6061, payload: "unknown-target"}
			before := guardFixtureCounter(ctx, t, "n64_join_trace", "wire_before")
			sendPacket(ctx, t, client, packetFrame(t, request))
			request.source, request.destination = alias, netip.MustParseAddr("10.240.4.12")
			request.sourceMAC, request.destinationMAC = targetRouterMAC, targetPeerMAC
			receivePacket(ctx, t, internet, packetFrame(t, request), false, 61)
			if guardFixtureCounter(ctx, t, "n64_join_trace", "wire_before") <= before {
				t.Fatal("unowned target did not reach the wire guard")
			}
		})
	}
	if separateRules {
		for _, name := range []string{"selected_raw_rule", "selected_wan_rule", "selected_lan_rule"} {
			if targetOwned && name == "selected_wan_rule" {
				continue
			}
			if guardFixtureCounter(ctx, t, "n64_join_trace", name) == 0 {
				t.Fatal("actual path did not retain its independent rule", name)
			}
		}
	}
	if authorization == "split" {
		lan := packetSocket(t, "lanpeer")
		probe := func(name string, lanPath, existing, allowed bool) {
			t.Helper()
			t.Run(name, func(t *testing.T) {
				port := portBase + 30
				encodedPeer, peer, socket := encoded, target, internet
				routerMAC, endpointMAC := "02:00:00:00:01:13", "02:00:00:00:00:13"
				if lanPath {
					encodedPeer, peer, socket = netip.MustParseAddr(grantPeer), netip.MustParseAddr("10.240.4.11"), lan
					routerMAC, endpointMAC = "02:00:00:00:01:14", "02:00:00:00:00:14"
				}
				if existing {
					port = portBase + 2
					if lanPath {
						port = portBase - 2
					}
				}
				request := packetDatagram{source: source, destination: encodedPeer, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
					sourcePort: port, destinationPort: 6061, payload: "independent-path-" + name}
				sendPacket(ctx, t, client, packetFrame(t, request))
				wire := request
				wire.source, wire.destination = alias, peer
				wire.sourceMAC, wire.destinationMAC = routerMAC, endpointMAC
				receivePacket(ctx, t, socket, packetFrame(t, wire), allowed, 61)
			})
		}
		publishDirectory(0, false)
		probe("owner-existing-survives-directory-loss", false, true, true)
		probe("owner-new-survives-directory-loss", false, false, true)
		probe("directory-existing-requires-current-grant", true, true, false)
		probe("directory-new-requires-current-grant", true, false, false)
		callback := packetDatagram{source: netip.MustParseAddr("10.240.4.11"), destination: alias,
			sourceMAC: "02:00:00:00:00:14", destinationMAC: "02:00:00:00:01:14",
			sourcePort: 6061, destinationPort: portBase - 2, payload: "revoked-directory-reply"}
		sendPacket(ctx, t, lan, packetFrame(t, callback))
		callback.source, callback.destination = netip.MustParseAddr(grantPeer), source
		callback.sourceMAC, callback.destinationMAC = "02:00:00:00:01:10", "02:00:00:00:00:10"
		receivePacket(ctx, t, client, packetFrame(t, callback), false, 61)
		publishDirectory(1, true)
		probe("fresh-directory-grant-restores-existing-path", true, true, true)
		timer := time.NewTimer(1200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		probe("expired-directory-grant-denies-path", true, true, false)
		probe("owner-existing-survives-directory-expiry", false, true, true)
		return
	}
	unsolicited := packetDatagram{source: target, destination: alias, sourceMAC: targetPeerMAC, destinationMAC: targetRouterMAC,
		sourcePort: 6061, destinationPort: portBase + 10, payload: "unsolicited-nat64-" + authorization}
	sendPacket(ctx, t, internet, packetFrame(t, unsolicited))
	rejectNATPayload(ctx, t, client, unsolicited.payload)
	if sourceOwned || targetOwned {
		if directory {
			wrongInterface := denied
			wrongInterface.destination, wrongInterface.sourceMAC, wrongInterface.destinationMAC = encoded, "02:00:00:00:00:11", "02:00:00:00:01:11"
			wrongInterface.sourcePort, wrongInterface.payload = portBase+11, fmt.Sprintf("directory-wrong-interface-%d", time.Now().UnixNano())
			sendPacket(ctx, t, wrong, packetFrame(t, wrongInterface))
			rejectNATPayload(ctx, t, internet, wrongInterface.payload)

			publishDirectory(1, true)
			expiring := denied
			expiring.destination, expiring.sourcePort, expiring.payload = encoded, portBase+12, fmt.Sprintf("directory-expiring-%d", time.Now().UnixNano())
			sendPacket(ctx, t, client, packetFrame(t, expiring))
			expiringWire := expiring
			expiringWire.source, expiringWire.destination = alias, target
			expiringWire.sourceMAC, expiringWire.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
			receivePacket(ctx, t, internet, packetFrame(t, expiringWire), true, 61)
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(1500 * time.Millisecond):
			}
			expired := expiring
			expired.sourcePort, expired.payload = portBase+13, fmt.Sprintf("directory-expired-%d", time.Now().UnixNano())
			sendPacket(ctx, t, client, packetFrame(t, expired))
			rejectNATPayload(ctx, t, internet, expired.payload)

			publishDirectory(43, false)
			withdrawnGrant := denied
			withdrawnGrant.destination, withdrawnGrant.sourcePort, withdrawnGrant.payload = encoded, portBase+14, fmt.Sprintf("directory-withdrawn-%d", time.Now().UnixNano())
			sendPacket(ctx, t, client, packetFrame(t, withdrawnGrant))
			rejectNATPayload(ctx, t, internet, withdrawnGrant.payload)
		}
		revocation, clearErr := prepareNativeOwnershipClear(ctx)
		if clearErr != nil {
			t.Fatal(clearErr)
		}
		executeGuardFixture(ctx, t, revocation.batch.data)
		sources = nil
		withdrawnOwner := denied
		withdrawnOwner.destination, withdrawnOwner.sourcePort, withdrawnOwner.payload = encoded, portBase+15, fmt.Sprintf("owner-withdrawn-%d", time.Now().UnixNano())
		sendPacket(ctx, t, client, packetFrame(t, withdrawnOwner))
		rejectNATPayload(ctx, t, internet, withdrawnOwner.payload)
	}

	if targetOwned {
		t.Run("target-recovery-retains-immutable-old-flow", func(t *testing.T) {
			publishOwnership(21, "02:00:00:00:00:14")
			renewed, deriveErr := deriveNativeNAT64Tokens(ctx, transport, layout.native, ledger, configuration, sources, time.Now().UTC())
			if deriveErr != nil {
				t.Fatal(deriveErr)
			}
			applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: renewed})
			if directory {
				publishDirectory(43, true)
			}
			old := packetDatagram{source: source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: portBase + 2, destinationPort: 6061, payload: "old-target-epoch"}
			sendPacket(ctx, t, client, packetFrame(t, old))
			old.source, old.destination = alias, target
			old.sourceMAC, old.destinationMAC = targetRouterMAC, targetPeerMAC
			receivePacket(ctx, t, internet, packetFrame(t, old), false, 61)
			fresh := packetDatagram{source: source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: portBase + 60, destinationPort: 6061, payload: "fresh-target-epoch"}
			sendPacket(ctx, t, client, packetFrame(t, fresh))
			wire := fresh
			wire.source, wire.destination = alias, target
			wire.sourceMAC, wire.destinationMAC = targetRouterMAC, targetPeerMAC
			receivePacket(ctx, t, internet, packetFrame(t, wire), true, 61)
			reply := wire
			reply.source, reply.destination = target, alias
			reply.sourceMAC, reply.destinationMAC = targetPeerMAC, targetRouterMAC
			reply.sourcePort, reply.destinationPort = 6061, portBase+60
			reply.payload = "fresh-target-return"
			sendPacket(ctx, t, internet, packetFrame(t, reply))
			raw := reply
			raw.source, raw.destination = encoded, source
			raw.sourceMAC, raw.destinationMAC = "02:00:00:00:01:10", "02:00:00:00:00:10"
			receivePacket(ctx, t, client, packetFrame(t, raw), true, 61)
			configurationRevocation, clearErr := prepareConfigurationClear(ctx)
			if clearErr != nil {
				t.Fatal(clearErr)
			}
			executeGuardFixture(ctx, t, configurationRevocation.batch.data)
			before := guardFixtureCounter(ctx, t, "n64_join_trace", "wire_reply_post")
			reply.payload = "configuration-revoked-target-return"
			sendPacket(ctx, t, internet, packetFrame(t, reply))
			raw.payload = reply.payload
			receivePacket(ctx, t, client, packetFrame(t, raw), sourceOwned, 61)
			if guardFixtureCounter(ctx, t, "n64_join_trace", "wire_reply_post") <= before {
				t.Fatal("configuration revocation also removed the independent target ownership path")
			}
			if sourceOwned {
				t.Run("owned-caller-return-requires-current-IPv4-sender", func(t *testing.T) {
					names := []string{nativeSourceLive6}
					if directory {
						names = append(names, "native_n64_from4_udp")
					}
					for _, name := range names {
						if !strings.Contains(string(kernelFixtureCommand(ctx, t, "list", "set", "inet", ownedTable, name)), `"elem"`) {
							t.Fatal("recipient proof withdrawal lost its independent current caller or grant", name)
						}
					}
					packetNft(ctx, t, "flush set inet "+ownedTable+" "+nativeSourceEpoch4+"; flush set netdev "+ownedTable+" "+nativeSourceEpoch4)
					reply.payload = "recipient-without-current-IPv4-sender"
					sendPacket(ctx, t, internet, packetFrame(t, reply))
					raw.payload = reply.payload
					receivePacket(ctx, t, client, packetFrame(t, raw), false, 61)
				})
			}
		})
	}

	tokenRevocation, err := prepareNativeNAT64TokenClear(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokenRevocation})
	withdrawn := denied
	withdrawn.destination, withdrawn.sourcePort, withdrawn.payload = encoded, portBase+16, fmt.Sprintf("withdrawn-%d", time.Now().UnixNano())
	sendPacket(ctx, t, client, packetFrame(t, withdrawn))
	rejectNATPayload(ctx, t, internet, withdrawn.payload)
}

func monitorNAT64TargetTrace(ctx context.Context, t *testing.T) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	file, err := root.Create("nat64-target-trace.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	monitor := exec.CommandContext(ctx, "/usr/bin/stdbuf", "-oL", "-eL", "/usr/sbin/nft", "monitor", "trace")
	monitor.Stdout, monitor.Stderr = file, file
	monitor.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := monitor.Wait(); err != nil && ctx.Err() == nil {
			t.Error(err)
		}
		if t.Failed() {
			data, err := root.ReadFile("nat64-target-trace.log")
			if err == nil {
				if len(data) > 16000 {
					data = data[len(data)-16000:]
				}
				t.Logf("synthetic NAT64 target trace: %s", data)
			}
		}
	})
}
