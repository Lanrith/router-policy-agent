//go:build integration && kernel && linux

package firewall

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// An observable veth replaces address conversion only. Original IPv6 packets
// must traverse the actual raw policy and export an exact tuple before an
// injected IPv4 equivalent can reach the actual final-interface policy. The
// test-only readiness object is synthetic; real TAYGA is qualified separately.
func TestKernelNamedNAT64WireFinalPolicyAndAllocationScopes(t *testing.T) {
	testKernelNamedNAT64WireFinalPolicyAndAllocationScopes(t, false)
}

func TestKernelNamedNAT64WireSourceEpochAndAllocationScopes(t *testing.T) {
	testKernelNamedNAT64WireFinalPolicyAndAllocationScopes(t, true)
}

func testKernelNamedNAT64WireFinalPolicyAndAllocationScopes(t *testing.T, sourceOwned bool) {
	t.Helper()
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupNAT64PendingLinks(ctx, t)
	packetIP(ctx, t, "route", "add", "10.251.0.0/24", "dev", "nat64-internal")
	b := nat64TransportFixture(t)
	b.NetworkModel.ManagedNetworks = []policy.Role{}
	if sourceOwned {
		b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[0].Role}
	}
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{
		Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}}
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::10/128")}},
			To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.11/32")}}},
		{Action: "deny", Authorization: "inherit", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::11/128")}},
			To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.10/32")}}},
		{Action: "allow", Authorization: "owner", Protocol: "udp", Ports: []uint16{6061},
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64"), MAC: "02:00:00:00:00:10"}},
			To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}},
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
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	transport := layout.native.nat64Transport
	ledger, err := transport.geometry.Capture(ctx, transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof := &testNAT64Readiness{transport: transport, entries: entries, ready: true}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(ctx, 23)
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
	publishOwnership := func(t *testing.T, epoch uint32) {
		t.Helper()
		now := time.Now().Round(0).UTC()
		snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "nat64-wire-source", ObservedAt: now, Complete: true,
			Records: []binding.Record{{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10,
				AssociatedAt: now, AssociationID: "nat64-wire-association", Addresses: []binding.Address{{IP: entries[0].Source,
					Source: "qualified_ipv6", OwnershipID: "nat64-wire-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}}
		ownership, err := compiler.CompileOwnership(ctx, snapshot, now, policy.CaptureAge())
		if err != nil {
			t.Fatal(err)
		}
		ownership, err = ownership.InEpoch(ctx, epoch)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := renderer.prepareNativeOwnership(ctx, ownership, now)
		if err != nil {
			t.Fatal(err)
		}
		// An epoch change must pass through the ordinary revocation boundary.
		prepared, err = prepareNativeNAT64SourceRefresh(ctx, prepared, sources, 0, transport)
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, prepared.batch.data)
		sources, err = nativeSourceReceipt(ctx, prepared)
		if err != nil {
			t.Fatal(err)
		}
	}
	if sourceOwned {
		publishOwnership(t, 19)
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
	publishAllocations := func() {
		t.Helper()
		prepared, err := prepareNativeNAT64Allocations(ctx, transport, ledger, proof)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.run(ctx, commandInput{op: applyNAT64Allocations, nat64Allocation: prepared}); err != nil {
			t.Fatal(err)
		}
	}
	publishTokens := func(t *testing.T) {
		t.Helper()
		tokens, err := deriveNativeNAT64Tokens(ctx, transport, layout.native, ledger, configuration, sources, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.run(ctx, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens}); err != nil {
			t.Fatal(err)
		}
	}
	publishAllocations()
	publishTokens(t)
	if _, err := publisher.inspectGuards(ctx, layout); err != nil {
		t.Fatal("installed final-interface graph differs from its immutable schema", err)
	}
	client, translated, target := packetSocket(t, "peer0"), packetSocket(t, "n64peer"), packetSocket(t, "device0")
	serial := uint16(46000)
	if sourceOwned {
		serial = 47000
	}
	probe := func(name, encoded, destination string, rawAllowed, allowed bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			serial++
			raw := packetDatagram{source: entries[0].Source, destination: netip.MustParseAddr(encoded),
				sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				sourcePort: serial, destinationPort: 6061, payload: "wire-policy-" + name}
			sendPacket(ctx, t, client, packetFrame(t, raw))
			rawWire := raw
			rawWire.sourceMAC, rawWire.destinationMAC = "02:00:00:00:01:64", "02:00:00:00:00:64"
			receivePacket(ctx, t, translated, packetFrame(t, rawWire), rawAllowed)
			wire := raw
			wire.source, wire.destination = entries[0].Alias, netip.MustParseAddr(destination)
			wire.sourceMAC, wire.destinationMAC = "02:00:00:00:00:64", "02:00:00:00:01:64"
			sendPacket(ctx, t, translated, packetFrame(t, wire))
			wire.sourceMAC, wire.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
			receivePacket(ctx, t, target, packetFrame(t, wire), allowed)
		})
	}
	probe("denied-final-LAN", "fdca:1a2b:e064::af0:30b", "10.240.3.11", true, false)
	probe("allowed-other-source-deny", "fdca:1a2b:e064::af0:30a", "10.240.3.10", true, true)
	scope := slices.Index(transport.sourceScopes, netip.MustParsePrefix("fdca:1a2b::/64"))
	if scope < 0 {
		t.Fatal("fixture lost the original allow source scope")
	}
	packetNft(ctx, t, "flush set inet "+ownedTable+" "+transport.sourceScopeName(scope))
	probe("missing-source-scope", "fdca:1a2b:e064::af0:30a", "10.240.3.10", true, false)
	publishAllocations() // also atomically revokes every token.
	probe("scope-is-not-permission", "fdca:1a2b:e064::af0:30a", "10.240.3.10", false, false)
	publishTokens(t)
	probe("restored-fresh-export", "fdca:1a2b:e064::af0:30a", "10.240.3.10", true, true)
	publishTokens(t)
	serial-- // Retransmit the existing connection after a same-epoch refresh.
	probe("same-epoch-refresh-retains-flow", "fdca:1a2b:e064::af0:30a", "10.240.3.10", true, true)
	if sourceOwned {
		t.Run("withdrawn-source-cannot-borrow-configuration", func(t *testing.T) {
			serial++
			original := packetDatagram{source: entries[0].Source, destination: netip.MustParseAddr("fdca:1a2b:e064::af0:30a"),
				sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				sourcePort: serial, destinationPort: 6061, payload: "withdrawn-source-export"}
			exported := time.Now()
			sendPacket(ctx, t, client, packetFrame(t, original))
			rawWire := original
			rawWire.sourceMAC, rawWire.destinationMAC = "02:00:00:00:01:64", "02:00:00:00:00:64"
			receivePacket(ctx, t, translated, packetFrame(t, rawWire), true)
			withdrawal, err := prepareNativeNAT64OwnershipClear(ctx, transport)
			if err != nil {
				t.Fatal(err)
			}
			executeGuardFixture(ctx, t, withdrawal.batch.data)
			sources = nil
			publishTokens(t)
			if time.Since(exported) >= 1500*time.Millisecond {
				t.Fatal("revoked-source probe exceeded its two-second proof window")
			}
			wire := original
			wire.source, wire.destination = entries[0].Alias, netip.MustParseAddr("10.240.3.10")
			wire.sourceMAC, wire.destinationMAC = "02:00:00:00:00:64", "02:00:00:00:01:64"
			sendPacket(ctx, t, translated, packetFrame(t, wire))
			wire.sourceMAC, wire.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
			receivePacket(ctx, t, target, packetFrame(t, wire), false)
		})
		publishOwnership(t, 20)
		publishTokens(t)
		probe("restored-owned-source-fresh-export", "fdca:1a2b:e064::af0:30a", "10.240.3.10", true, true)
	}
	t.Run("old-export-cannot-acquire-new-epoch", func(t *testing.T) {
		serial++
		original := packetDatagram{source: entries[0].Source, destination: netip.MustParseAddr("fdca:1a2b:e064::af0:30a"),
			sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: serial, destinationPort: 6061, payload: "old-epoch-export"}
		exported := time.Now()
		sendPacket(ctx, t, client, packetFrame(t, original))
		rawWire := original
		rawWire.sourceMAC, rawWire.destinationMAC = "02:00:00:00:01:64", "02:00:00:00:00:64"
		receivePacket(ctx, t, translated, packetFrame(t, rawWire), true)

		// Leave the exported tuple live without creating its IPv4 connection.
		// The new registry reuses opaque IDs for a different authority epoch.
		if sourceOwned {
			withdrawal, err := prepareNativeNAT64OwnershipClear(ctx, transport)
			if err != nil {
				t.Fatal(err)
			}
			executeGuardFixture(ctx, t, withdrawal.batch.data)
			sources = nil
			publishTokens(t)
			publishOwnership(t, 21)
		} else {
			configuration, err = compiler.CompileOwnerConfiguration(ctx, 24)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := renderer.prepareConfiguration(ctx, configuration)
			if err != nil {
				t.Fatal(err)
			}
			executeGuardFixture(ctx, t, prepared.batch.data)
		}
		publishTokens(t)
		if time.Since(exported) >= 1500*time.Millisecond {
			t.Fatal("old-tuple probe exceeded its two-second proof window")
		}
		wire := original
		wire.source, wire.destination = entries[0].Alias, netip.MustParseAddr("10.240.3.10")
		wire.sourceMAC, wire.destinationMAC = "02:00:00:00:00:64", "02:00:00:00:01:64"
		sendPacket(ctx, t, translated, packetFrame(t, wire))
		wire.sourceMAC, wire.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
		receivePacket(ctx, t, target, packetFrame(t, wire), false)
	})
	probe("new-epoch-fresh-export", "fdca:1a2b:e064::af0:30a", "10.240.3.10", true, true)
}
