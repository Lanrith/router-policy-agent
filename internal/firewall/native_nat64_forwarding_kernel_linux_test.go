//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
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
	testKernelNamedNAT64JoinedTAYGA(t, "configuration")
}

func TestKernelNamedNAT64JoinedTAYGAOwner(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "owner")
}

func TestKernelNamedNAT64JoinedTAYGADirectory(t *testing.T) {
	testKernelNamedNAT64JoinedTAYGA(t, "directory")
}

func testKernelNamedNAT64JoinedTAYGA(t *testing.T, authorization string) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	if authorization != "configuration" && authorization != "owner" && authorization != "directory" {
		t.Fatal("unknown NAT64 fixture authorization", authorization)
	}
	sourceOwned, directory := authorization != "configuration", authorization == "directory"
	portBase := uint16(48000)
	switch authorization {
	case "owner":
		portBase = 52000
	case "directory":
		portBase = 56000
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for _, link := range []struct {
		router, endpoint, routerMAC, endpointMAC, address string
	}{
		{"lan10", "peer0", "02:00:00:00:01:10", "02:00:00:00:00:10", "fdca:1a2b::1/64"},
		{"lan11", "wrongpeer", "02:00:00:00:01:11", "02:00:00:00:00:11", "fdca:1a2b:1::1/64"},
		{"wan", "wanpeer", "02:00:00:00:01:13", "02:00:00:00:00:13", "10.240.3.1/24"},
	} {
		packetIP(ctx, t, "link", "add", link.router, "type", "veth", "peer", "name", link.endpoint)
		selected := link.router
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", selected)
		})
		packetIP(ctx, t, "link", "set", link.router, "address", link.routerMAC)
		packetIP(ctx, t, "link", "set", link.endpoint, "address", link.endpointMAC)
		if link.router != "wan" {
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
	b.Zones = b.Zones[:1]
	b.NetworkModel.ManagedNetworks = []policy.Role{}
	if sourceOwned {
		b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[0].Role}
	}
	pool := netip.MustParsePrefix("10.251.0.0/24")
	b.NAT64 = []policy.NAT64{{
		ID: "nat64-internal", Prefix: netip.MustParsePrefix("fdca:1a2b:e064::/96"), Scope: "private", SourcePool: &pool,
		SourceMappings: []policy.NAT64SourceMapping{{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}},
	}}
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
	  meta mark & 0xff000000 { 0xd1000000, 0xd2000000, 0xd3000000, 0xd4000000, 0xd5000000, 0xd6000000 } accept
 }
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		if t.Failed() {
			logNAT64IdentityFixture(cleanup, t)
			for _, name := range []string{"n64_wire_reply_entry", "n64_fact_restore", "n64_fact_restore_current", "n64_fact_epoch", "n64_fact_reply_kind"} {
				t.Logf("joined NAT64 internal counter %s: %s", name, kernelFixtureCommand(cleanup, t, "list", "counter", "inet", ownedTable, name))
			}
			for _, name := range []string{"n64_scope_entry", "n64_phys_iif", "n64_phys_udp", "n64_phys_mark", "n64_physical_admitted", "n64_final_configuration", "n64_priority_restore"} {
				t.Logf("joined NAT64 internal counter %s: %s", name, kernelFixtureCommand(cleanup, t, "list", "counter", "netdev", ownedTable, name))
			}
		}
		packetNft(cleanup, t, "delete table inet n64_layout_floor; delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
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
	readiness := startNAT64IdentityTranslator(ctx, t, b.NAT64[0], transport, entries)
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
	if sourceOwned {
		now := time.Now().Round(0).UTC()
		snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "nat64-owner", ObservedAt: now, Complete: true,
			Records: []binding.Record{{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10,
				AssociatedAt: now, AssociationID: "nat64-owner-association", Addresses: []binding.Address{{IP: netip.MustParseAddr("fdca:1a2b::10"),
					Source: "qualified_ipv6", OwnershipID: "nat64-owner-address", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)}}}}}
		proof, compileErr := compiler.CompileOwnership(ctx, snapshot, now, policy.CaptureAge())
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		proof, compileErr = proof.InEpoch(ctx, 19)
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		owned, prepareErr := renderer.prepareNativeOwnership(ctx, proof, now)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		executeGuardFixture(ctx, t, owned.batch.data)
		sources, err = nativeSourceReceipt(ctx, owned)
		if err != nil {
			t.Fatal(err)
		}
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
	publishDirectory := func(timeout int, enabled bool) {
		t.Helper()
		logical := guardChanges{}
		for _, name := range grantSets {
			logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
		}
		if enabled {
			for _, protocol := range []string{"tcp", "udp"} {
				value, marshalErr := json.Marshal(map[string]any{"elem": map[string]any{"timeout": timeout, "val": map[string]any{"concat": []any{
					"lan10", "02:00:00:00:00:10", "fdca:1a2b::10", "fdca:1a2b:e064::af0:30a", 6061,
				}}}})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				logical.Commands = append(logical.Commands, guardAdd("inet", "lease_from6_"+protocol, []json.RawMessage{value}))
			}
		}
		data, marshalErr := json.Marshal(logical)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		utc, started := time.Now().UTC(), time.Now()
		history := &state.Classification{MACs: []string{"02:00:00:00:00:10"}, IPv4: []string{}, IPv6: []string{"fdca:1a2b::10"}}
		mapped, prepareErr := prepareMappedGuards(ctx, &preparedBatch{data: data, preparedAt: utc, startedAt: started, startBefore: utc.Add(preparationBudget)}, history, nil)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		guarded, prepareErr := prepareNativeNAT64Guards(ctx, mapped, sources, transport, utc)
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
	packetNft(ctx, t, `table inet n64_join_trace {
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
add rule inet n64_join_trace wire_before iifname "wan" ip daddr 10.251.0.0/24 counter name wire_reply_before
add rule inet n64_join_trace wire_after_early iifname "wan" ip daddr 10.251.0.0/24 counter name wire_reply_after
add rule inet n64_join_trace wire_before_confirm iifname "wan" ip daddr 10.251.0.0/24 counter name wire_reply_before_confirm
add rule inet n64_join_trace wire_after_confirm iifname "wan" ip daddr 10.251.0.0/24 counter name wire_reply_after_confirm
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

	client, wrong, internet := packetSocket(t, "peer0"), packetSocket(t, "wrongpeer"), packetSocket(t, "wanpeer")
	source, alias := entries[0].Source, entries[0].Alias
	target, encoded := netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("fdca:1a2b:e064::af0:30a")
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
		if directory && protocol == "echo" {
			rejectNATPayload(ctx, t, internet, request.payload)
			continue
		}
		wire := request
		wire.source, wire.destination = alias, target
		wire.sourceMAC, wire.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
		if request.isICMP {
			wire.icmpType = 8
		}
		receivePacket(ctx, t, internet, packetFrame(t, wire), true, 61)

		reply := packetDatagram{source: target, destination: alias, sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
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

	unsolicited := packetDatagram{source: target, destination: alias, sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
		sourcePort: 6061, destinationPort: portBase + 10, payload: "unsolicited-nat64-" + authorization}
	sendPacket(ctx, t, internet, packetFrame(t, unsolicited))
	rejectNATPayload(ctx, t, client, unsolicited.payload)
	if sourceOwned {
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
		withdrawnOwner := denied
		withdrawnOwner.destination, withdrawnOwner.sourcePort, withdrawnOwner.payload = encoded, portBase+15, fmt.Sprintf("owner-withdrawn-%d", time.Now().UnixNano())
		sendPacket(ctx, t, client, packetFrame(t, withdrawnOwner))
		rejectNATPayload(ctx, t, internet, withdrawnOwner.payload)
	}

	clear, err := prepareNativeNAT64TokenClear(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: clear})
	withdrawn := denied
	withdrawn.destination, withdrawn.sourcePort, withdrawn.payload = encoded, portBase+16, fmt.Sprintf("withdrawn-%d", time.Now().UnixNano())
	sendPacket(ctx, t, client, packetFrame(t, withdrawn))
	rejectNATPayload(ctx, t, internet, withdrawn.payload)
}
