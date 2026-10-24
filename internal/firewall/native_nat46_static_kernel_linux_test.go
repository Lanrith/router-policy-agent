//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// Exact static source identity is a component fact. These synthetic callers
// supply the ordered permission; this fixture does not activate the router.
func TestKernelNamedNAT46StaticSourceIdentity(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "address", "add", "10.232.0.1/21", "dev", "lan10")
	packetIP(ctx, t, "link", "add", "nat46", "type", "veth", "peer", "name", "translated0")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "nat46")
	})
	for _, link := range []struct{ name, mac string }{{"nat46", "02:00:00:00:01:46"}, {"translated0", "02:00:00:00:00:46"}} {
		packetIP(ctx, t, "link", "set", link.name, "address", link.mac)
		packetIP(ctx, t, "link", "set", link.name, "up")
	}
	packetIP(ctx, t, "route", "add", "10.250.0.0/24", "dev", "nat46")
	packetIP(ctx, t, "neighbor", "replace", "10.250.0.20", "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:e046::/96", "dev", "nat46")
	packetIP(ctx, t, "neighbor", "replace", "fdca:1a2b:e046::ae8:40a", "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
	packetIP(ctx, t, "neighbor", "replace", "10.232.4.10", "dev", "lan10", "lladdr", "02:00:00:00:00:10", "nud", "permanent")
	packetIP(ctx, t, "neighbor", "replace", "10.232.4.11", "dev", "lan10", "lladdr", "02:00:00:00:00:10", "nud", "permanent")
	packetIP(ctx, t, "neighbor", "replace", "fdca:1a2b:e046::ae8:40b", "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
	b := nativeAccessBaseline(t)
	b.Zones[0].Networks = sourceClassPrefixes("10.232.0.0/21", "fdca:1a2b::/64")
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: sourceClassPrefixes("10.232.0.1/32"), Roles: []policy.Role{}})
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	b.NAT46 = []policy.NAT46{{ID: "mapped", Alias: netip.MustParseAddr("10.250.0.20"), Target: netip.MustParseAddr("fdca:1a2b:3::10"), Ready: true}}
	b.Zones = append(b.Zones, policy.Zone{Role: policy.Guest, VLAN: 11, Interfaces: []string{"lan11"}, Networks: sourceClassPrefixes("10.240.1.0/24")})
	b.NetworkModel.ManagedNetworks = []policy.Role{policy.Guest}
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "owner", Protocol: "any", From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.232.0.0/21")}}, To: []policy.NetworkSelector{{Interface: "nat46", Addresses: sourceClassPrefixes("10.250.0.20/32")}}}}
	sources, err := newNativeNAT46StaticSources(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newNativeNAT46StaticTransport(ctx, sources)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := sources.handoff(ctx, nativePacketContext{iface: "lan10", family: 4})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := nativeTranslationFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{"table inet " + ownedTable + " {", "set " + classified4Set + " {type ipv4_addr;size 16384;}", "set " + classified6Set + " {type ipv6_addr;size 16384;}", "set " + ownershipEpochSet + " {type mark;size 1;}", "set " + nativeSourceBits4 + " {typeof meta mark . meta priority . @nh,96,32;size 16384;}"}
	lines = append(lines, "set owner_live {type mark; elements={0};}", "chain save_owner_priority {")
	lines = append(lines, nativeRulesText(nativePriorityScopes(false))...)
	lines = append(lines, "}")
	lines = append(lines, configurationEpochDefinitions()...)
	lines = append(lines, epochChannelDefinitions(true, "inet")...)
	static, err := sources.definitions(ctx, "inet")
	if err != nil {
		t.Fatal(err)
	}
	lines = append(lines, static...)
	lines = append(lines, transport.definitions()...)
	for _, graph := range []map[string][]nativeScope{transport.chains(), handoff, facts} {
		for _, name := range nativeChainNames(graph) {
			lines = append(lines, "chain "+name+" {")
			lines = append(lines, nativeRulesText(graph[name])...)
			lines = append(lines, "}")
		}
	}
	forward := []string{"chain forward {type filter hook forward priority 0;policy drop;"}
	for _, leg := range transport.legs {
		if leg.reply {
			nativeReply, rawReply := leg.name+"_native_reply", leg.name+"_raw_reply"
			forward = append(forward, leg.geometry(false).text+" goto "+nativeReply,
				leg.geometry(true).text+" goto "+rawReply)
			binding := "(meta mark & 0xe000) . (meta priority & 0x3ff) . ip6 daddr @" + nativeNAT46StaticBindings6
			lines = append(lines, "chain "+nativeReply+" {", "meta mark set 0x009f0000 meta priority set 3", "jump native_translation_facts_restore",
				"meta mark & 0x3ff @owner_live "+binding+" goto "+nativeReply+"_current", "drop", "}",
				"chain "+nativeReply+"_current {", "jump "+leg.name+"_export", "accept", "}",
				"chain "+rawReply+" {", "jump "+leg.name+"_import", "meta mark & 0x3ff @owner_live accept", "drop", "}")
			continue
		}
		raw, converted := leg.name+"_raw_caller", leg.name+"_wire_caller"
		forward = append(forward, leg.geometry(false).text+" iifname \"lan10\" ip saddr 10.232.0.0/21 goto "+raw)
		lines = append(lines, "chain "+raw+" {", "ct mark 0 ct state new ct mark set meta nfproto map @"+configurationEpochMap, "meta mark set 0xd36a1400", "meta priority set ct mark & 0xfffffc00 map @configuration_epoch_channel", "meta mark & 0x3ff @owner_live jump "+leg.name+"_export", "meta mark & 0x3ff @owner_live accept", "drop", "}")
		forward = append(forward, leg.geometry(true).text+" goto "+converted)
		lines = append(lines, "chain "+converted+" {", "jump "+leg.name+"_import", "jump native_n46_static_handoff_0", "meta mark & 0x3ff @owner_live jump native_translation_facts_capture", "meta mark & 0x3ff @owner_live accept", "drop", "}")
	}
	forward = append(forward, "}")
	lines = append(lines, forward...)
	lines = append(lines, "counter handoff_completed {}", "counter return_handoff_completed {}", "chain late_handoff {type filter hook forward priority 150;policy accept; meta mark & 0xff000000 == 0xf3000000 counter name handoff_completed; meta mark & 0xff000000 == 0xf4000000 counter name return_handoff_completed;}")
	lines = append(lines, "}", "table netdev "+ownedTable+" {")
	lines = append(lines, "set "+classified4Set+" {type ipv4_addr;size 16384;}", "set "+classified6Set+" {type ipv6_addr;size 16384;}")
	lines = append(lines, epochChannelDefinitions(true, "netdev")...)
	static, err = sources.definitions(ctx, "netdev")
	if err != nil {
		t.Fatal(err)
	}
	lines = append(lines, static...)
	lines = append(lines, "chain static_source {")
	lines = append(lines, nativeRulesText(nat46StaticPhysical(false))...)
	lines = append(lines, "}", "chain static_return {")
	lines = append(lines, nativeRulesText(nat46StaticPhysical(true))...)
	lines = append(lines, "}", "chain restore_owner_priority {")
	lines = append(lines, nativeRulesText(nativePriorityScopes(true))...)
	lines = append(lines, "}", `chain source_scope {
 meta mark & 0xff0003ff == 0xf3000000 ip6 saddr fdca:1a2b:e046::ae8:0/117 ip6 daddr fdca:1a2b:3::10 tcp dport 6061 goto admitted
 meta mark & 0xff0003ff == 0xf3000000 ip6 saddr fdca:1a2b:e046::ae8:0/117 ip6 daddr fdca:1a2b:3::10 udp dport 6061 goto admitted
 meta mark & 0xff0003ff == 0xf3000000 ip6 saddr fdca:1a2b:e046::ae8:0/117 ip6 daddr fdca:1a2b:3::10 icmpv6 type echo-request goto admitted
 drop
 }
 chain admitted {
 jump static_source
 meta mark set meta mark & 0xffff1fff
 goto restore_owner_priority
 }
 chain mutate_final {type filter hook egress device "lan13" priority -1;policy accept;}
 chain guarded {type filter hook egress device "lan13" priority 0;policy accept;
 ip6 saddr fdca:1a2b:e046::/96 goto source_scope
 meta mark & 0xff000000 == 0xf3000000 drop
 }

 chain mutate_return {type filter hook egress device "lan10" priority -1;policy accept;}
 chain return_scope {
 meta mark & 0xff0003ff == 0xf4000000 ip saddr 10.250.0.20 ip daddr 10.232.0.0/21 tcp sport 6061 goto return_admitted
 meta mark & 0xff0003ff == 0xf4000000 ip saddr 10.250.0.20 ip daddr 10.232.0.0/21 udp sport 6061 goto return_admitted
 meta mark & 0xff0003ff == 0xf4000000 ip saddr 10.250.0.20 ip daddr 10.232.0.0/21 icmp type echo-reply goto return_admitted
 drop
 }
 chain return_admitted {
 jump static_return
 meta mark set meta mark & 0xffff1fff
 goto restore_owner_priority
 }
 chain returned {type filter hook egress device "lan10" priority 0;policy accept;
 ip saddr 10.250.0.0/24 goto return_scope
 meta mark & 0xff000000 == 0xf4000000 drop
 }
}`, `table netdev static_source_fixture {
 chain peer_input {type filter hook ingress device "peer0" priority 0;policy drop;}
 chain device_input {type filter hook ingress device "device0" priority 0;policy drop;}
 chain translator_input {type filter hook ingress device "translated0" priority 0;policy drop;}
 counter preserved {}
 counter reply_preserved {}
 chain reply_observed {type filter hook egress device "lan10" priority 1;policy accept;
 meta mark & 0xffffe3ff == 0xf49f0000 meta priority 3 counter name reply_preserved
 }
 chain observed {type filter hook egress device "lan13" priority 1;policy accept;
 meta mark & 0x00ff0000 == 0x006a0000 meta priority 5 counter name preserved
 }
}`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable+"; delete table netdev static_source_fixture")
	})
	inspectNAT46TransportFixture(ctx, t, transport)
	for _, family := range []string{"inet", "netdev"} {
		if err := inspectStaticFixtureGraph(ctx, t, sources, family, handoff); err != nil {
			t.Fatal(err)
		}
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(epoch uint32, geometry bool) {
		t.Helper()
		proof, err := renderer.compiler.CompileOwnerConfiguration(ctx, epoch)
		if err != nil {
			t.Fatal(err)
		}
		current, err := renderer.prepareConfiguration(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, current.batch.data)
		if geometry {
			channel, err := sources.prepareConfiguration(ctx, proof)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateNAT46StaticConfiguration(ctx, channel); err != nil {
				t.Fatal(err)
			}
			executeGuardFixture(ctx, t, channel.batch.data)
		}
	}
	publish(17, true)
	peer, device, translated := packetSocket(t, "peer0"), packetSocket(t, "device0"), packetSocket(t, "translated0")
	serial := 0
	transmit := func(value packetDatagram, input, output packetEndpoint, allowed bool, observe bool) {
		t.Helper()
		serial++
		value.payload = fmt.Sprintf("static-source-%d", serial)
		previous := guardFamilyCounter(ctx, t, "netdev", "static_source_fixture", "preserved")
		sendPacket(ctx, t, input, packetFrame(t, value))
		if allowed {
			receivePacket(ctx, t, output, packetFrame(t, value), true)
		} else {
			rejectNATPayload(ctx, t, output, value.payload)
		}
		next := guardFamilyCounter(ctx, t, "netdev", "static_source_fixture", "preserved")
		expected := previous
		if allowed && observe {
			expected++
		}
		if next != expected {
			t.Fatal("static source handoff changed QoS or original packet priority", previous, next, expected)
		}
	}
	returnPacket := func(value packetDatagram, allowed bool) {
		t.Helper()
		before := guardFamilyCounter(ctx, t, "netdev", "static_source_fixture", "reply_preserved")
		transmit(value, translated, peer, allowed, false)
		expected := before
		if allowed {
			expected++
		}
		if guardFamilyCounter(ctx, t, "netdev", "static_source_fixture", "reply_preserved") != expected {
			t.Fatal("reply restoration changed current packet QoS or priority")
		}
	}
	var original, wire packetDatagram
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		original = packetDatagram{source: netip.MustParseAddr("10.232.4.10"), destination: netip.MustParseAddr("10.250.0.20"), sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: 51000, destinationPort: 6061, isTCP: protocol == "tcp", tcpFlags: 2, isICMP: protocol == "icmp", icmpType: 8, icmpData: 0xc0461001}
		wire = original
		wire.source, wire.destination = netip.MustParseAddr("fdca:1a2b:e046::ae8:40a"), netip.MustParseAddr("fdca:1a2b:3::10")
		wire.sourceMAC, wire.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
		wire.icmpType = 128
		reply := wire
		reply.source, reply.destination = wire.destination, wire.source
		reply.sourcePort, reply.destinationPort = wire.destinationPort, wire.sourcePort
		reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
		reply.tcpFlags, reply.icmpType = 18, 129
		returned := reply
		returned.source, returned.destination = original.destination, original.source
		returned.sourceMAC, returned.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
		returned.icmpType = 0
		transmit(reply, device, translated, false, false)
		returnPacket(returned, false)
		transmit(original, peer, translated, true, false)
		transmit(wire, translated, device, true, true)
		transmit(reply, device, translated, true, false)
		returnPacket(returned, true)
		for _, mutation := range []string{
			"ip daddr set 10.232.4.11",
			"meta priority set 0",
			"meta mark set 0xf4000000",
			"meta mark set 0 meta priority set 0",
		} {
			transmit(reply, device, translated, true, false)
			beforeReturn := guardFamilyCounter(ctx, t, "inet", ownedTable, "return_handoff_completed")
			packetNft(ctx, t, "add rule netdev "+ownedTable+" mutate_return "+mutation)
			returnPacket(returned, false)
			if guardFamilyCounter(ctx, t, "inet", ownedTable, "return_handoff_completed") != beforeReturn+1 {
				t.Fatal("return mutation did not reach the physical predicate with a fresh tuple")
			}
			packetNft(ctx, t, "flush chain netdev "+ownedTable+" mutate_return")
		}
		transmit(reply, device, translated, true, false)
		returnPacket(returned, true)
		if protocol == "udp" {
			time.Sleep(2200 * time.Millisecond)
			returnPacket(returned, false)
			// Fresh native replies retain immutable connection facts and current
			// permission, then export a new short return proof without a request.
			transmit(reply, device, translated, true, false)
			returnPacket(returned, true)
			packetNft(ctx, t, "flush set inet "+ownedTable+" owner_live")
			transmit(reply, device, translated, false, false)
			returnPacket(returned, false)
			packetNft(ctx, t, "add element inet "+ownedTable+" owner_live {0}")
			transmit(reply, device, translated, true, false)
			returnPacket(returned, true)
		}
		packetNft(ctx, t, "add rule netdev "+ownedTable+" mutate_final ip6 saddr fdca:1a2b:e046::ae8:40a ip6 saddr set fdca:1a2b:e046::ae8:40b")
		transmit(original, peer, translated, true, false)
		transmit(wire, translated, device, false, true)
		packetNft(ctx, t, "flush chain netdev "+ownedTable+" mutate_final")
		// Both addresses use source IDs above 1023; the other current address
		// works with its own exact identity and high-ID group.
		otherRaw, otherWire := original, wire
		otherRaw.source = otherRaw.source.Next()
		otherWire.source = otherWire.source.Next()
		otherRaw.sourcePort++
		otherWire.sourcePort++
		otherRaw.icmpData++
		otherWire.icmpData++
		transmit(otherRaw, peer, translated, true, false)
		transmit(otherWire, translated, device, true, true)
		otherReply, otherReturned := reply, returned
		otherReply.destination = otherWire.source
		otherReturned.destination = otherRaw.source
		otherReply.destinationPort, otherReturned.destinationPort = otherWire.sourcePort, otherRaw.sourcePort
		otherReply.icmpData, otherReturned.icmpData = otherWire.icmpData, otherRaw.icmpData
		transmit(otherReply, device, translated, true, false)
		returnPacket(otherReturned, true)
		packetNft(ctx, t, "add rule netdev "+ownedTable+" mutate_final meta priority set 0")
		transmit(original, peer, translated, true, false)
		transmit(wire, translated, device, false, true)
		packetNft(ctx, t, "flush chain netdev "+ownedTable+" mutate_final")
	}
	original.isICMP, wire.isICMP = false, false
	nativeReturn := wire
	nativeReturn.source, nativeReturn.destination = wire.destination, wire.source
	nativeReturn.sourcePort, nativeReturn.destinationPort = wire.destinationPort, wire.sourcePort
	nativeReturn.sourceMAC, nativeReturn.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
	rawReturn := nativeReturn
	rawReturn.source, rawReturn.destination = original.destination, original.source
	rawReturn.sourceMAC, rawReturn.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
	transmit(nativeReturn, device, translated, true, false)
	returnPacket(rawReturn, true)
	// Withdraw only the physical mirror, leaving the early epoch current.
	// The late inet counter proves that the packet still completes handoff.
	_, physicalEpoch := epochChannelNames(true)
	packetNft(ctx, t, "delete element netdev "+ownedTable+" "+physicalEpoch+" {0:4400}")
	transmit(nativeReturn, device, translated, true, false)
	beforeReturn := guardFamilyCounter(ctx, t, "inet", ownedTable, "return_handoff_completed")
	returnPacket(rawReturn, false)
	if guardFamilyCounter(ctx, t, "inet", ownedTable, "return_handoff_completed") != beforeReturn+1 {
		t.Fatal("physical return epoch withdrawal lost its early positive control")
	}
	transmit(original, peer, translated, true, false)
	before := guardFamilyCounter(ctx, t, "inet", ownedTable, "handoff_completed")
	transmit(wire, translated, device, false, true)
	if guardFamilyCounter(ctx, t, "inet", ownedTable, "handoff_completed") != before+1 {
		t.Fatal("physical withdrawal did not retain its early positive control")
	}

	publish(17, true)
	transmit(original, peer, translated, true, false)
	transmit(wire, translated, device, true, true)
	cleared, err := prepareNAT46StaticConfigurationClear(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT46StaticConfiguration(ctx, cleared); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, cleared.batch.data)
	transmit(original, peer, translated, true, false)
	transmit(wire, translated, device, false, true)
	publish(17, true)
	transmit(original, peer, translated, true, false)
	transmit(wire, translated, device, true, true)
	transmit(nativeReturn, device, translated, true, false)
	returnPacket(rawReturn, true)
	// Start with current CFG geometry and valid immutable facts. Publish only
	// deny history in one table family, leaving all positive proofs untouched.
	// With only the physical mirror, both early handoff counters must advance.
	for _, family := range []string{"netdev", "inet"} {
		for _, classified := range []string{original.source.String(), wire.destination.String()} {
			history := state.EmptyClassification()
			history.MACs = []string{"02:00:00:00:00:10"}
			if netip.MustParseAddr(classified).Is4() {
				history.IPv4 = []string{classified}
			} else {
				history.IPv6 = []string{classified}
			}
			shadow, err := sources.model.translatedClassification(ctx, history)
			if err != nil {
				t.Fatal(err)
			}
			// The fixture installs the projection directly. Production restoration
			// must retain its complete typed seal and original persisted history.
			for _, item := range []struct {
				name   string
				values []string
			}{{classified4Set, shadow.IPv4}, {classified6Set, shadow.IPv6}} {
				if len(item.values) > 0 {
					packetNft(ctx, t, "add element "+family+" "+ownedTable+" "+item.name+" {"+strings.Join(item.values, ",")+"}")
				}
			}
			beforeForward := guardFamilyCounter(ctx, t, "inet", ownedTable, "handoff_completed")
			if family == "netdev" {
				transmit(nativeReturn, device, translated, true, false)
				beforeReply := guardFamilyCounter(ctx, t, "inet", ownedTable, "return_handoff_completed")
				returnPacket(rawReturn, false)
				transmit(original, peer, translated, true, false)
				transmit(wire, translated, device, false, true)
				if guardFamilyCounter(ctx, t, "inet", ownedTable, "handoff_completed") != beforeForward+1 || guardFamilyCounter(ctx, t, "inet", ownedTable, "return_handoff_completed") != beforeReply+1 {
					t.Fatal("classification denial lost early positive controls")
				}
			} else {
				transmit(nativeReturn, device, translated, false, false)
				returnPacket(rawReturn, false)
				transmit(original, peer, translated, true, false)
				transmit(wire, translated, device, false, true)
			}
			// Fault isolation only: a deployed history publisher never removes members.
			packetNft(ctx, t, "flush set "+family+" "+ownedTable+" "+classified4Set+"; flush set "+family+" "+ownedTable+" "+classified6Set)
			transmit(original, peer, translated, true, false)
			transmit(wire, translated, device, true, true)
			transmit(nativeReturn, device, translated, true, false)
			returnPacket(rawReturn, true)
		}
	}
	// An epoch with no matching geometry channel fails closed until both
	// compiler-local proofs have been published for that same configuration.
	publish(18, false)
	transmit(nativeReturn, device, translated, false, false)
	returnPacket(rawReturn, false)
	original.sourcePort, wire.sourcePort = 52000, 52000
	transmit(original, peer, translated, true, false)
	transmit(wire, translated, device, false, true)
	publish(18, true)
	transmit(original, peer, translated, true, false)
	transmit(wire, translated, device, true, true)
	newNativeReturn, newRawReturn := nativeReturn, rawReturn
	newNativeReturn.destinationPort, newRawReturn.destinationPort = 52000, 52000
	transmit(newNativeReturn, device, translated, true, false)
	returnPacket(newRawReturn, true)
	transmit(nativeReturn, device, translated, false, false)
	returnPacket(rawReturn, false)
}

func inspectStaticFixtureGraph(ctx context.Context, t *testing.T, sources *nativeNAT46StaticSources, family string, handoff map[string][]nativeScope) error {
	t.Helper()
	schema, _, err := sources.staticInventory(ctx, family)
	if err != nil {
		return err
	}
	if family == "inet" {
		for name, rules := range handoff {
			schema.chains[name] = map[string]any{"family": family, "table": ownedTable, "name": name}
			schema.rules[name] = nativeRulesExpressions(rules)
		}
	} else {
		schema.chains["static_source"] = map[string]any{"family": family, "table": ownedTable, "name": "static_source"}
		schema.rules["static_source"] = nativeRulesExpressions(nat46StaticPhysical(false))
		schema.chains["static_return"] = map[string]any{"family": family, "table": ownedTable, "name": "static_return"}
		schema.rules["static_return"] = nativeRulesExpressions(nat46StaticPhysical(true))
	}
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", family, ownedTable), &listing); err != nil {
		return err
	}
	observed := &guardTableObservation{sets: map[string]listedSet{}}
	headers, counts := map[string]bool{}, map[string]int{}
	for _, raw := range listing.Objects[2:] {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		if _, counter := object["counter"]; counter {
			continue // Named counters belong only to the synthetic caller.
		}
		kind, fields, err := guardObject(raw)
		if err != nil {
			return err
		}
		var name string
		key := "name"
		if kind == "rule" {
			key = "chain"
		}
		if err := json.Unmarshal(fields[key], &name); err != nil {
			return err
		}
		var expected map[string]any
		switch kind {
		case "set":
			expected = schema.sets[name]
		case "map":
			expected = schema.maps[name]
		case "chain":
			expected = schema.chains[name]
		case "rule":
			if rules, exists := schema.rules[name]; exists {
				if counts[name] >= len(rules) {
					return fmt.Errorf("unexpected static source rule: %s", name)
				}
				expected = map[string]any{"family": family, "table": ownedTable, "chain": name, "expr": rules[counts[name]]}
				counts[name]++
			}
		}
		if expected == nil {
			continue // Synthetic callers and the transport have independent graphs.
		}
		if kind == "set" || kind == "map" {
			value := listedSet{}
			if elements, exists := fields["elem"]; exists {
				if err := json.Unmarshal(elements, &value.Elements); err != nil {
					return err
				}
			}
			observed.sets[name] = value
		}
		if _, err := checkGuardObject(fields, expected, kind == "set" || kind == "map"); err != nil {
			return fmt.Errorf("static source graph differs for %s: %w; actual=%s", name, err, raw)
		}
		if kind != "rule" {
			if headers[name] {
				return fmt.Errorf("duplicate static source object: %s", name)
			}
			headers[name] = true
		}
	}
	for _, collection := range []map[string]map[string]any{schema.sets, schema.maps, schema.chains} {
		for name := range collection {
			if !headers[name] {
				return fmt.Errorf("missing static source object: %s", name)
			}
		}
	}
	for name, rules := range schema.rules {
		if counts[name] != len(rules) {
			return fmt.Errorf("missing static source rule: %s", name)
		}
	}
	return sources.inspectStaticIdentities(ctx, family, observed)
}
