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
)

// This qualifies metadata transport, with an independent synthetic caller
// checking grants. It does not install shared router-policy translator hooks.
func TestKernelNamedNAT46TupleTransport(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "link", "add", "nat46", "type", "veth", "peer", "name", "translated0")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "nat46")
	})
	for _, e := range []struct{ name, mac string }{{"nat46", "02:00:00:00:01:46"}, {"translated0", "02:00:00:00:00:46"}} {
		packetIP(ctx, t, "link", "set", e.name, "address", e.mac)
		packetIP(ctx, t, "link", "set", e.name, "up")
	}
	b := nativeAccessBaseline(t)
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	for i := range 6 {
		alias := netip.MustParseAddr(fmt.Sprintf("10.250.0.%d", 20+i))
		target := netip.MustParseAddr(fmt.Sprintf("fdca:1a2b:3::%x", 16+i))
		b.NAT46 = append(b.NAT46, policy.NAT46{ID: fmt.Sprintf("mapped%d", i), Alias: alias, Target: target, Ready: true})
		packetIP(ctx, t, "neighbor", "replace", alias.String(), "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
		packetIP(ctx, t, "neighbor", "replace", target.String(), "dev", "lan13", "lladdr", "02:00:00:00:00:13", "nud", "permanent")
	}
	embedded := netip.MustParseAddr("fdca:1a2b:e046::af0:a")
	packetIP(ctx, t, "route", "add", "10.250.0.0/24", "dev", "nat46")
	packetIP(ctx, t, "-6", "route", "add", prefix.String(), "dev", "nat46")
	packetIP(ctx, t, "neighbor", "replace", embedded.String(), "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
	model, err := newNativeNAT46Model(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newNativeNAT46Transport(ctx, model)
	if err != nil {
		t.Fatal(err)
	}
	const table = ownedTable
	lines := []string{"table inet " + table + " {",
		"set " + ownershipEpochSet + " { type mark; elements={0x1c00}; }",
		"set " + configurationEpochSet + " { type mark; elements={0xc00}; }",
		"set " + nativeSourceBits4 + " { typeof meta mark . meta priority . @nh,96,32; elements={0 . 0:1 . 0x0af0000a}; }",
		"set current_grants { type classid . mark . ipv4_addr . inet_service; }",
		"chain epoch_stamp {ct mark 0 ct mark set 0x1c03; return;}",
		"chain original_stamp { meta l4proto icmp meta mark set 0xd1000001 meta priority set 0x1c01 return; meta mark set 0xd5000001 meta priority set 0x1c01; return;}",
		"chain reply_stamp {meta l4proto ipv6-icmp meta mark set 0xd2000001 meta priority set 0x1c01 return; meta mark set 0xd6000001 meta priority set 0x1c01; return;}"}
	lines = append(lines, transport.definitions()...)
	chains := transport.chains()
	for _, name := range nativeChainNames(chains) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(chains[name])...)
		lines = append(lines, "}")
	}
	forward := []string{"chain forward {type filter hook forward priority 0;policy drop;"}
	for _, leg := range transport.legs {
		stamp := "original_stamp"
		if leg.reply {
			stamp = "reply_stamp"
		}
		exportCaller := leg.name + "_export_caller"
		forward = append(forward, leg.geometry(false).text+" goto "+exportCaller)
		lines = append(lines, "chain "+exportCaller+" {", "jump epoch_stamp", "jump "+stamp, "jump "+leg.name+"_export", "accept", "}")
		// A positive proof does not bypass the independent caller's listener/grant
		// check. The IPv4 alias stays in the key while the actual packet is IPv6.
		port := "dport"
		if leg.reply {
			port = "sport"
		}
		caller := leg.name + "_caller"
		importCaller := leg.name + "_import_caller"
		forward = append(forward, leg.geometry(true).text+" goto "+importCaller)
		lines = append(lines, "chain "+importCaller+" {", "jump "+leg.name+"_import", "jump "+caller, "accept", "}")
		lines = append(lines, "chain "+caller+" {")
		if leg.protocol == "icmp" {
			lines = append(lines, fmt.Sprintf("meta mark & 0xff000000 == %#x return", nativeTag(false, leg.reply)), fmt.Sprintf("meta mark & 0xff000000 == %#x return", nativeTag(true, leg.reply)))
		} else {
			lines = append(lines, fmt.Sprintf("meta mark & 0xff000000 == %#x meta priority . (meta mark & 0xe000) . %s . %s %s @current_grants return", nativeDirectoryTag(leg.reply), leg.mapping.alias, leg.protocol, port))
			lines = append(lines, fmt.Sprintf("meta mark & 0xff000000 == %#x %s %s 6061 return", nativeTag(true, leg.reply), leg.protocol, port))
		}
		lines = append(lines, "drop", "}")
	}
	forward = append(forward, "}")
	lines = append(lines, forward...)
	lines = append(lines, "}", "table netdev "+table+" {")
	lines = append(lines, nativeSourceDefinitions("netdev")...)
	lines = append(lines, epochChannelDefinitions(false, "netdev")...)
	for _, leg := range transport.legs {
		lines = append(lines, "chain "+leg.name+"_physical {")
		lines = append(lines, nativeRulesText(leg.sourcePhysical())...)
		lines = append(lines, "}")
	}
	lines = append(lines, "chain physical_scope {",
		// Separate synthetic static caller: static geometry has its own
		// independently qualified production namespace and predicates.
		"meta mark & 0xff00e3ff == 0xd3000001 meta priority 0xc00 return")
	for _, leg := range transport.legs {
		if leg.protocol != "udp" {
			continue
		}
		if leg.reply {
			lines = append(lines, "ip saddr "+leg.mapping.alias.String()+" goto "+leg.name+"_physical")
		} else {
			lines = append(lines, "ip6 daddr "+leg.mapping.target.String()+" goto "+leg.name+"_physical")
		}
	}
	lines = append(lines, "drop", "}")
	for _, device := range []string{"lan10", "lan13"} {
		lines = append(lines, fmt.Sprintf("chain mutate_%s {type filter hook egress device %q priority -1;policy accept;}", device, device),
			fmt.Sprintf("chain final_%s {type filter hook egress device %q priority 0;policy accept;meta mark & 0xff000000 != 0 jump physical_scope;}", device, device))
	}
	lines = append(lines, "}", `table netdev nat46_transport_endpoints {
 chain peer {type filter hook ingress device "peer0" priority 0;policy drop;}
 chain fixture_device {type filter hook ingress device "device0" priority 0;policy drop;}
 chain fixture_translator {type filter hook ingress device "translated0" priority 0;policy drop;}
}`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+table+"; delete table netdev "+table+"; delete table netdev nat46_transport_endpoints")
	})
	packetNft(ctx, t, "add element netdev "+table+" "+nativeSourceBits4+" {0 . 0:1 . 0x0af0000a}; add element netdev "+table+" "+nativeSource4+" {0 . 0:1 . 10.240.0.10}; add element netdev "+table+" ownership_egress_epoch {0x1c00}")
	inspectNAT46PhysicalFixture(ctx, t, transport)
	inspectNAT46TransportFixture(ctx, t, transport)
	peer, device, translated := packetSocket(t, "peer0"), packetSocket(t, "device0"), packetSocket(t, "translated0")
	serial := 0
	transmit := func(value packetDatagram, input, output packetEndpoint, allowed bool) {
		t.Helper()
		serial++
		value.payload = fmt.Sprintf("n46-proof-%d", serial)
		sendPacket(ctx, t, input, packetFrame(t, value))
		if allowed {
			receivePacket(ctx, t, output, packetFrame(t, value), true)
		} else {
			rejectNATPayload(ctx, t, output, value.payload)
		}
	}
	var initial, wire packetDatagram
	for i, mapping := range model.mappings {
		for _, tcp := range []bool{false, true} {
			initial = packetDatagram{source: netip.MustParseAddr("10.240.0.10"), destination: mapping.alias, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: 45000 + uint16(i), destinationPort: 6061, isTCP: tcp, tcpFlags: 2}
			wire = initial
			wire.source, wire.destination = embedded, mapping.target
			wire.sourceMAC, wire.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
			// An unsolicited callback cannot acquire a reply proof.
			callback := wire
			callback.source, callback.destination = wire.destination, wire.source
			callback.sourcePort, callback.destinationPort = wire.destinationPort, wire.sourcePort
			callback.sourceMAC, callback.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
			callback.tcpFlags = 18
			transmit(callback, device, translated, false)
			// No export, and then a valid export without a grant, both deny.
			transmit(wire, translated, device, false)
			transmit(initial, peer, translated, true)
			transmit(wire, translated, device, false)
			packetNft(ctx, t, fmt.Sprintf("add element inet %s current_grants { 0x1c01 . 0 . %s . 6061 }", table, mapping.alias))
			transmit(initial, peer, translated, true)
			transmit(wire, translated, device, true)
			reply := wire
			reply.source, reply.destination = wire.destination, wire.source
			reply.sourcePort, reply.destinationPort = wire.destinationPort, wire.sourcePort
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
			reply.tcpFlags = 18
			transmit(reply, device, translated, true)
			returned := reply
			returned.source, returned.destination = mapping.alias, initial.source
			returned.sourceMAC, returned.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
			transmit(returned, translated, peer, true)
			if i == 0 && !tcp {
				packetNft(ctx, t, "flush set netdev "+table+" "+nativeSource4)
				transmit(returned, translated, peer, false)
				packetNft(ctx, t, "add element netdev "+table+" "+nativeSource4+" {0 . 0:1 . 10.240.0.10,0 . 0:2 . 10.240.0.11}")
				for _, mutation := range []string{"ip daddr set 10.240.0.11", "meta priority set 0x1c02", "meta mark set 0xd6002001"} {
					packetNft(ctx, t, "add rule netdev "+table+" mutate_lan10 "+mutation)
					transmit(returned, translated, peer, false)
					packetNft(ctx, t, "flush chain netdev "+table+" mutate_lan10")
				}
				transmit(reply, device, translated, true)
				transmit(returned, translated, peer, true)
			}
			packetNft(ctx, t, "flush set inet "+table+" current_grants")
		}
	}
	// Echo uses its unchanged identifier and sequence, never TCP/UDP grants.
	for i, mapping := range model.mappings {
		original := packetDatagram{source: netip.MustParseAddr("10.240.0.10"), destination: mapping.alias, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", isICMP: true, icmpType: 8, icmpData: 0xc0460001 + uint32(i<<16)}
		converted := original
		converted.source, converted.destination = embedded, mapping.target
		converted.sourceMAC, converted.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
		converted.icmpType = 128
		transmit(converted, translated, device, false)
		transmit(original, peer, translated, true)
		transmit(converted, translated, device, true)
		reply := converted
		reply.source, reply.destination = converted.destination, converted.source
		reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
		reply.icmpType = 129
		transmit(reply, device, translated, true)
		returned := reply
		returned.source, returned.destination = mapping.alias, original.source
		returned.sourceMAC, returned.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
		returned.icmpType = 0
		transmit(returned, translated, peer, true)
		changed := converted
		changed.icmpData ^= 1
		transmit(changed, translated, device, false)
		changed = converted
		changed.icmpData ^= 1 << 16
		transmit(changed, translated, device, false)
		changed = converted
		changed.icmpType = 1
		changed.icmpCode = 3
		transmit(changed, translated, device, false)
	}
	packetNft(ctx, t, fmt.Sprintf("add element inet %s current_grants {0x1c01 . 0 . %s . 6061}", table, initial.destination))
	// Use a fresh UDP tuple for independent negative controls.
	initial.isTCP, initial.sourcePort = false, 46000
	wire.isTCP, wire.sourcePort = false, 46000
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	for _, change := range []string{"client", "port", "listener", "target", "prefix", "interface"} {
		wrong := wire
		input := translated
		switch change {
		case "client":
			wrong.source = wrong.source.Next()
		case "port":
			wrong.sourcePort++
		case "listener":
			wrong.destinationPort++
		case "target":
			wrong.destination = netip.MustParseAddr("fdca:1a2b:3::10")
		case "prefix":
			wrong.source = netip.MustParseAddr("fdca:1a2b:e047::af0:a")
		case "interface":
			input = peer
			wrong.sourceMAC, wrong.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
		}
		transmit(wrong, input, device, false)
	}
	var active nativeNAT46Leg
	for _, leg := range transport.legs {
		if !leg.reply && leg.protocol == "udp" && leg.mapping.alias == initial.destination {
			active = leg
		}
	}
	// Keep the inet tuple, grant and source proof valid, then revoke only the
	// physical mirror. Earlier admission must not carry stale source authority.
	packetNft(ctx, t, "flush set netdev "+table+" "+nativeSourceBits4)
	transmit(wire, translated, device, false)
	packetNft(ctx, t, "add element netdev "+table+" "+nativeSourceBits4+" {0 . 0:1 . 0x0af0000a}")
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	packetNft(ctx, t, "flush set netdev "+table+" "+nativeSourceBits4+"; add element netdev "+table+" "+nativeSourceBits4+" {0 . 0:1 . 0x0af0000a timeout 1s}")
	time.Sleep(1200 * time.Millisecond)
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, false)
	packetNft(ctx, t, "add element netdev "+table+" "+nativeSourceBits4+" {0 . 0:1 . 0x0af0000a}")
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	// A different address may be live under its own UID, but the old carried
	// UID cannot use it after the translated packet passed the inet checks.
	packetNft(ctx, t, "add element netdev "+table+" "+nativeSourceBits4+" {0 . 0:2 . 0x0af0000b}")
	for _, mutation := range []string{
		"ip6 saddr set fdca:1a2b:e046::af0:b",
		"meta priority set 0x1c02",
		"meta mark set 0xd5002001",
		"meta mark set 0xd3000001",
	} {
		packetNft(ctx, t, "add rule netdev "+table+" mutate_lan13 "+mutation)
		transmit(wire, translated, device, false)
		packetNft(ctx, t, "flush chain netdev "+table+" mutate_lan13")
	}
	packetNft(ctx, t, "flush set netdev "+table+" ownership_egress_epoch")
	transmit(wire, translated, device, false)
	packetNft(ctx, t, "add element netdev "+table+" ownership_egress_epoch {0x1c00}")
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	packetNft(ctx, t, "flush map inet "+table+" "+active.name+"_context")
	transmit(wire, translated, device, false)
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	packetNft(ctx, t, "flush map inet "+table+" "+active.name+"_channel; add element inet "+table+" "+active.name+"_channel {0x0af0000a . 46000 . 6061 : 0x2001}")
	transmit(wire, translated, device, false)
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	packetNft(ctx, t, "flush set inet "+table+" current_grants")
	transmit(wire, translated, device, false)
	packetNft(ctx, t, fmt.Sprintf("add element inet %s current_grants {0x1c01 . 0 . %s . 6061}", table, initial.destination))
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	packetNft(ctx, t, "flush set inet "+table+" "+nativeSourceBits4)
	transmit(wire, translated, device, false)
	packetNft(ctx, t, "add element inet "+table+" "+nativeSourceBits4+" {0 . 0:1 . 0x0af0000a}")
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	time.Sleep(2200 * time.Millisecond)
	transmit(wire, translated, device, false)
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	packetNft(ctx, t, "flush set inet "+table+" "+ownershipEpochSet+"; add element inet "+table+" "+ownershipEpochSet+" {0x2000}")
	transmit(wire, translated, device, false)
	// An existing translated connection must not be restamped with a newer epoch.
	packetNft(ctx, t, "flush chain inet "+table+" epoch_stamp; add rule inet "+table+" epoch_stamp ct mark 0 ct mark set 0x2003; add rule inet "+table+" epoch_stamp return")
	initial.sourcePort = 47000
	transmit(initial, peer, translated, false)
	wire.sourcePort = 47000
	transmit(wire, translated, device, false) // old source publication/grant cannot follow the new epoch
	// Simulate retirement and replacement of only the raw IPv4 connection.
	// The translated IPv6 connection deliberately retains its positive old mark.
	// This fault rule is test-only; production never restamps positive CT marks.
	packetNft(ctx, t, "flush chain inet "+table+" epoch_stamp; add rule inet "+table+" epoch_stamp ct mark set 0x2003 return; flush chain inet "+table+" original_stamp; add rule inet "+table+" original_stamp meta mark set 0xd5000001 meta priority set 0x2001 return")
	packetNft(ctx, t, fmt.Sprintf("add element inet %s current_grants {0x2001 . 0 . %s . 6061}", table, initial.destination))
	initial.sourcePort = 46000
	transmit(initial, peer, translated, true)
	wire.sourcePort = 46000
	transmit(wire, translated, device, false)
	packetNft(ctx, t, "flush set netdev "+table+" ownership_egress_epoch; add element netdev "+table+" ownership_egress_epoch {0x2000}")
	initial.sourcePort = 47000
	transmit(initial, peer, translated, true)
	wire.sourcePort = 47000
	transmit(wire, translated, device, true)
	wire.sourcePort = 46000
	transmit(wire, translated, device, false)
	// Exercise a high source-ID group and high epoch bits independently of
	// the low-ID controls, including a zero low source-ID field.
	packetNft(ctx, t, "flush set inet "+table+" "+ownershipEpochSet+"; add element inet "+table+" "+ownershipEpochSet+" {0x10000400}; flush set inet "+table+" "+nativeSourceBits4+"; add element inet "+table+" "+nativeSourceBits4+" {0x8000 . none . 0x0af0000a}; flush chain inet "+table+" epoch_stamp; add rule inet "+table+" epoch_stamp ct mark 0 ct mark set 0x10000403; add rule inet "+table+" epoch_stamp return; flush chain inet "+table+" original_stamp; add rule inet "+table+" original_stamp meta mark set 0xd5008001 meta priority set 0x10000400 return")
	packetNft(ctx, t, fmt.Sprintf("add element inet %s current_grants {0x10000400 . 0x8000 . %s . 6061}", table, initial.destination))
	packetNft(ctx, t, "flush set netdev "+table+" "+nativeSourceBits4+"; add element netdev "+table+" "+nativeSourceBits4+" {0x8000 . none . 0x0af0000a}; flush set netdev "+table+" ownership_egress_epoch; add element netdev "+table+" ownership_egress_epoch {0x10000400}")
	initial.sourcePort = 49000
	wire.sourcePort = 49000
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
	packetNft(ctx, t, "flush set inet "+table+" "+nativeSourceBits4)
	transmit(wire, translated, device, false)
	// A static owner caller uses its separate configuration epoch and no source
	// or grant evidence. This still requires a fresh exact tuple proof.
	packetNft(ctx, t, "flush chain inet "+table+" epoch_stamp; add rule inet "+table+" epoch_stamp ct mark 0 ct mark set 0xc03; add rule inet "+table+" epoch_stamp return; flush chain inet "+table+" original_stamp; add rule inet "+table+" original_stamp meta mark set 0xd3000001 meta priority set 0xc00 return; flush set inet "+table+" "+nativeSourceBits4)
	initial.sourcePort = 48000
	wire.sourcePort = 48000
	transmit(wire, translated, device, false)
	transmit(initial, peer, translated, true)
	transmit(wire, translated, device, true)
}

func inspectNAT46PhysicalFixture(ctx context.Context, t *testing.T, transport *nativeNAT46Transport) {
	t.Helper()
	facts := map[string][]nativeScope{}
	for _, leg := range transport.legs {
		facts[leg.name+"_physical"] = leg.sourcePhysical()
	}
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", "netdev", ownedTable), &listing); err != nil {
		t.Fatal(err)
	}
	counts, headers := map[string]int{}, map[string]bool{}
	for _, raw := range listing.Objects[2:] {
		kind, fields, err := guardObject(raw)
		if err != nil {
			t.Fatal(err)
		}
		var name string
		field := "name"
		if kind == "rule" {
			field = "chain"
		}
		if err := json.Unmarshal(fields[field], &name); err != nil {
			t.Fatal(err)
		}
		rules, exists := facts[name]
		if !exists {
			continue
		}
		var expected map[string]any
		if kind == "chain" {
			expected = map[string]any{"family": "netdev", "table": ownedTable, "name": name}
			headers[name] = true
		} else if kind == "rule" && counts[name] < len(rules) {
			expected = map[string]any{"family": "netdev", "table": ownedTable, "chain": name, "expr": rules[counts[name]].expressions}
			counts[name]++
		}
		if _, err := checkGuardObject(fields, expected, false); err != nil {
			t.Fatalf("physical nat46 source graph differs for %s: %v; actual=%s", name, err, raw)
		}
	}
	for name, rules := range facts {
		if !headers[name] || counts[name] != len(rules) {
			t.Fatal("physical nat46 source graph is incomplete", name)
		}
	}
}

func inspectNAT46TransportFixture(ctx context.Context, t *testing.T, transport *nativeNAT46Transport) {
	t.Helper()
	const table = ownedTable
	// Verify the production body's complete graph against the actual kernel
	// listing. Synthetic caller scopes are deliberately outside this schema.
	schema := transport.schema()
	var listed struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", "inet", table), &listed); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	headers := map[string]bool{}
	for _, raw := range listed.Objects[2:] {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		if _, counter := object["counter"]; counter {
			continue // Named counters belong only to the synthetic caller.
		}
		kind, fields, err := guardObject(raw)
		if err != nil {
			t.Fatal(err)
		}
		var name string
		field := "name"
		if kind == "rule" {
			field = "chain"
		}
		if err := json.Unmarshal(fields[field], &name); err != nil {
			t.Fatal(err)
		}
		var expected map[string]any
		switch kind {
		case "map":
			expected = schema.maps[name]
		case "set":
			expected = schema.sets[name]
		case "chain":
			expected = schema.chains[name]
		case "rule":
			if _, exists := schema.rules[name]; !exists {
				continue
			}
			if counts[name] >= len(schema.rules[name]) {
				t.Fatal("unexpected transport rule", name)
			}
			expected = map[string]any{"family": "inet", "table": table, "chain": name, "expr": schema.rules[name][counts[name]]}
			counts[name]++
		}
		if expected == nil {
			continue
		}
		if _, err := checkGuardObject(fields, expected, kind == "map" || kind == "set"); err != nil {
			want, _ := json.Marshal(expected)
			t.Fatalf("transport graph differs for %s: %v; expected=%s actual=%s", name, err, want, raw)
		}
		if kind != "rule" {
			headers[name] = true
		}
	}
	for _, collection := range []map[string]map[string]any{schema.maps, schema.sets, schema.chains} {
		for name := range collection {
			if !headers[name] {
				t.Fatal("missing transport header", name)
			}
		}
	}
	for name, rules := range schema.rules {
		if counts[name] != len(rules) {
			t.Fatal("missing transport rules", name)
		}
	}
}
