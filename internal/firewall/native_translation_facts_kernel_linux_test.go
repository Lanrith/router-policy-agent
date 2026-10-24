//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// These callers supply current permission independently of the fact program.
// No translator, NAS publisher or complete private router is activated here.
func TestKernelNamedTranslationFacts(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	facts, err := nativeTranslationFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const table = ownedTable
	lines := []string{"table inet " + table + " {",
		"set current_epoch {type mark;size 1;elements={0xfffffc00};}",
		"set current_permission {type mark . classid;size 64;}",
		"map caller_epoch {type nf_proto : mark;elements={ipv4:0xfffffc09,ipv6:0xfffffc09};}",
		"map caller_context {type nf_proto : mark;size 2;}",
		"map caller_channel {type nf_proto : classid;size 2;}"}
	lines = append(lines, ownerPriorityRules(false)...)
	for _, name := range nativeChainNames(facts) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(facts[name])...)
		lines = append(lines, "}")
	}
	lines = append(lines, `chain seed_allocation {
 ct status & confirmed == 0 ct label set (0 | 7 | 31 | 100)
 }
 chain capture_gate {jump native_translation_facts_capture;}
 chain current_checks {
 ct mark & 0xfffffc00 @current_epoch (meta mark & 0xff00e3ff) . meta priority @current_permission return
 drop
 }
 chain original {
 ct mark 0 ct state new ct mark set meta nfproto map @caller_epoch
 meta mark set meta nfproto map @caller_context
 meta priority set meta nfproto map @caller_channel
 jump current_checks
 jump seed_allocation
 jump capture_gate
 ct label & (0 | 7 | 31 | 100) != (0 | 7 | 31 | 100) drop
 accept
 }
 chain reply {
 meta mark set 0x009f0000
 meta priority set 3
 jump native_translation_facts_restore
 jump current_checks
 ct label & (0 | 7 | 31 | 100) != (0 | 7 | 31 | 100) drop
 accept
 }
 chain forward {type filter hook forward priority 0;policy drop;
 iifname "lan10" oifname "lan13" udp dport 6061 goto original
 iifname "lan10" oifname "lan13" tcp dport 6061 goto original
 iifname "lan13" oifname "lan10" udp sport 6061 goto reply
 iifname "lan13" oifname "lan10" tcp sport 6061 goto reply
 }
}`)
	lines = append(lines, "table netdev translation_facts_fixture {", "counter request_properties {}", "counter reply_properties {}")
	lines = append(lines, ownerPriorityRules(true)...)
	lines = append(lines, `chain peer_input {type filter hook ingress device "peer0" priority 0;policy drop;}
 chain device_input {type filter hook ingress device "device0" priority 0;policy drop;}
 chain request_final {type filter hook egress device "lan13" priority 0;policy accept;
 meta mark set meta mark & 0xffff1fff
 goto restore_owner_priority
 }
 chain reply_final {type filter hook egress device "lan10" priority 0;policy accept;
 meta mark set meta mark & 0xffff1fff
 goto restore_owner_priority
 }
 chain request_observed {type filter hook egress device "lan13" priority 1;policy accept;
 meta mark & 0x00ff0000 == 0x006a0000 meta priority 5 counter name request_properties
 }
 chain reply_observed {type filter hook egress device "lan10" priority 1;policy accept;
 meta mark & 0x00ff0000 == 0x009f0000 meta priority 3 counter name reply_properties
 }
}`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+table+";delete table netdev translation_facts_fixture")
	})
	inspectTranslationFactsFixture(ctx, t, facts)
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	serial := 0
	transmit := func(value packetDatagram, reply, allowed bool) {
		t.Helper()
		serial++
		value.payload = fmt.Sprintf("immutable-facts-%04d", serial)
		input, output, counter := peer, device, "request_properties"
		if reply {
			input, output, counter = device, peer, "reply_properties"
		}
		before := guardFamilyCounter(ctx, t, "netdev", "translation_facts_fixture", counter)
		sendPacket(ctx, t, input, packetFrame(t, value))
		if allowed {
			receivePacket(ctx, t, output, packetFrame(t, value), true)
			if next := guardFamilyCounter(ctx, t, "netdev", "translation_facts_fixture", counter); next != before+1 {
				t.Fatal("fact handoff lost current packet QoS or standard priority", counter, before, next)
			}
		} else {
			rejectNATPayload(ctx, t, output, value.payload)
		}
	}
	permissions := map[string]bool{}
	configure := func(mark, priority uint32) {
		t.Helper()
		for _, current := range []uint32{mark, (mark & 0x00ffffff) | ((mark & 0xff000000) + 0x01000000)} {
			permissions[fmt.Sprintf("%#x . %s", current&nativeFactsMask, epochClassID(priority))] = true
		}
		rows := make([]string, 0, len(permissions))
		for row := range permissions {
			rows = append(rows, row)
		}
		slices.Sort(rows)
		packetNft(ctx, t, fmt.Sprintf("flush map inet %s caller_context\nadd element inet %s caller_context {ipv4:%#x,ipv6:%#x}\nflush map inet %s caller_channel\nadd element inet %s caller_channel {ipv4:%s,ipv6:%s}\nflush set inet %s current_permission\nadd element inet %s current_permission {%s}",
			table, table, mark, mark, table, table, epochClassID(priority), epochClassID(priority), table, table, strings.Join(rows, ",")))
	}
	port := uint16(43000)
	var original, response packetDatagram
	for _, family := range []int{4, 6} {
		for _, tcp := range []bool{false, true} {
			for _, tag := range []uint32{0xd1000000, 0xd3000000, 0xd5000000, 0xf1000000, 0xf3000000, 0xf5000000} {
				port++
				mark, priority := tag|0x006a1401, uint32(0xfffffc01)
				configure(mark, priority)
				source, target := "10.240.0.10", "10.240.3.10"
				if family == 6 {
					source, target = "fdca:1a2b::10", "fdca:1a2b:3::10"
				}
				original = packetDatagram{source: netip.MustParseAddr(source), destination: netip.MustParseAddr(target),
					sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: port,
					destinationPort: 6061, isTCP: tcp, tcpFlags: 2}
				response = packetDatagram{source: original.destination, destination: original.source,
					sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13", sourcePort: 6061,
					destinationPort: port, isTCP: tcp, tcpFlags: 18}
				transmit(original, false, true)
				transmit(response, true, true)
			}
		}
	}
	// Saturate both identity halves and all epoch bits on a fresh UDP flow.
	configure(0xf36af7ff, 0xffffffff)
	original.isTCP, response.isTCP = false, false
	original.sourcePort, response.destinationPort = port+1, port+1
	transmit(original, false, true)
	transmit(response, true, true)
	time.Sleep(2200 * time.Millisecond)
	transmit(response, true, true)
	packetNft(ctx, t, "flush chain netdev translation_facts_fixture request_observed\n"+
		"add rule netdev translation_facts_fixture request_observed meta mark & 0x00ff0000 == 0x002d0000 meta priority 2 counter name request_properties")
	configure((0xf36af7ff&^uint32(0x00ff1c00))|0x002d0800, 0xffffffff)
	transmit(original, false, true)
	transmit(response, true, true)
	packetNft(ctx, t, "flush chain netdev translation_facts_fixture request_observed\n"+
		"add rule netdev translation_facts_fixture request_observed meta mark & 0x00ff0000 == 0x006a0000 meta priority 5 counter name request_properties")
	configure(0xf36af7ff, 0xffffffff)
	for _, change := range []struct{ mark, priority uint32 }{
		{0xf36af7fe, 0xffffffff}, // Saved ingress/MAC policy class.
		{0xf36ad7ff, 0xffffffff}, // High source identity.
		{0xf36af7ff, 0xfffffffe}, // Low source identity.
		{0xd56af7ff, 0xffffffff}, // Authorization/identity namespace.
	} {
		configure(change.mark, change.priority)
		transmit(original, false, false)
		fresh := original
		fresh.sourcePort += 100
		transmit(fresh, false, true)
		// Each different fresh context must use a new connection too.
		original.sourcePort++
		response.destinationPort = original.sourcePort
		configure(0xf36af7ff, 0xffffffff)
		transmit(original, false, true)
		transmit(response, true, true)
	}
	packetNft(ctx, t, "flush set inet "+table+" current_permission")
	transmit(response, true, false)
	configure(0xf36af7ff, 0xffffffff)
	transmit(response, true, true)
	packetNft(ctx, t, "flush set inet "+table+" current_epoch")
	transmit(response, true, false)
	packetNft(ctx, t, "add element inet "+table+" current_epoch {0xfffffc00}")
	transmit(response, true, true)
	// A confirmed legacy connection cannot acquire a later metadata snapshot.
	packetNft(ctx, t, "flush chain inet "+table+" capture_gate")
	original.sourcePort += 200
	response.destinationPort = original.sourcePort
	transmit(original, false, true)
	packetNft(ctx, t, "add rule inet "+table+" capture_gate jump native_translation_facts_capture")
	transmit(original, false, false)
	transmit(response, true, false)
	original.sourcePort++
	response.destinationPort++
	transmit(original, false, true)
	transmit(response, true, true)
	packetNft(ctx, t, "flush chain inet "+table+" seed_allocation\n"+
		"add rule inet "+table+" seed_allocation ct status & confirmed == 0 ct label set (0 | 7 | 31 | 32 | 100)")
	original.sourcePort++
	response.destinationPort++
	transmit(original, false, false)
	packetNft(ctx, t, "flush chain inet "+table+" seed_allocation\n"+
		"add rule inet "+table+" seed_allocation ct status & confirmed == 0 ct label set (0 | 7 | 31 | 100)")
	transmit(original, false, true)
	transmit(response, true, true)
}

func inspectTranslationFactsFixture(ctx context.Context, t *testing.T, facts map[string][]nativeScope) {
	t.Helper()
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", "inet", ownedTable), &listing); err != nil {
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
			expected = map[string]any{"family": "inet", "table": ownedTable, "name": name}
			headers[name] = true
		} else if kind == "rule" && counts[name] < len(rules) {
			expected = map[string]any{"family": "inet", "table": ownedTable, "chain": name, "expr": rules[counts[name]].expressions}
			counts[name]++
		}
		if _, err := checkGuardObject(fields, expected, false); err != nil {
			t.Fatalf("immutable translation facts graph differs for %s: %v; actual=%s", name, err, raw)
		}
	}
	for name, rules := range facts {
		if !headers[name] || counts[name] != len(rules) {
			t.Fatal("immutable translation facts graph is incomplete", name)
		}
	}
}
