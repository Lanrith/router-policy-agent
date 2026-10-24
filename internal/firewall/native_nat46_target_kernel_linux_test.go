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

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// These synthetic metadata callers isolate the current mapped IPv6 ownership
// fact, including after the return becomes IPv4. They grant no shared runtime
// admission and do not qualify source identity or a live binding producer.
func TestKernelNamedNAT46TargetOwnership(t *testing.T) {
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
	for _, link := range []struct{ name, mac string }{{"nat46", "02:00:00:00:01:46"}, {"translated0", "02:00:00:00:00:46"}} {
		packetIP(ctx, t, "link", "set", link.name, "address", link.mac)
		packetIP(ctx, t, "link", "set", link.name, "up")
	}
	b := nativeAccessBaseline(t)
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	target, alias := netip.MustParseAddr("fdca:1a2b:3::10"), netip.MustParseAddr("10.250.0.20")
	b.NAT46 = []policy.NAT46{{ID: "mapped", Alias: alias, Target: target, Ready: true}}
	model, err := newNativeNAT46Model(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	forward := nativeNAT46Leg{mapping: model.mappings[0], prefix: prefix, protocol: "udp"}
	reply := forward
	reply.reply = true
	lines := []string{"table inet " + ownedTable + " {"}
	lines = append(lines, ownershipDefinitions("inet")...)
	lines = append(lines, ownershipEpochDefinitions()...)
	lines = append(lines, epochChannelDefinitions(false, "inet")...)
	lines = append(lines, nativeSourceDefinitions("inet")...)
	lines = append(lines, "chain stamp {meta mark set 0xd1000001 meta priority set 0x1c01;}", "counter early {}", `chain admitted {type filter hook forward priority 150;policy accept;jump stamp;counter name early;}`, "}", "table netdev "+ownedTable+" {")
	lines = append(lines, ownershipDefinitions("netdev")...)
	lines = append(lines, epochChannelDefinitions(false, "netdev")...)
	lines = append(lines, nativeSourceDefinitions("netdev")...)
	graph := map[string][]nativeScope{"target_forward": forward.targetPhysical(), "target_return": reply.targetPhysical()}
	for _, name := range nativeChainNames(graph) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(graph[name])...)
		lines = append(lines, "}")
	}
	lines = append(lines, `chain late_forward {type filter hook egress device "lan13" priority -1;policy accept;}`, `chain final_forward {type filter hook egress device "lan13" priority 0;policy drop;jump target_forward;accept;}`, `chain final_return {type filter hook egress device "lan10" priority 0;policy drop;jump target_return;accept;}`, "}", `table netdev n46_target_endpoints {
 chain fixture_device {type filter hook ingress device "device0" priority 0;policy drop;}
 chain fixture_translator {type filter hook ingress device "translated0" priority 0;policy drop;}
 chain fixture_client {type filter hook ingress device "peer0" priority 0;policy drop;}
 }`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+";delete table netdev "+ownedTable+";delete table netdev n46_target_endpoints")
	})
	inspectNAT46TargetFixture(ctx, t, graph)
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownershipProofFixture(t, b, time.Now().UTC(), 70*time.Second).InEpoch(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	publish := func() {
		t.Helper()
		now := time.Now().UTC()
		prepared, err := renderer.prepareNativeOwnership(ctx, proof, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateOwnershipPreparation(ctx, prepared, now); err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, prepared.batch.data)
	}
	publish()
	stamp := func(kind uint64, priority string) {
		t.Helper()
		packetNft(ctx, t, fmt.Sprintf("flush chain inet %s stamp;add rule inet %s stamp meta mark set %#x meta priority set %s", ownedTable, ownedTable, kind|1, priority))
	}
	translated, device, client := packetSocket(t, "translated0"), packetSocket(t, "device0"), packetSocket(t, "peer0")
	wire := packetDatagram{source: netip.MustParseAddr("fdca:1a2b:e046::af0:a"), destination: target, sourceMAC: "02:00:00:00:00:46", destinationMAC: "02:00:00:00:01:46", sourcePort: 56000, destinationPort: 6061}
	raw := wire
	raw.source, raw.destination = alias, netip.MustParseAddr("10.240.0.10")
	raw.sourcePort, raw.destinationPort = wire.destinationPort, wire.sourcePort
	serial := 0
	transmit := func(value packetDatagram, output packetEndpoint, allowed bool) {
		t.Helper()
		serial++
		value.payload = fmt.Sprintf("n46-target-%d", serial)
		before := guardFamilyCounter(ctx, t, "inet", ownedTable, "early")
		sendPacket(ctx, t, translated, packetFrame(t, value))
		if allowed {
			receivePacket(ctx, t, output, packetFrame(t, value), true)
		} else {
			rejectNATPayload(ctx, t, output, value.payload)
		}
		if guardFamilyCounter(ctx, t, "inet", ownedTable, "early") != before+1 {
			t.Fatal("target proof test did not retain early admission")
		}
	}
	for _, kind := range []uint64{0xd1000000, 0xd5000000, 0xf1000000, 0xf5000000} {
		stamp(kind, "0x1c01")
		transmit(wire, device, true)
		stamp(kind+0x01000000, "0x1c01")
		transmit(raw, client, true)
	}
	// Configuration namespaces cannot consume source-epoch target proof, even
	// if the numeric configuration epoch happens to equal the ownership epoch.
	for _, kind := range []uint64{0xd3000000, 0xf3000000} {
		stamp(kind, "0x1c01")
		transmit(wire, device, false)
		stamp(kind+0x01000000, "0x1c01")
		transmit(raw, client, false)
	}
	stamp(0xf1000000, "0x2001")
	transmit(wire, device, false)
	stamp(0xf2000000, "0x2001")
	transmit(raw, client, false)
	stamp(0xd1000000, "0x1c01")
	packetNft(ctx, t, "add rule netdev "+ownedTable+" late_forward ether daddr set 02:00:00:00:00:14")
	transmit(wire, device, false)
	packetNft(ctx, t, "flush chain netdev "+ownedTable+" late_forward")
	changed := raw
	changed.source = alias.Next()
	stamp(0xd2000000, "0x1c01")
	transmit(changed, client, false)
	packetNft(ctx, t, "flush set netdev "+ownedTable+" "+nativeSourceEpoch6)
	stamp(0xd1000000, "0x1c01")
	transmit(wire, device, false)
	stamp(0xd2000000, "0x1c01")
	transmit(raw, client, false)
	publish()
	stamp(0xd1000000, "0x1c01")
	transmit(wire, device, true)
	stamp(0xd2000000, "0x1c01")
	transmit(raw, client, true)
	// Shorten only the existing target mirror; the global epoch and original
	// ownership stay live. This fault cannot extend the original deadline.
	packetNft(ctx, t, "flush set netdev "+ownedTable+" "+nativeSourceEpoch6+";add element netdev "+ownedTable+" "+nativeSourceEpoch6+" {0:1c00 . "+target.String()+" timeout 1s}")
	time.Sleep(1200 * time.Millisecond)
	stamp(0xd1000000, "0x1c01")
	transmit(wire, device, false)
	stamp(0xd2000000, "0x1c01")
	transmit(raw, client, false)
	publish()
	stamp(0xd1000000, "0x1c01")
	transmit(wire, device, true)
	stamp(0xd2000000, "0x1c01")
	transmit(raw, client, true)
}

func inspectNAT46TargetFixture(ctx context.Context, t *testing.T, graph map[string][]nativeScope) {
	t.Helper()
	inspectNAT46TargetFamilyFixture(ctx, t, "netdev", graph, false)
}

func inspectNAT46TargetFamilyFixture(ctx context.Context, t *testing.T, family string, graph map[string][]nativeScope, mixed bool) {
	t.Helper()
	schema := &guardTableSchema{sets: map[string]map[string]any{}}
	if mixed {
		nativeNAT46TargetGrantSchema(schema, family)
	}
	sets := map[string]bool{}
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", family, ownedTable), &listing); err != nil {
		t.Fatal(err)
	}
	counts, headers := map[string]int{}, map[string]bool{}
	for _, raw := range listing.Objects[2:] {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		if value, found := object["counter"]; found {
			var counter struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(value, &counter) != nil || !mixed || family != "inet" || counter.Name != "mixed_early" {
				t.Fatal("unexpected target fixture counter")
			}
			continue // Only the explicitly named independent caller counter.
		}
		kind, fields, err := guardObject(raw)
		if err != nil {
			t.Fatal(err)
		}
		var name string
		key := "name"
		if kind == "rule" {
			key = "chain"
		}
		if err := json.Unmarshal(fields[key], &name); err != nil {
			t.Fatal(err)
		}
		if kind == "set" {
			if expected, found := schema.sets[name]; found {
				if _, err := checkGuardObject(fields, expected, true); err != nil {
					t.Fatal("mixed target grant header differs", family, name, err)
				}
				sets[name] = true
			}
		}
		rules, found := graph[name]
		if !found {
			continue
		}
		var expected map[string]any
		if kind == "chain" {
			expected = map[string]any{"family": family, "table": ownedTable, "name": name}
			headers[name] = true
		} else if kind == "rule" && counts[name] < len(rules) {
			expected = map[string]any{"family": family, "table": ownedTable, "chain": name, "expr": rules[counts[name]].expressions}
			counts[name]++
		}
		if _, err := checkGuardObject(fields, expected, false); err != nil {
			t.Fatalf("NAT46 target proof graph differs for %s: %v; actual=%s", name, err, raw)
		}
	}
	for name, rules := range graph {
		if !headers[name] || counts[name] != len(rules) {
			t.Fatal("NAT46 target proof graph is incomplete", name)
		}
	}
	for name := range schema.sets {
		if !sets[name] {
			t.Fatal("mixed target grant collection is missing", family, name)
		}
	}
}

// Isolate the mixed-family destination grant projection and its exact packet
// lookups. Metadata and admission are synthetic. Current source/target identity,
// ordered policy and TAYGA are qualified separately, not supplied by this test.
func TestKernelNamedNAT46TargetGrants(t *testing.T) {
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
	for _, link := range []struct{ name, mac string }{{"nat46", "02:00:00:00:01:46"}, {"translated0", "02:00:00:00:00:46"}} {
		packetIP(ctx, t, "link", "set", link.name, "address", link.mac)
		packetIP(ctx, t, "link", "set", link.name, "up")
	}
	model, receipt, _, baseline := nat46TargetGrantFixture(t, true)
	mapping := model.mappings[0]
	embedded := nativeNAT46SourcePrefix(model.prefix, netip.MustParsePrefix("10.240.0.10/32")).Addr()
	packetIP(ctx, t, "route", "add", "10.250.0.0/24", "dev", "nat46")
	packetIP(ctx, t, "-6", "route", "add", model.prefix.String(), "dev", "nat46")
	packetIP(ctx, t, "neighbor", "replace", mapping.alias.String(), "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
	packetIP(ctx, t, "neighbor", "replace", embedded.String(), "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
	graph := map[string][]nativeScope{}
	for _, protocol := range []string{"tcp", "udp"} {
		for _, reply := range []bool{false, true} {
			for _, wire := range []bool{false, true} {
				leg := nativeNAT46Leg{mapping: mapping, prefix: model.prefix, protocol: protocol, reply: reply}
				graph[fmt.Sprintf("mixed_%s_%t_%t", protocol, reply, wire)] = leg.targetGrant(wire)
			}
		}
	}
	lines := []string{}
	for _, family := range []string{"inet", "netdev"} {
		lines = append(lines, "table "+family+" "+ownedTable+" {")
		lines = append(lines, ownershipDefinitions(family)...)
		lines = append(lines, nativeSourceDefinitions(family)...)
		lines = append(lines, epochChannelDefinitions(false, family)...)
		lines = append(lines, nativeNAT46TargetGrantDefinitions(family)...)
		if family == "inet" {
			lines = append(lines, ownershipEpochDefinitions()...)
		}
		for _, name := range nativeChainNames(graph) {
			lines = append(lines, "chain "+name+" {")
			lines = append(lines, nativeRulesText(graph[name])...)
			lines = append(lines, "}")
		}
		lines = append(lines, "chain mixed_dispatch {")
		for _, protocol := range []string{"tcp", "udp"} {
			for _, item := range []struct {
				reply, wire bool
				match       string
			}{{false, false, "ip daddr " + mapping.alias.String()}, {false, true, "ip6 daddr " + mapping.target.String()}, {true, false, "ip saddr " + mapping.alias.String()}, {true, true, "ip6 saddr " + mapping.target.String()}} {
				lines = append(lines, item.match+" meta l4proto "+protocol+" goto "+fmt.Sprintf("mixed_%s_%t_%t", protocol, item.reply, item.wire))
			}
		}
		lines = append(lines, "drop", "}")
		if family == "inet" {
			lines = append(lines, "chain mixed_stamp {meta mark set 0xd5000001 meta priority set 0x1c01;}", "counter mixed_early {}", `chain mixed_forward {type filter hook forward priority 0;policy drop;jump mixed_stamp;jump mixed_dispatch;counter name mixed_early;accept;}`)
		} else {
			for _, iface := range []string{"lan10", "lan13", "nat46"} {
				lines = append(lines, fmt.Sprintf("chain mixed_final_%s {type filter hook egress device %q priority 0;policy drop;jump mixed_dispatch;accept;}", iface, iface))
			}
			lines = append(lines, `chain mixed_late {type filter hook egress device "lan13" priority -1;policy accept;}`)
		}
		lines = append(lines, "}")
	}
	lines = append(lines, `table netdev n46_mixed_endpoints {
 chain fixture_device {type filter hook ingress device "device0" priority 0;policy drop;}
 chain fixture_translator {type filter hook ingress device "translated0" priority 0;policy drop;}
 chain fixture_client {type filter hook ingress device "peer0" priority 0;policy drop;}
 }`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+";delete table netdev "+ownedTable+";delete table netdev n46_mixed_endpoints")
	})
	// Pin both named representations, their collection headers and namespace
	// branches independently of the fixture's callers.
	for _, family := range []string{"inet", "netdev"} {
		inspectNAT46TargetFamilyFixture(ctx, t, family, graph, true)
	}
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	prepared, err := renderer.prepareNativeOwnership(ctx, receipt.evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnershipPreparation(ctx, prepared, now); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, prepared.batch.data)
	publish := func(timeout int) {
		t.Helper()
		logical := idGrantInput(t, "lan13", "02:00:00:00:00:13", mapping.alias.String(), timeout)
		changes := guardChanges{}
		for _, name := range grantSets {
			changes.Commands = append(changes.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
		}
		changes.Commands = append(changes.Commands, logical.Commands...)
		encoded, err := json.Marshal(changes)
		if err != nil {
			t.Fatal(err)
		}
		utc, started := time.Now().UTC(), time.Now()
		mapped, err := prepareMappedGuards(ctx, &preparedBatch{data: encoded, preparedAt: utc, startedAt: started, startBefore: utc.Add(preparationBudget)}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareNativeNAT46Guards(ctx, mapped, receipt, model, utc)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePreparedGuardBatch(ctx, prepared); err != nil {
			t.Fatal(err)
		}
		complete, err := decodeGuardChanges(prepared.batch.data)
		if err != nil {
			t.Fatal(err)
		}
		// This packet fixture installs only the typed mixed-grant subset. The
		// complete transaction is independently reconstructed above; shared
		// runtime writer/floor integration remains a separate admission gate.
		commands := []change{}
		for _, command := range complete.Commands {
			if command.Flush != nil && slices.Contains(nativeNAT46TargetGrantRefs(), command.Flush.Set) {
				commands = append(commands, command)
			}
			if command.Add != nil {
				value := command.Add.Element
				if slices.Contains(nativeNAT46TargetGrantRefs(), objectReference{Family: value.Family, Table: value.Table, Name: value.Name}) {
					commands = append(commands, command)
				}
			}
		}
		data, err := json.Marshal(guardChanges{Commands: commands})
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, data)
	}
	translated, device, client := packetSocket(t, "translated0"), packetSocket(t, "device0"), packetSocket(t, "peer0")
	serial := 0
	transmit := func(protocol string, reply, wire bool, kind uint64, allowed, early bool) {
		t.Helper()
		serial++
		source, destination := netip.MustParseAddr("10.240.0.10"), mapping.alias
		if wire {
			source, destination = embedded, mapping.target
		}
		sport, dport := uint16(57000), uint16(6053)
		input, output := client, translated
		sourceMAC, destinationMAC := "02:00:00:00:00:10", "02:00:00:00:01:10"
		if wire {
			input, output = translated, device
			sourceMAC, destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
		}
		if reply {
			source, destination = destination, source
			sport, dport = dport, sport
			kind += 0x01000000
			input, output = translated, client
			if wire {
				input, output = device, translated
				sourceMAC, destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
			} else {
				sourceMAC, destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
			}
		}
		packetNft(ctx, t, fmt.Sprintf("flush chain inet %s mixed_stamp;add rule inet %s mixed_stamp meta mark set %#x meta priority set 0x1c01", ownedTable, ownedTable, kind|1))
		value := packetDatagram{source: source, destination: destination, sourceMAC: sourceMAC, destinationMAC: destinationMAC, sourcePort: sport, destinationPort: dport, isTCP: protocol == "tcp", tcpFlags: 2, payload: fmt.Sprintf("mixed-grant-%d", serial)}
		if reply {
			value.tcpFlags = 18
		}
		before := guardFamilyCounter(ctx, t, "inet", ownedTable, "mixed_early")
		sendPacket(ctx, t, input, packetFrame(t, value))
		if allowed {
			receivePacket(ctx, t, output, packetFrame(t, value), true)
		} else {
			rejectNATPayload(ctx, t, output, value.payload)
		}
		expected := before
		if early {
			expected++
		}
		if guardFamilyCounter(ctx, t, "inet", ownedTable, "mixed_early") != expected {
			t.Fatal("mixed grant test lost its expected early admission")
		}
	}
	transmit("tcp", false, true, 0xf5000000, false, false)
	publish(43)
	for _, protocol := range []string{"tcp", "udp"} {
		for _, reply := range []bool{false, true} {
			for _, wire := range []bool{false, true} {
				for _, kind := range []uint64{0xd5000000, 0xf5000000} {
					transmit(protocol, reply, wire, kind, true, true)
				}
			}
		}
	}
	packetNft(ctx, t, "flush set netdev "+ownedTable+" native_n46_to6_tcp")
	transmit("tcp", false, true, 0xf5000000, false, true)
	transmit("tcp", true, true, 0xf5000000, false, true)
	transmit("tcp", false, false, 0xf5000000, true, true)
	publish(43)
	packetNft(ctx, t, "flush set inet "+ownedTable+" native_n46_to4_tcp")
	transmit("tcp", false, false, 0xf5000000, false, false)
	transmit("tcp", true, false, 0xf5000000, false, false)
	transmit("tcp", false, true, 0xf5000000, true, true)
	publish(43)
	for _, mutation := range []string{"ip6 saddr set fdca:1a2b:e046::af0:b", "tcp dport set 6054", "meta priority set 0x2001", "meta mark set 0xf3000001"} {
		packetNft(ctx, t, "add rule netdev "+ownedTable+" mixed_late "+mutation)
		transmit("tcp", false, true, 0xf5000000, false, true)
		packetNft(ctx, t, "flush chain netdev "+ownedTable+" mixed_late")
	}
	publish(1)
	time.Sleep(1200 * time.Millisecond)
	for _, reply := range []bool{false, true} {
		for _, wire := range []bool{false, true} {
			transmit("tcp", reply, wire, 0xf5000000, false, false)
		}
	}
	publish(43)
	transmit("tcp", false, true, 0xf5000000, true, true)
}
