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

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Qualify normalized scope and terminal authorization independently of source
// the translator. Synthetic callers supply connection metadata; current grants
// use the production typed projection and listener leaf. This is not shared
// runtime activation or qualification of a directory/binding producer.
func TestKernelNamedNAT46OrderedWirePolicy(t *testing.T) {
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
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	client := netip.MustParseAddr("fdca:1a2b:e046::af0:a")
	target := netip.MustParseAddr("fdca:1a2b:3::10")
	packetIP(ctx, t, "-6", "route", "add", prefix.String(), "dev", "nat46")
	packetIP(ctx, t, "neighbor", "replace", client.String(), "dev", "nat46", "lladdr", "02:00:00:00:00:46", "nud", "permanent")
	b := nativeAccessBaseline(t)
	b.NetworkModel.NAT46Prefix = &prefix
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	b.NAT46 = []policy.NAT46{{ID: "mapped", Alias: netip.MustParseAddr("10.250.0.20"), Target: target, Ready: true}}
	b.NetworkModel.ManagedNetworks = []policy.Role{}
	base := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "tcp",
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.0/24")}},
		To:   []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:3::/64")}}}
	deny, directory, owner, udp, echo := base, base, base, base, base
	deny.Action, deny.Authorization = "deny", "inherit"
	deny.Protocol = "any"
	deny.From = []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.12/32")}}
	directory.Authorization, directory.Ports = "directory", []uint16{6062}
	owner.Ports = []uint16{6053, 6062}
	udp.Protocol, udp.Ports = "udp", []uint16{6053}
	echo.Protocol = "icmp"
	b.NetworkModel.Rules = []policy.NetworkRule{deny, directory, owner, udp, echo}
	model, err := newNativeNAT46Model(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := nativeTranslationFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const table = ownedTable
	lines := []string{"table inet " + table + " {"}
	lines = append(lines, nativeIDGrantDefinitions("inet")...)
	lines = append(lines, "chain save_owner_priority {")
	lines = append(lines, nativeRulesText(nativePriorityScopes(false))...)
	lines = append(lines, "}")
	for _, name := range nativeChainNames(facts) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(facts[name])...)
		lines = append(lines, "}")
	}
	programs := map[string]*nativeNAT46Policy{}
	grants := map[string]bool{}
	for _, physical := range []bool{false, true} {
		if physical {
			lines = append(lines, "}", "table netdev "+table+" {")
			lines = append(lines, nativeIDGrantDefinitions("netdev")...)
		}
		for index := 1; index < len(b.NetworkModel.Rules); index++ {
			for _, protocol := range []string{"tcp", "udp", "icmp"} {
				for _, reply := range []bool{false, true} {
					original := nativePacketContext{iface: "lan10", family: 4, id: uint64(index + 1)}
					program, err := model.wirePolicy(ctx, index, 0, original, protocol, reply, physical)
					if err != nil {
						t.Fatal(err)
					}
					key := fmt.Sprintf("%d_%s_%t_%t", index, protocol, reply, physical)
					programs[key] = program
					for _, name := range nativeChainNames(program.chains) {
						lines = append(lines, "chain "+name+" {")
						lines = append(lines, nativeRulesText(program.chains[name])...)
						lines = append(lines, "}")
					}
					if !grants[program.grant] {
						leg := nativeNAT46Leg{mapping: model.mappings[0], prefix: prefix, protocol: protocol, reply: reply}
						lines = append(lines, "chain "+program.grant+" {")
						lines = append(lines, nativeRulesText(leg.wireSourceGrant())...)
						lines = append(lines, "}")
						grants[program.grant] = true
					}
				}
			}
		}
		if !physical {
			lines = append(lines, `chain stamp {
 ct mark 0 ct state new meta l4proto tcp tcp dport 6062 ct mark set 0x1c01
 ct mark 0 ct state new meta l4proto tcp ct mark set 0x1c02
 ct mark 0 ct state new meta l4proto udp ct mark set 0x1c03
 ct mark 0 ct state new icmpv6 type echo-request ct mark set 0x1c04
 meta l4proto tcp tcp dport 6062 meta mark set 0xd5000002 meta priority set 0x1c01 return
 meta l4proto tcp meta mark set 0xf3000003 meta priority set 0x1c01 return
 meta l4proto udp meta mark set 0xf3000004 meta priority set 0x1c01 return
 meta mark set 0xf3000005 meta priority set 0x1c01 return
}`)
			lines = append(lines, "chain before {type filter hook forward priority 0;policy drop;",
				"ct direction original jump stamp",
				"iifname \"lan13\" ct direction reply jump native_translation_facts_restore")
		} else {
			lines = append(lines, `chain late_mutation {type filter hook egress device "lan13" priority -1;policy accept;}`,
				"chain before_device {type filter hook egress device \"lan13\" priority 0;policy drop; jump before;}",
				"chain before_translator {type filter hook egress device \"nat46\" priority 0;policy drop; jump before;}", "chain before {")
		}
		for index := 1; index < len(b.NetworkModel.Rules); index++ {
			for _, protocol := range []string{"tcp", "udp", "icmp"} {
				for _, reply := range []bool{false, true} {
					program := programs[fmt.Sprintf("%d_%s_%t_%t", index, protocol, reply, physical)]
					kind := nativeNAT46StaticTag(reply)
					if index == 1 {
						kind = nativeDirectoryTag(reply)
					}
					guard := fmt.Sprintf("meta mark & 0xff0003ff == %#x", kind|uint64(index+1))
					if protocol == "icmp" {
						guard += " meta l4proto ipv6-icmp"
					} else {
						guard += " meta l4proto " + protocol
					}
					lines = append(lines, guard+" goto "+program.entry+"_caller")
				}
			}
		}
		lines = append(lines, "drop", "}")
		for index := 1; index < len(b.NetworkModel.Rules); index++ {
			for _, protocol := range []string{"tcp", "udp", "icmp"} {
				for _, reply := range []bool{false, true} {
					program := programs[fmt.Sprintf("%d_%s_%t_%t", index, protocol, reply, physical)]
					lines = append(lines, "chain "+program.entry+"_caller {", "jump "+program.entry)
					if !physical && !reply {
						lines = append(lines, "jump native_translation_facts_capture")
					}
					lines = append(lines, "accept", "}")
				}
			}
		}
	}
	lines = append(lines, "}", `table netdev n46_scope_endpoints {
 chain fixture_device {type filter hook ingress device "device0" priority 0;policy drop;}
 chain fixture_translator {type filter hook ingress device "translated0" priority 0;policy drop;}
 chain fixture_peer {type filter hook ingress device "peer0" priority 0;policy drop;}
}`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+table+"; delete table netdev "+table+"; delete table netdev n46_scope_endpoints")
	})
	for _, family := range []string{"inet", "netdev"} {
		inspectNAT46WirePolicyFixture(ctx, t, family, table, programs, model)
	}
	translated, device := packetSocket(t, "translated0"), packetSocket(t, "device0")
	serial := 0
	transmit := func(value packetDatagram, input, output packetEndpoint, allowed bool) {
		t.Helper()
		serial++
		value.payload = fmt.Sprintf("n46-policy-%d", serial)
		t.Logf(
			"wire packet %d: %s -> %s tcp=%t icmp=%t echo=%#x allowed=%t",
			serial,
			value.source,
			value.destination,
			value.isTCP,
			value.isICMP,
			value.icmpData,
			allowed,
		)
		sendPacket(ctx, t, input, packetFrame(t, value))
		if allowed {
			receivePacket(ctx, t, output, packetFrame(t, value), true)
		} else {
			rejectNATPayload(ctx, t, output, value.payload)
		}
	}
	// Conntrack keys echo identifiers, not their sequence numbers. Use an
	// identifier distinct from the transport fixture's retained epoch marks.
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		original := packetDatagram{
			source: client, destination: target,
			sourceMAC: "02:00:00:00:00:46", destinationMAC: "02:00:00:00:01:46",
			sourcePort: 53000, destinationPort: 6053,
			isTCP: protocol == "tcp", tcpFlags: 2,
			isICMP: protocol == "icmp", icmpType: 128, icmpData: 0x4e460001,
		}
		transmit(original, translated, device, true)
		reply := original
		reply.source, reply.destination = target, client
		reply.sourcePort, reply.destinationPort = original.destinationPort, original.sourcePort
		reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
		reply.tcpFlags, reply.icmpType = 18, 129
		transmit(reply, device, translated, true)
		wrong := original
		wrong.source = netip.MustParseAddr("fdca:1a2b:e046::af0:c")
		transmit(wrong, translated, device, false)
		wrong = original
		wrong.sourcePort++
		wrong.destinationPort = 6054
		if !wrong.isICMP {
			transmit(wrong, translated, device, false)
		}
	}
	directoryFrame := packetDatagram{source: client, destination: target, sourceMAC: "02:00:00:00:00:46", destinationMAC: "02:00:00:00:01:46", sourcePort: 54000, destinationPort: 6062, isTCP: true, tcpFlags: 2}
	transmit(directoryFrame, translated, device, false)
	publication, baselineHash := nat46WirePolicySourceFixture(ctx, t, b)
	publishGrants := func(timeout int) {
		t.Helper()
		value, err := json.Marshal(map[string]any{"elem": map[string]any{"timeout": timeout,
			"val": map[string]any{"concat": []any{"lan10", "02:00:00:00:00:10", "10.240.0.10", model.mappings[0].alias.String(), 6062}}}})
		if err != nil {
			t.Fatal(err)
		}
		logical := guardChanges{Commands: []change{guardAdd("inet", "lease_from4_tcp", []json.RawMessage{value})}}
		commands, err := projectNativeIPv4GrantIDs(ctx, logical, publication, baselineHash, time.Now().UTC(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(guardChanges{Commands: commands})
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, data)
	}
	publishGrants(43)
	transmit(directoryFrame, translated, device, true)
	directoryReply := directoryFrame
	directoryReply.source, directoryReply.destination = target, client
	directoryReply.sourcePort, directoryReply.destinationPort = directoryFrame.destinationPort, directoryFrame.sourcePort
	directoryReply.sourceMAC, directoryReply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
	directoryReply.tcpFlags = 18
	transmit(directoryReply, device, translated, true)
	packetNft(ctx, t, "flush set inet "+table+" native_id_lease_from4_tcp")
	transmit(directoryFrame, translated, device, false)
	transmit(directoryReply, device, translated, false)
	publishGrants(43)
	packetNft(ctx, t, "flush set netdev "+table+" native_id_lease_from4_tcp")
	transmit(directoryFrame, translated, device, false)
	transmit(directoryReply, device, translated, false)
	publishGrants(43)
	transmit(directoryFrame, translated, device, true)
	ownerFrame := directoryFrame
	ownerFrame.sourcePort, ownerFrame.destinationPort = 55000, 6053
	transmit(ownerFrame, translated, device, true)
	wrongInterface := ownerFrame
	wrongInterface.sourceMAC, wrongInterface.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
	transmit(wrongInterface, packetSocket(t, "peer0"), device, false)
	for _, mutation := range []string{"tcp dport set 6062", "ip6 saddr set fdca:1a2b:e046::af0:c", "meta mark set 0xd5000003"} {
		publishGrants(43)
		packetNft(ctx, t, "add rule netdev "+table+" late_mutation "+mutation)
		transmit(ownerFrame, translated, device, false)
		packetNft(ctx, t, "flush chain netdev "+table+" late_mutation")
	}
	// A grant for this exact IPv4 ownership ID cannot be borrowed by another
	// ID, an older epoch, the opposite source half or the static NAS-target
	// namespace. inet admission still sees the unchanged positive packet.
	for _, mutation := range []string{"meta priority set 0x1c02", "meta priority set 0x1801", "meta mark set 0xd5002002", "meta mark set 0xf5000002"} {
		publishGrants(43)
		transmit(directoryFrame, translated, device, true)
		packetNft(ctx, t, "add rule netdev "+table+" late_mutation "+mutation)
		transmit(directoryFrame, translated, device, false)
		packetNft(ctx, t, "flush chain netdev "+table+" late_mutation")
	}
	publishGrants(1)
	time.Sleep(1200 * time.Millisecond)
	transmit(directoryFrame, translated, device, false)
	transmit(directoryReply, device, translated, false)
	transmit(ownerFrame, translated, device, true)
}

func inspectNAT46WirePolicyFixture(ctx context.Context, t *testing.T, family, table string, programs map[string]*nativeNAT46Policy, model *nativeNAT46Model) {
	t.Helper()
	suffix := "_inet"
	if family == "netdev" {
		suffix = "_physical"
	}
	graph := map[string][]nativeScope{}
	for _, program := range programs {
		if strings.HasSuffix(program.entry, suffix) {
			for name, rules := range program.chains {
				graph[name] = rules
			}
			protocol := "tcp"
			if strings.Contains(program.grant, "_udp_") {
				protocol = "udp"
			}
			if strings.Contains(program.grant, "_icmp_") {
				protocol = "icmp"
			}
			leg := nativeNAT46Leg{mapping: model.mappings[0], prefix: model.prefix, protocol: protocol,
				reply: strings.Contains(program.grant, "_reply_")}
			graph[program.grant] = leg.wireSourceGrant()
		}
	}
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", family, table), &listing); err != nil {
		t.Fatal(err)
	}
	headers, counts := map[string]bool{}, map[string]int{}
	for _, raw := range listing.Objects[2:] {
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
		rules, exists := graph[name]
		if !exists {
			continue // Independent synthetic callers, grants and connection facts.
		}
		var expected map[string]any
		if kind == "chain" {
			expected = map[string]any{"family": family, "table": table, "name": name}
			headers[name] = true
		} else if kind == "rule" && counts[name] < len(rules) {
			expected = map[string]any{"family": family, "table": table, "chain": name, "expr": rules[counts[name]].expressions}
			counts[name]++
		}
		if _, err := checkGuardObject(fields, expected, false); err != nil {
			t.Fatalf("normalized nat46 wire policy differs for %s/%s: %v; actual=%s", family, name, err, raw)
		}
	}
	for name, rules := range graph {
		if !headers[name] || counts[name] != len(rules) {
			t.Fatal("normalized nat46 wire policy graph is incomplete", family, name)
		}
	}
}

// The independent binding fixture supplies one actual IPv4 device identity.
// The receipt is minted from the same original typed ownership preparation;
// neither a kernel listing nor later republishing restarts that deadline.
func nat46WirePolicySourceFixture(ctx context.Context, t *testing.T, baseline policy.Baseline) (*nativeSourcePublication, string) {
	t.Helper()
	now := time.Now().UTC()
	compiler, err := policy.New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "synthetic-n46-policy", ObservedAt: now, Complete: true,
		Records: []binding.Record{{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10,
			AssociatedAt: now, AssociationID: "synthetic-association", Addresses: []binding.Address{{
				IP: netip.MustParseAddr("10.240.0.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-lease4", ObservedAt: now, ValidUntil: now.Add(80 * time.Second),
			}}}}}
	evidence, err := compiler.CompileOwnership(ctx, snapshot, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = evidence.InEpoch(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeOwnership(ctx, evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := nativeSourceReceipt(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, compiler.BaselineHash()
}
