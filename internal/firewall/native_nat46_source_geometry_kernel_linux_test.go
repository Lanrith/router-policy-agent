//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// Join current source-epoch GIDs, target ownership, ordered wire policy,
// destination grants, immutable facts and fresh translator tuples. The original
// raw decision is synthetic; this does not activate the shared router layout.
func TestKernelNamedNAT46SourceGeometry(t *testing.T) {
	testKernelNamedNAT46SourceGeometry(t, false, false)
}

func TestKernelNamedNAT46MappedContext(t *testing.T) {
	testKernelNamedNAT46SourceGeometry(t, true, false)
}

func TestKernelNamedNAT46SharedValidation(t *testing.T) {
	testKernelNamedNAT46SourceGeometry(t, true, true)
}

func testKernelNamedNAT46SourceGeometry(t *testing.T, mapped, shared bool) {
	t.Helper()
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
	client4 := netip.MustParseAddr("10.232.4.10")
	client6 := netip.MustParseAddr("fdca:1a2b:e046::ae8:40a")
	target, alias := netip.MustParseAddr("fdca:1a2b:3::10"), netip.MustParseAddr("10.250.0.20")
	for _, neighbor := range []struct{ address, iface, mac string }{{client4.String(), "lan10", "02:00:00:00:00:10"}, {client6.String(), "nat46", "02:00:00:00:00:46"}, {alias.String(), "nat46", "02:00:00:00:00:46"}} {
		packetIP(ctx, t, "neighbor", "replace", neighbor.address, "dev", neighbor.iface, "lladdr", neighbor.mac, "nud", "permanent")
	}
	packetIP(ctx, t, "route", "add", "10.250.0.0/24", "dev", "nat46")
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:e046::/96", "dev", "nat46")
	b := nativeAccessBaseline(t)
	b.Zones[0].Networks = sourceClassPrefixes("10.232.0.0/21", "fdca:1a2b::/64")
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: sourceClassPrefixes("10.232.0.1/32"), Roles: []policy.Role{}})
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	b.NAT46 = []policy.NAT46{{ID: "mapped", Alias: alias, Target: target, Ready: true}}
	base := policy.NetworkRule{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6053}, From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.232.0.0/21")}}, To: []policy.NetworkSelector{{Interface: "lan13", Addresses: sourceClassPrefixes("fdca:1a2b:3::/64")}}}
	udp, owner := base, base
	udp.Protocol = "udp"
	owner.Protocol, owner.Authorization, owner.Ports = "any", "owner", nil
	b.NetworkModel.Rules = []policy.NetworkRule{base, udp, owner}
	sources, err := newNativeNAT46StaticSources(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	model := sources.model
	transport, err := newNativeNAT46SourceTransport(ctx, sources)
	if shared {
		transport, err = newNativeNAT46SharedTransport(ctx, sources)
	}
	if err != nil {
		t.Fatal(err)
	}
	facts, err := nativeTranslationFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inet, physical := map[string][]nativeScope{}, map[string][]nativeScope{}
	merge := func(into, from map[string][]nativeScope) {
		t.Helper()
		for name, rules := range from {
			if prior, exists := into[name]; exists && !reflect.DeepEqual(prior, rules) {
				t.Fatal("inconsistent shared source geometry chain", name)
			}
			into[name] = rules
		}
	}
	merge(inet, transport.chains())
	merge(inet, facts)
	saved := map[string]nativePacketContext{}
	for index := range 3 {
		for _, protocol := range []string{"tcp", "udp", "icmp"} {
			if index == 0 && protocol != "tcp" || index == 1 && protocol != "udp" {
				continue
			}
			saved[fmt.Sprintf("%d_%s", index, protocol)] = nativePacketContext{iface: "lan10", family: 4, id: uint64(index + 1)}
		}
	}
	var plan *nativeNAT46ContextPlan
	if mapped {
		plan, err = model.contextPlan(ctx, map[int][]nativePacketContext{0: {{iface: "lan10", family: 4, id: 1}}, 1: {{iface: "lan10", family: 4, id: 2}}, 2: {{iface: "lan10", family: 4, id: 3}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range plan.entries {
			saved[fmt.Sprintf("%d_%s", entry.rule, entry.protocol)] = entry.packet
		}
		handoff, err := plan.handoff(ctx)
		if err != nil {
			t.Fatal(err)
		}
		merge(inet, handoff)
	}
	handoffs := map[uint64]string{}
	if shared {
		for _, directory := range []bool{false, true} {
			contexts := []nativePacketContext{}
			for key, original := range saved {
				if (!strings.HasPrefix(key, "2_")) == directory {
					contexts = append(contexts, original)
				}
			}
			entry, handoff, err := sources.sourceHandoffGroup(ctx, contexts, directory)
			if err != nil {
				t.Fatal(err)
			}
			merge(inet, handoff)
			for _, original := range contexts {
				handoffs[original.id] = entry
			}
		}
	} else {
		for key, original := range saved {
			directory := !strings.HasPrefix(key, "2_")
			handoff, err := sources.sourceHandoff(ctx, original, directory)
			if err != nil {
				t.Fatal(err)
			}
			merge(inet, handoff)
			suffix := "owner"
			if directory {
				suffix = "directory"
			}
			handoffs[original.id] = fmt.Sprintf("native_n46_source_handoff_%d_%s", original.id, suffix)
		}
	}
	programs := map[string]*nativeNAT46Policy{}
	for _, hardware := range []bool{false, true} {
		graph := inet
		if hardware {
			graph = physical
		}
		for index := range 3 {
			for _, protocol := range []string{"tcp", "udp", "icmp"} {
				if index == 0 && protocol != "tcp" || index == 1 && protocol != "udp" {
					continue
				}
				for _, reply := range []bool{false, true} {
					original := saved[fmt.Sprintf("%d_%s", index, protocol)]
					var program *nativeNAT46Policy
					if mapped {
						groupIndex := slices.IndexFunc(plan.groups, func(group nativeNAT46ContextGroup) bool {
							return slices.ContainsFunc(group.entries, func(entry nativeNAT46Context) bool { return entry.packet.id == original.id })
						})
						program, err = plan.wirePolicy(ctx, groupIndex, reply, hardware)
					} else {
						program, err = model.wireSourcePolicy(ctx, sources, index, 0, original, protocol, reply, hardware)
					}
					if err != nil {
						t.Fatal(err)
					}
					programs[fmt.Sprintf("%d_%s_%t_%t", index, protocol, reply, hardware)] = program
					merge(graph, program.chains)
					leg := nativeNAT46Leg{mapping: model.mappings[0], prefix: prefix, protocol: protocol, reply: reply}
					merge(graph, map[string][]nativeScope{program.grant: leg.targetGrant(true)})
				}
			}
		}
	}
	for _, leg := range transport.legs {
		physical[leg.name+"_wire_source"] = nat46StaticSourceWirePhysical(leg.reply)
		physical[leg.name+"_wire_target"] = leg.targetWirePhysical()
		if leg.reply {
			physical[leg.name+"_raw_source"] = nat46StaticSourcePhysical(true)
			physical[leg.name+"_raw_target"] = leg.targetPhysical()
			physical[leg.name+"_raw_grant"] = leg.targetGrant(false)
			inet[leg.name+"_raw_grant"] = leg.targetGrant(false)
		}
	}
	lines := []string{}
	for _, family := range []string{"inet", "netdev"} {
		lines = append(lines, "table "+family+" "+ownedTable+" {")
		lines = append(lines, ownershipDefinitions(family)...)
		lines = append(lines, nativeSourceDefinitions(family)...)
		lines = append(lines, epochChannelDefinitions(false, family)...)
		lines = append(lines, nativeNAT46TargetGrantDefinitions(family)...)
		lines = append(lines, "set "+classified4Set+" {type ipv4_addr;size 16384;}", "set "+classified6Set+" {type ipv6_addr;size 16384;}", nat46StaticSourceLiveDefinition())
		definitions, err := sources.definitions(ctx, family)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, definitions...)
		graph := physical
		if family == "inet" {
			graph = inet
			lines = append(lines, ownershipEpochDefinitions()...)
			lines = append(lines, "set "+configurationEpochSet+" {type mark;size 1;}", nat46StaticSourceDefinition())
			lines = append(lines, transport.definitions()...)
		} else {
			lines = append(lines, epochChannelDefinitions(true, family)...)
		}
		for _, name := range nativeChainNames(graph) {
			lines = append(lines, "chain "+name+" {")
			lines = append(lines, nativeRulesText(graph[name])...)
			lines = append(lines, "}")
		}
		if family == "inet" {
			lines = append(lines, "chain save_owner_priority {")
			lines = append(lines, nativeRulesText(nativePriorityScopes(false))...)
			lines = append(lines, "}")
			forward := []string{"chain source_geometry_forward {type filter hook forward priority 0;policy drop;"}
			for _, leg := range transport.legs {
				original := leg.name + "_original"
				converted := leg.name + "_converted"
				forward = append(forward, leg.geometry(false).text+" goto "+original, leg.geometry(true).text+" goto "+converted)
				if !leg.reply {
					lines = append(lines, "chain "+original+" {", "iifname != \"lan10\" drop", "ip saddr != 10.232.0.0/21 drop")
					for index := range 3 {
						if index == 0 && leg.protocol != "tcp" || index == 1 && leg.protocol != "udp" {
							continue
						}
						match := ""
						if leg.protocol != "icmp" {
							port := 6053
							if index == 2 {
								port = 6061
							}
							match = fmt.Sprintf("%s dport %d ", leg.protocol, port)
						}
						kind := nativeTag(false, false)
						if index != 2 {
							kind = nativeDirectoryTag(false)
						}
						lines = append(lines, fmt.Sprintf("%sct mark 0 ct state new ct mark set %#x", match, 0x1c00|index), fmt.Sprintf("%sct mark %#x meta mark set %#x meta priority set 0x1c00", match, 0x1c00|index, kind|0x006a1400|uint64(index+1)))
						if mapped {
							lines = append(lines, fmt.Sprintf("%sct mark %#x jump native_n46_select_context", match, 0x1c00|index))
						}
						lines = append(lines, fmt.Sprintf("%sct mark %#x jump %s_export", match, 0x1c00|index, leg.name), fmt.Sprintf("%sct mark %#x accept", match, 0x1c00|index))
					}
					lines = append(lines, "drop", "}", "chain "+converted+" {", "jump "+leg.name+"_import")
					for index := range 3 {
						if index == 0 && leg.protocol != "tcp" || index == 1 && leg.protocol != "udp" {
							continue
						}
						id := saved[fmt.Sprintf("%d_%s", index, leg.protocol)].id
						lines = append(lines, fmt.Sprintf("meta mark & 0x3ff == %d jump %s", id, handoffs[id]))
					}
					lines = append(lines, "goto "+leg.name+"_wire_policy", "}")
				} else {
					lines = append(lines, "chain "+original+" {", "iifname . ether saddr . ip6 saddr != @"+ownership6Set+" drop", "meta mark set 0x009f0000 meta priority set 3", "jump native_translation_facts_restore", "jump "+leg.name+"_wire_policy", "jump "+leg.name+"_export", "accept", "}", "chain "+converted+" {", "jump "+leg.name+"_import", "goto "+leg.name+"_raw_policy", "}")
				}
				lines = append(lines, "chain "+leg.name+"_wire_policy {")
				for index := range 3 {
					if index == 0 && leg.protocol != "tcp" || index == 1 && leg.protocol != "udp" {
						continue
					}
					program := programs[fmt.Sprintf("%d_%s_%t_false", index, leg.protocol, leg.reply)]
					lines = append(lines, fmt.Sprintf("meta mark & 0x3ff == %d goto %s", saved[fmt.Sprintf("%d_%s", index, leg.protocol)].id, program.entry+"_caller"))
				}
				lines = append(lines, "drop", "}")
				if leg.reply {
					lines = append(lines, nat46SourceRawPolicyFixture(ctx, t, model, leg, false, saved)...)
				}
			}
			lines = append(lines, forward...)
			lines = append(lines, "}", "counter source_geometry_handoff {}", "chain source_geometry_observed {type filter hook forward priority 150;policy accept;meta mark & 0xff000000 != 0 counter name source_geometry_handoff;}")
			seenCallers := map[string]bool{}
			for _, program := range programs {
				if seenCallers[program.entry] || !strings.HasSuffix(program.entry, "_inet") {
					continue
				}
				seenCallers[program.entry] = true
				lines = append(lines, "chain "+program.entry+"_caller {", "jump "+program.entry)
				if strings.Contains(program.entry, "_original_") {
					lines = append(lines, "jump native_translation_facts_capture", "accept")
				} else {
					lines = append(lines, "return")
				}
				lines = append(lines, "}")
			}
		} else {
			for _, device := range []string{"lan10", "lan13", "nat46"} {
				lines = append(lines, fmt.Sprintf("chain source_geometry_final_%s {type filter hook egress device %q priority 0;policy drop;goto source_geometry_dispatch;}", device, device))
			}
			lines = append(lines, `chain source_geometry_late {type filter hook egress device "lan13" priority -1;policy accept;}`, "chain source_geometry_dispatch {")
			for _, leg := range transport.legs {
				wireField, rawField := "daddr", "daddr"
				if leg.reply {
					wireField, rawField = "saddr", "saddr"
				}
				protocol := "meta l4proto " + leg.protocol
				if leg.protocol == "icmp" {
					protocol = "icmpv6 type echo-request icmpv6 code 0"
					if leg.reply {
						protocol = "icmpv6 type echo-reply icmpv6 code 0"
					}
				}
				lines = append(lines, "ip6 "+wireField+" "+target.String()+" "+protocol+" goto "+leg.name+"_wire_physical")
				if leg.reply {
					proto := "meta l4proto " + leg.protocol
					if leg.protocol == "icmp" {
						proto = "icmp type echo-reply icmp code 0"
					}
					lines = append(lines, "ip "+rawField+" "+alias.String()+" "+proto+" goto "+leg.name+"_raw_policy")
				}
			}
			// Synthetic raw-origin gate: full shared raw policy/floor admission is
			// deliberately outside this component fixture.
			lines = append(lines, "ip daddr "+alias.String()+" meta mark & 0xff000000 == 0xd1000000 meta priority 0x1c00 accept", "ip daddr "+alias.String()+" meta mark & 0xff000000 == 0xd5000000 meta priority 0x1c00 accept", "drop", "}")
			for _, leg := range transport.legs {
				lines = append(lines, "chain "+leg.name+"_wire_physical {", "jump "+leg.name+"_wire_source", "jump "+leg.name+"_wire_target")
				for index := range 3 {
					if index == 0 && leg.protocol != "tcp" || index == 1 && leg.protocol != "udp" {
						continue
					}
					program := programs[fmt.Sprintf("%d_%s_%t_true", index, leg.protocol, leg.reply)]
					lines = append(lines, fmt.Sprintf("meta mark & 0x3ff == %d goto %s", saved[fmt.Sprintf("%d_%s", index, leg.protocol)].id, program.entry+"_caller"))
				}
				lines = append(lines, "drop", "}")
				if leg.reply {
					lines = append(lines, nat46SourceRawPolicyFixture(ctx, t, model, leg, true, saved)...)
				}
			}
			seenCallers := map[string]bool{}
			for _, program := range programs {
				if seenCallers[program.entry] || !strings.HasSuffix(program.entry, "_physical") {
					continue
				}
				seenCallers[program.entry] = true
				lines = append(lines, "chain "+program.entry+"_caller {", "jump "+program.entry, "accept", "}")
			}
		}
		lines = append(lines, "}")
	}
	lines = append(lines, `table netdev n46_source_endpoints {
 chain fixture_device {type filter hook ingress device "device0" priority 0;policy drop;}
 chain fixture_translator {type filter hook ingress device "translated0" priority 0;policy drop;}
 chain fixture_client {type filter hook ingress device "peer0" priority 0;policy drop;}
 }`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+";delete table netdev "+ownedTable+";delete table netdev n46_source_endpoints")
	})
	inspectNAT46TransportFixture(ctx, t, transport)
	inspectNAT46SourceGeometryFixture(ctx, t, "inet", inet)
	inspectNAT46SourceGeometryFixture(ctx, t, "netdev", physical)
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proof, err := ownershipProofFixture(t, b, now, 70*time.Second).InEpoch(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := renderer.prepareNativeOwnership(ctx, proof, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnershipPreparation(ctx, owned, now); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, owned.batch.data)
	publication, err := nativeSourceReceipt(ctx, owned)
	if err != nil {
		t.Fatal(err)
	}
	// This target is already a classified admitted device. Source-epoch GIDs
	// must remain usable while CFG geometry stays closed to that target.
	targetHistory := state.Classification{MACs: []string{"02:00:00:00:00:13"}, IPv4: []string{}, IPv6: []string{target.String()}}
	targetShadow, err := model.translatedClassification(ctx, targetHistory)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"inet", "netdev"} {
		packetNft(ctx, t, "add element "+family+" "+ownedTable+" "+classified4Set+" {"+strings.Join(targetShadow.IPv4, ",")+"};add element "+family+" "+ownedTable+" "+classified6Set+" {"+strings.Join(targetShadow.IPv6, ",")+"}")
	}

	publishSource := func() {
		t.Helper()
		prepared, err := sources.prepareSourceEpoch(ctx, publication, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := validateNAT46StaticOwnership(ctx, prepared); err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, prepared.batch.data)
		first, second := observeNAT46SourceEpochFixture(ctx, t)
		if err := sources.inspectSourceEpoch(ctx, first, second); err != nil {
			t.Fatal(err)
		}
	}
	publishGrants := func(timeout int) {
		t.Helper()
		logical := guardChanges{}
		for _, name := range grantSets {
			logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
		}
		for _, name := range []string{"lease_to4_tcp", "lease_to4_udp"} {
			value, err := json.Marshal(map[string]any{"elem": map[string]any{"timeout": timeout, "val": map[string]any{"concat": []any{"lan13", "02:00:00:00:00:13", alias.String(), client4.String(), 6053}}}})
			if err != nil {
				t.Fatal(err)
			}
			logical.Commands = append(logical.Commands, guardAdd("inet", name, []json.RawMessage{value}))
		}
		data, err := json.Marshal(logical)
		if err != nil {
			t.Fatal(err)
		}
		utc, started := time.Now().UTC(), time.Now()
		mapped, err := prepareMappedGuards(ctx, &preparedBatch{data: data, preparedAt: utc, startedAt: started, startBefore: utc.Add(preparationBudget)}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareNativeNAT46Guards(ctx, mapped, publication, model, utc)
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
		selected := []change{}
		for _, command := range complete.Commands {
			if command.Flush != nil && nat46SourceIsTargetRef(command.Flush.Set) {
				selected = append(selected, command)
			}
			if command.Add != nil {
				v := command.Add.Element
				if nat46SourceIsTargetRef(objectReference{Family: v.Family, Table: v.Table, Name: v.Name}) {
					selected = append(selected, command)
				}
			}
		}
		encoded, err := json.Marshal(guardChanges{Commands: selected})
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, encoded)
	}
	peer, device, translated := packetSocket(t, "peer0"), packetSocket(t, "device0"), packetSocket(t, "translated0")
	serial := 0
	transmit := func(value packetDatagram, input, output packetEndpoint, allowed bool) {
		t.Helper()
		serial++
		value.payload = fmt.Sprintf("source-geometry-%d", serial)
		sendPacket(ctx, t, input, packetFrame(t, value))
		if allowed {
			receivePacket(ctx, t, output, packetFrame(t, value), true)
		} else {
			rejectNATPayload(ctx, t, output, value.payload)
		}
	}
	// Conntrack facts outlive deleted fixture links. Give the mapped-context
	// fixture its own tuples rather than reusing the preceding fixture's
	// immutable original context, including the echo identifier/sequence.
	clientPort, ownerPort, echo := uint16(58000), uint16(58100), uint32(0xc0261001)
	if mapped {
		clientPort, ownerPort, echo = 59000, 59100, 0xc0271001
	}
	if shared {
		clientPort, ownerPort, echo = 60000, 60100, 0xc0281001
	}
	raw := packetDatagram{source: client4, destination: alias, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: clientPort, destinationPort: 6053, isTCP: true, tcpFlags: 2}
	wire := raw
	wire.source, wire.destination = client6, target
	wire.sourceMAC, wire.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
	transmit(raw, peer, translated, true)
	transmit(wire, translated, device, false)
	publishSource()
	transmit(raw, peer, translated, true)
	transmit(wire, translated, device, false)
	publishGrants(43)
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		for _, directory := range []bool{false, true} {
			if directory && protocol == "icmp" {
				continue
			}
			request, converted := raw, wire
			request.isTCP, converted.isTCP = protocol == "tcp", protocol == "tcp"
			request.isICMP, converted.isICMP = protocol == "icmp", protocol == "icmp"
			request.icmpType, converted.icmpType = 8, 128
			request.icmpData, converted.icmpData = echo, echo
			if !directory {
				request.destinationPort, converted.destinationPort = 6061, 6061
				request.sourcePort, converted.sourcePort = ownerPort, ownerPort
			}
			response := converted
			response.source, response.destination = target, client6
			response.sourcePort, response.destinationPort = converted.destinationPort, converted.sourcePort
			response.sourceMAC, response.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
			response.tcpFlags, response.icmpType = 18, 129
			returned := response
			returned.source, returned.destination = alias, client4
			returned.sourceMAC, returned.destinationMAC = "02:00:00:00:00:46", "02:00:00:00:01:46"
			returned.icmpType = 0
			transmit(response, device, translated, false)
			transmit(returned, translated, peer, false)
			transmit(request, peer, translated, true)
			transmit(converted, translated, device, true)
			transmit(response, device, translated, true)
			transmit(returned, translated, peer, true)
			if directory && protocol == "udp" {
				time.Sleep(2200 * time.Millisecond)
				transmit(returned, translated, peer, false)
				transmit(response, device, translated, true)
				transmit(returned, translated, peer, true)
			}
		}
	}
	// A current source GID must not borrow the UID namespace or another client.
	for _, mutation := range []string{"meta mark set 0xd5000001", "meta priority set 0x1c00", "meta mark set 0xf5000001", "ip6 saddr set fdca:1a2b:e046::ae8:40b", "tcp dport set 6061"} {
		transmit(raw, peer, translated, true)
		packetNft(ctx, t, "add rule netdev "+ownedTable+" source_geometry_late "+mutation)
		transmit(wire, translated, device, false)
		packetNft(ctx, t, "flush chain netdev "+ownedTable+" source_geometry_late")
	}
	// Physical-only liveness withdrawal leaves the early source handoff intact.
	packetNft(ctx, t, "flush set netdev "+ownedTable+" "+nativeNAT46StaticSourceLive)
	transmit(raw, peer, translated, true)
	before := guardFamilyCounter(ctx, t, "inet", ownedTable, "source_geometry_handoff")
	transmit(wire, translated, device, false)
	if guardFamilyCounter(ctx, t, "inet", ownedTable, "source_geometry_handoff") != before+1 {
		t.Fatal("source liveness withdrawal lost its early positive control")
	}
	publishSource()
	transmit(raw, peer, translated, true)
	transmit(wire, translated, device, true)
	// An administrator-owned flow remains current while directory grants close.
	ownerRaw, ownerWire := raw, wire
	ownerRaw.isTCP, ownerWire.isTCP = false, false
	ownerRaw.sourcePort, ownerWire.sourcePort = ownerPort+100, ownerPort+100
	ownerRaw.destinationPort, ownerWire.destinationPort = 6061, 6061
	publishGrants(1)
	time.Sleep(1200 * time.Millisecond)
	transmit(raw, peer, translated, true)
	transmit(wire, translated, device, false)
	transmit(ownerRaw, peer, translated, true)
	transmit(ownerWire, translated, device, true)
	publishGrants(43)
	clearedSource, err := prepareNAT46StaticOwnershipClear(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT46StaticOwnership(ctx, clearedSource); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, clearedSource.batch.data)
	transmit(ownerRaw, peer, translated, true)
	transmit(ownerWire, translated, device, false)
	ownerReply := ownerWire
	ownerReply.source, ownerReply.destination = target, client6
	ownerReply.sourcePort, ownerReply.destinationPort = ownerWire.destinationPort, ownerWire.sourcePort
	ownerReply.sourceMAC, ownerReply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
	transmit(ownerReply, device, translated, false)
	publishSource()
	transmit(ownerRaw, peer, translated, true)
	transmit(ownerWire, translated, device, true)
	transmit(ownerReply, device, translated, true)
	// Deny-only client history closes source geometry without removing its epoch.
	history := state.Classification{MACs: []string{"02:00:00:00:00:10"}, IPv4: []string{client4.String()}, IPv6: []string{target.String()}}
	shadow, err := model.translatedClassification(ctx, history)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"inet", "netdev"} {
		packetNft(ctx, t, "add element "+family+" "+ownedTable+" "+classified4Set+" {"+strings.Join(shadow.IPv4, ",")+"};add element "+family+" "+ownedTable+" "+classified6Set+" {"+strings.Join(shadow.IPv6, ",")+"}")
	}
	transmit(raw, peer, translated, true)
	transmit(wire, translated, device, false)
}

func nat46SourceIsTargetRef(ref objectReference) bool {
	for _, candidate := range nativeNAT46TargetGrantRefs() {
		if ref == candidate {
			return true
		}
	}
	return false
}

// This raw-reply fixture preserves ordering and the original root rule after
// tuple import. It is not the shared compiler's complete native floor.
func nat46SourceRawPolicyFixture(ctx context.Context, t *testing.T, model *nativeNAT46Model, leg nativeNAT46Leg, physical bool, saved map[string]nativePacketContext) []string {
	t.Helper()
	name := leg.name + "_raw_policy"
	lines := []string{"chain " + name + " {"}
	if physical {
		lines = append(lines, "jump "+leg.name+"_raw_source", "jump "+leg.name+"_raw_target")
	}
	for index := range 3 {
		scopes, err := model.rules.scopes(ctx, index, true, physical)
		if err != nil {
			t.Fatal(err)
		}
		for _, scope := range scopes {
			lines = append(lines, scope.text+" goto "+fmt.Sprintf("%s_rule_%d", name, index))
		}
	}
	lines = append(lines, "drop", "}")
	for index := range 3 {
		lines = append(lines, fmt.Sprintf("chain %s_rule_%d {", name, index), fmt.Sprintf("meta mark & 0x3ff != %d drop", saved[fmt.Sprintf("%d_%s", index, leg.protocol)].id))
		if index != 2 {
			lines = append(lines, "jump "+leg.name+"_raw_grant")
		}
		lines = append(lines, "accept", "}")
	}
	return lines
}

func inspectNAT46SourceGeometryFixture(ctx context.Context, t *testing.T, family string, graph map[string][]nativeScope) *guardTableObservation {
	t.Helper()
	schema := &guardTableSchema{sets: map[string]map[string]any{}, maps: map[string]map[string]any{}}
	nat46StaticSourceSchema(schema, family)
	nativeNAT46TargetGrantSchema(schema, family)
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", family, ownedTable), &listing); err != nil {
		t.Fatal(err)
	}
	observed := &guardTableObservation{sets: map[string]listedSet{}}
	headers, counts := map[string]bool{}, map[string]int{}
	collections := map[string]bool{}
	for _, raw := range listing.Objects[2:] {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		if value, found := object["counter"]; found {
			var counter struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(value, &counter) != nil || family != "inet" || counter.Name != "source_geometry_handoff" {
				t.Fatal("unexpected source geometry fixture counter")
			}
			continue
		}
		kind, fields, err := guardObject(raw)
		if err != nil {
			t.Fatal(err)
		}
		key := "name"
		if kind == "rule" {
			key = "chain"
		}
		var name string
		if err := json.Unmarshal(fields[key], &name); err != nil {
			t.Fatal(err)
		}
		if kind == "set" || kind == "map" {
			values := []json.RawMessage{}
			if element, found := fields["elem"]; found {
				if err := json.Unmarshal(element, &values); err != nil {
					t.Fatal(err)
				}
			}
			observed.sets[name] = listedSet{Elements: values}
			expected := schema.sets[name]
			if kind == "map" {
				expected = schema.maps[name]
			}
			if expected != nil {
				if _, err := checkGuardObject(fields, expected, true); err != nil {
					t.Fatal("source geometry collection header differs", family, name, err)
				}
				collections[name] = true
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
			t.Fatalf("source geometry graph differs for %s/%s: %v; actual=%s", family, name, err, raw)
		}
	}
	for name, rules := range graph {
		if !headers[name] || counts[name] != len(rules) {
			t.Fatal("source geometry graph is incomplete", family, name)
		}
	}
	for name := range schema.sets {
		if !collections[name] {
			t.Fatal("source geometry set is missing", family, name)
		}
	}
	for name := range schema.maps {
		if !collections[name] {
			t.Fatal("source geometry map is missing", family, name)
		}
	}
	return observed
}

// Read only the fixed source-channel collections after a data replacement.
// The full graph and collection schemas were already checked before traffic.
func observeNAT46SourceEpochFixture(ctx context.Context, t *testing.T) (*guardTableObservation, *guardTableObservation) {
	t.Helper()
	inet, netdev := &guardTableObservation{sets: map[string]listedSet{}}, &guardTableObservation{sets: map[string]listedSet{}}
	for _, ref := range []struct{ family, kind, name string }{{"inet", "map", nativeNAT46StaticSourceChannel}, {"inet", "set", nativeNAT46StaticSourceLive}, {"netdev", "set", nativeNAT46StaticSourceLive}, {"inet", "set", ownershipEpochSet}} {
		var listing struct {
			Objects []json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", ref.kind, ref.family, ownedTable, ref.name), &listing); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, raw := range listing.Objects {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			value, exists := object[ref.kind]
			if !exists {
				continue
			}
			var item struct {
				Name     string            `json:"name"`
				Elements []json.RawMessage `json:"elem"`
			}
			if err := json.Unmarshal(value, &item); err != nil || item.Name != ref.name {
				t.Fatal("fixed source channel observation changed name")
			}
			target := inet
			if ref.family == "netdev" {
				target = netdev
			}
			target.sets[ref.name] = listedSet{Elements: item.Elements}
			found = true
		}
		if !found {
			t.Fatal("fixed source channel observation is missing", ref.name)
		}
	}
	return inet, netdev
}
