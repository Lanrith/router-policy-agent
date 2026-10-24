//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// This is the native owner component, not complete router admission. Positive
// directory grants, core bootstrap, translation and related errors stay gated.
func TestKernelNamedNativeOwnerOrderAndReplies(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	requireKernelHeaderMutation(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "link", "add", "wan", "type", "dummy")
	packetIP(ctx, t, "link", "add", "lan11", "type", "dummy")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "wan")
		packetIP(cleanup, t, "link", "delete", "lan11")
	})
	packetNft(ctx, t, `table netdev native_access_endpoints {
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
table inet native_access_floor {
 chain mandatory_floor { type filter hook forward priority 0; policy drop;
  udp dport 6080 drop
  tcp dport 6080 drop
  meta mark & 0xff000000 == 0xd1000000 accept
  meta mark & 0xff000000 == 0xd2000000 accept
  meta mark & 0xff000000 == 0xd3000000 accept
  meta mark & 0xff000000 == 0xd4000000 accept
 }
 chain change_after_confirmation { type filter hook forward priority 151; policy accept; }
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet native_access_floor; delete table netdev native_access_endpoints")
	})
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for episode, managed := range []bool{true, false} {
		for _, protocol := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("managed=%t/%s", managed, protocol), func(t *testing.T) {
				baseline := nativeAccessBaseline(t)
				baseline.NetworkModel.Rules[0].Protocol = protocol
				baseline.NetworkModel.Rules[0].Ports = []uint16{6053, 6080}
				peerTarget := baseline.NetworkModel.Rules[0].From[0]
				peerTarget.MAC = ""
				baseline.NetworkModel.Rules = slices.Insert(baseline.NetworkModel.Rules, 1, policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: protocol, Ports: []uint16{6061},
					From: []policy.NetworkSelector{{Interface: "lan13", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.3.0/24"), netip.MustParsePrefix("fdca:1a2b:3::/64")}}}, To: []policy.NetworkSelector{peerTarget}})
				lateDeny := baseline.NetworkModel.Rules[0]
				lateDeny.Action, lateDeny.Authorization = "deny", "inherit"
				lateDeny.Ports = []uint16{6053}
				baseline.NetworkModel.Rules = append(baseline.NetworkModel.Rules, lateDeny)
				baseline.NetworkModel.Rules[0].Ports = []uint16{6053, 6054, 6080}
				earlyRequirement := lateDeny
				earlyRequirement.Ports = []uint16{6054}
				if protocol == "udp" {
					earlyRequirement.Action, earlyRequirement.Authorization = "allow", "directory"
				}
				baseline.NetworkModel.Rules = append([]policy.NetworkRule{earlyRequirement}, baseline.NetworkModel.Rules...)
				for _, dimension := range []string{"interface", "MAC"} {
					scopedDeny := lateDeny
					source := scopedDeny.From[0]
					if dimension == "interface" {
						source.Interface = "lan13"
					} else {
						source.MAC = "02:00:00:00:00:ee"
					}
					scopedDeny.From = []policy.NetworkSelector{source}
					baseline.NetworkModel.Rules = append([]policy.NetworkRule{scopedDeny}, baseline.NetworkModel.Rules...)
				}
				if !managed {
					baseline.Zones = append(baseline.Zones, policy.Zone{Role: policy.Guest, VLAN: 11, Interfaces: []string{"lan11"},
						Networks: []netip.Prefix{netip.MustParsePrefix("10.240.1.0/24")}})
					baseline.NetworkModel.ManagedNetworks = []policy.Role{policy.Guest}
				}
				layout, err := newNativeAccessLayout(ctx, baseline)
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
				p, err := openProcess(ctx, "/usr/sbin/nft")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := p.close(); err != nil {
						t.Error(err)
					}
				})
				renderer, err := newRenderer(baseline)
				if err != nil {
					t.Fatal(err)
				}
				inspected := false
				install := func(sequence uint32) {
					t.Helper()
					configuration, err := renderer.compiler.CompileOwnerConfiguration(ctx, sequence)
					if err != nil {
						t.Fatal(err)
					}
					prepared, err := renderer.prepareConfiguration(ctx, configuration)
					if err != nil {
						t.Fatal(err)
					}
					executeGuardFixture(ctx, t, prepared.batch.data)
					now := time.Now().UTC()
					proof, err := nativeOwnerOwnershipFixture(t, renderer.compiler, now).InEpoch(ctx, sequence+1)
					if err != nil {
						t.Fatal(err)
					}
					ownership, err := renderer.prepareNativeOwnership(ctx, proof, now)
					if err != nil {
						t.Fatal(err)
					}
					executeGuardFixture(ctx, t, ownership.batch.data)
					if !inspected {
						if _, err := p.inspectGuards(ctx, layout); err != nil {
							logNativeAccessSchema(ctx, t, layout)
							t.Fatal("native access graph or epoch mirrors differ from code-owned schema", err)
						}
						inspected = true
					}
				}
				sequence := uint32(100 + episode*100) // #nosec G115 -- episode is 0 or 1.
				if protocol == "udp" {
					sequence += 20
				}
				install(sequence)
				if !managed {
					revocation, err := prepareNativeOwnershipClear(ctx)
					if err != nil {
						t.Fatal(err)
					}
					executeGuardFixture(ctx, t, revocation.batch.data)
				}
				for _, family := range []int{4, 6} {
					t.Run(fmt.Sprintf("ipv%d", family), func(t *testing.T) {
						source, target := netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("10.240.3.10")
						if family == 6 {
							source, target = netip.MustParseAddr("fdca:1a2b::10"), netip.MustParseAddr("fdca:1a2b:3::10")
						}
						original := packetDatagram{source: source, destination: target, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
							sourcePort: uint16(48000 + episode*100 + family), destinationPort: 6053, isTCP: protocol == "tcp", tcpFlags: 2, payload: "native-owner"} // #nosec G115 -- episode 0..1 and family 4/6 keep the port below 48107.
						transmit := func(datagram packetDatagram, reverse, allowed bool) {
							t.Helper()
							input, output := peer, device
							if reverse {
								input, output = device, peer
							}
							frame := packetFrame(t, datagram)
							sendPacket(ctx, t, input, frame)
							receivePacket(ctx, t, output, frame, allowed)
						}
						transmit(original, false, true)
						reply := original
						reply.source, reply.destination = target, source
						reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
						reply.sourcePort, reply.destinationPort = 6053, original.sourcePort
						reply.tcpFlags = 18
						transmit(reply, true, true)
						callback := reply
						callback.sourcePort, callback.destinationPort = original.sourcePort+30, 6053
						callback.tcpFlags = 2
						transmit(callback, true, false)
						if managed {
							owned := original
							owned.source, owned.destination = target, source
							owned.sourceMAC, owned.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
							owned.sourcePort, owned.destinationPort = original.sourcePort+70, 6061
							owned.tcpFlags = 2
							transmit(owned, true, true)
							spelling := "ip"
							if family == 6 {
								spelling = "ip6"
							}
							packetNft(ctx, t, "add rule inet native_access_floor change_after_confirmation iifname lan13 "+spelling+" saddr "+target.String()+" "+protocol+" dport 6061 "+spelling+" saddr set "+target.Next().String())
							owned.sourcePort++
							sendPacket(ctx, t, device, packetFrame(t, owned))
							substituted := owned
							substituted.source = target.Next()
							receivePacket(ctx, t, peer, packetFrame(t, substituted), false)
							packetNft(ctx, t, "flush chain inet native_access_floor change_after_confirmation")
							substituted.sourceMAC = "02:00:00:00:00:14"
							transmit(substituted, true, true)
							// An association can own several addresses in either
							// family; none may borrow another address's identity.
							sameMAC := owned
							sameMAC.sourcePort += 5
							sameMAC.payload = fmt.Sprintf("same-mac-%s-ipv%d", protocol, family)
							second := "10.240.3.12"
							if family == 6 {
								second = "fdca:1a2b:3::12"
							}
							packetNft(ctx, t, "add rule inet native_access_floor change_after_confirmation iifname lan13 "+spelling+" saddr "+target.String()+" "+protocol+" dport 6061 "+spelling+" saddr set "+second)
							sendPacket(ctx, t, device, packetFrame(t, sameMAC))
							rejectNATPayload(ctx, t, peer, sameMAC.payload)
							packetNft(ctx, t, "flush chain inet native_access_floor change_after_confirmation")
							sameMAC.source = netip.MustParseAddr(second)
							transmit(sameMAC, true, true)

						}
						wrongInterface := original
						wrongInterface.sourcePort += 35
						wrongFrame := packetFrame(t, wrongInterface)
						sendPacket(ctx, t, device, wrongFrame)
						receivePacket(ctx, t, device, wrongFrame, false)
						if managed {
							wrongTarget := original
							wrongTarget.sourcePort += 36
							packetIP(ctx, t, "neighbor", "replace", target.String(), "lladdr", "02:00:00:00:00:ee", "dev", "lan13", "nud", "permanent")
							transmit(wrongTarget, false, false)
							packetIP(ctx, t, "neighbor", "replace", target.String(), "lladdr", "02:00:00:00:00:13", "dev", "lan13", "nud", "permanent")
							transmit(wrongTarget, false, true)
						}
						for _, change := range []func(*packetDatagram){
							func(p *packetDatagram) { p.destinationPort = 6054 },
							func(p *packetDatagram) { p.source = p.source.Next() },
							func(p *packetDatagram) { p.sourceMAC = "02:00:00:00:00:ee" },
							func(p *packetDatagram) { p.isTCP = !p.isTCP },
							func(p *packetDatagram) { p.destinationPort = 6080 },
						} {
							changed := original
							changed.sourcePort += 40
							change(&changed)
							transmit(changed, false, false)
						}
						// A changed listener after confirmation must fail the actual
						// physical scope, even with the same connection and epoch.
						packetNft(ctx, t, "add rule inet native_access_floor change_after_confirmation "+protocol+" dport 6053 "+protocol+" dport set 6054")
						t.Cleanup(func() {
							cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
							defer done()
							packetNft(cleanup, t, "flush chain inet native_access_floor change_after_confirmation")
						})
						mutated := original
						mutated.sourcePort += 50
						frame := packetFrame(t, mutated)
						sendPacket(ctx, t, peer, frame)
						// Match the transformed segment too, so a leak at the new
						// listener cannot disappear from the negative observation.
						changed := mutated
						changed.destinationPort = 6054
						receivePacket(ctx, t, device, packetFrame(t, changed), false)
						packetNft(ctx, t, "flush chain inet native_access_floor change_after_confirmation")
						transmit(mutated, false, true)
						install(sequence + 2)
						transmit(original, false, false)
						transmit(reply, true, false)
						fresh := original
						fresh.sourcePort += 60
						transmit(fresh, false, true)
						sequence += 2
					})
				}
			})
		}
	}
}

func logNativeAccessSchema(ctx context.Context, t *testing.T, layout *guardLayout) {
	t.Helper()
	for _, family := range []string{"inet", "netdev"} {
		raw := kernelFixtureCommand(ctx, t, "list", "table", family, ownedTable)
		var actual struct {
			Objects []struct {
				Set  map[string]any `json:"set"`
				Rule *struct {
					Chain       string `json:"chain"`
					Expressions []any  `json:"expr"`
				} `json:"rule"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(raw, &actual); err != nil {
			t.Fatal(err)
		}
		rules := map[string][][]any{}
		for _, item := range actual.Objects {
			if item.Set != nil && item.Set["name"] == nativeSourceBits4 {
				delete(item.Set, "elem")
				delete(item.Set, "handle")
				t.Logf("synthetic raw source set header: %#v", item.Set)
			}
			if item.Rule != nil {
				rules[item.Rule.Chain] = append(rules[item.Rule.Chain], item.Rule.Expressions)
			}
		}
		expected, err := layout.schema(family)
		if err != nil {
			t.Fatal(err)
		}
		objectCount := 2 + len(expected.sets) + len(expected.maps) + len(expected.chains)
		for _, body := range expected.rules {
			objectCount += len(body)
		}
		t.Logf("synthetic %s object count actual=%d expected=%d", family, len(actual.Objects), objectCount)
		var identities struct {
			Objects []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(raw, &identities); err != nil {
			t.Fatal(err)
		}
		for _, object := range identities.Objects {
			for kind, data := range object {
				var fields struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(data, &fields); err != nil {
					t.Fatal(err)
				}
				if kind == "set" && expected.sets[fields.Name] == nil || kind == "map" && expected.maps[fields.Name] == nil ||
					kind == "chain" && expected.chains[fields.Name] == nil || kind == "counter" {
					t.Logf("unexpected synthetic %s %s object %q", family, kind, fields.Name)
				}
			}
		}
		names := make([]string, 0, len(expected.rules))
		for name := range expected.rules {
			names = append(names, name)
		}
		slices.Sort(names)
		logged := 0
		for _, name := range names {
			encoded, err := json.Marshal(expected.rules[name])
			if err != nil {
				t.Fatal(err)
			}
			var normalized [][]any
			if err := json.Unmarshal(encoded, &normalized); err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(rules[name], normalized) {
				continue
			}
			if len(rules[name]) != len(normalized) {
				t.Logf("synthetic %s/%s rule count actual=%d expected=%d", family, name, len(rules[name]), len(normalized))
				continue
			}
			for index, want := range normalized {
				if !reflect.DeepEqual(rules[name][index], want) {
					t.Logf("synthetic %s/%s/%d actual=%#v expected=%#v", family, name, index, rules[name][index], want)
					break
				}
			}
			logged++
			if logged >= 5 {
				break
			}
		}
	}
}

func nativeOwnerOwnershipFixture(t *testing.T, compiler *policy.Compiler, now time.Time) policy.Ownership {
	t.Helper()
	snapshot := nativeOwnerBindingsFixture(now)
	additional := snapshot.Records[0].Addresses[0]
	additional.IP = netip.MustParseAddr("10.240.3.12")
	additional.OwnershipID = "same-association-other-v4"
	snapshot.Records[0].Addresses = append(snapshot.Records[0].Addresses, additional)
	additional = snapshot.Records[0].Addresses[1]
	additional.IP = netip.MustParseAddr("fdca:1a2b:3::12")
	additional.OwnershipID = "same-association-other-v6"
	snapshot.Records[0].Addresses = append(snapshot.Records[0].Addresses, additional)
	proof, err := compiler.CompileOwnership(t.Context(), snapshot, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func nativeOwnerBindingsFixture(now time.Time) binding.Snapshot {
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "synthetic-native-ids", ObservedAt: now, Complete: true}
	for _, entry := range []struct{ mac, ipv4, ipv6, episode string }{
		{"02:00:00:00:00:13", "10.240.3.10", "fdca:1a2b:3::10", "first"},
		{"02:00:00:00:00:14", "10.240.3.11", "fdca:1a2b:3::11", "second"},
	} {
		snapshot.Records = append(snapshot.Records, binding.Record{MAC: entry.mac, NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: entry.episode, Addresses: []binding.Address{
			{IP: netip.MustParseAddr(entry.ipv4), Source: "kea_dhcp4", OwnershipID: entry.episode + "-lease4", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)},
			{IP: netip.MustParseAddr(entry.ipv6), Source: "qualified_ipv6", OwnershipID: entry.episode + "-lease6", ObservedAt: now, ValidUntil: now.Add(90 * time.Second)},
		}})
	}
	return snapshot
}
