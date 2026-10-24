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

// This fixture exercises native grant lifetime at physical egress. The private
// image remains gated on generated bootstrap, translator and floor integration.
func TestKernelNamedNativeDirectoryPhysicalRevocation(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "link", "add", "wan", "type", "dummy")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable+"; delete table inet native_directory_floor; delete table netdev native_directory_endpoints")
		packetIP(cleanup, t, "link", "delete", "wan")
	})
	packetNft(ctx, t, `table netdev native_directory_endpoints {
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
 }
 table inet native_directory_floor {
 chain mandatory { type filter hook forward priority 0; policy drop;
  meta mark & 0xff000000 == 0xd1000000 accept
  meta mark & 0xff000000 == 0xd2000000 accept
  meta mark & 0xff000000 == 0xd3000000 accept
  meta mark & 0xff000000 == 0xd4000000 accept
  meta mark & 0xff000000 == 0xd5000000 accept
  meta mark & 0xff000000 == 0xd6000000 accept
 }
 }`)
	baseline := nativeAccessBaseline(t)
	owner := baseline.NetworkModel.Rules[0]
	owner.Ports = []uint16{6061}
	delegated := policy.NetworkRule{Action: "allow", Authorization: "directory", Protocol: "any", From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}}
	fallback := delegated
	fallback.Authorization = "owner"
	baseline.NetworkModel.Rules = []policy.NetworkRule{owner, delegated, fallback}
	layout, err := newNativeAccessLayout(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	p, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Now().UTC()
	configuration, err := renderer.compiler.CompileOwnerConfiguration(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	config, err := renderer.prepareConfiguration(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, config.batch.data)
	ownership, err := nativeOwnerOwnershipFixture(t, renderer.compiler, now).InEpoch(ctx, 501)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := renderer.prepareNativeOwnership(ctx, ownership, now)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, owned.batch.data)
	_, _, _, input := renderFixture(t)
	input.Directory.ObservedAt = now
	input.Directory.Devices[0].MAC = "02:00:00:00:00:13"
	rules := []any{}
	for _, direction := range []string{"from_device", "to_device"} {
		for _, protocol := range []string{"tcp", "udp"} {
			port := 6090
			if protocol == "udp" {
				port = 6092
			}
			rules = append(rules, map[string]any{"id": direction + "-" + protocol, "direction": direction, "peer": map[string]any{"addresses": []string{"10.240.0.10/32", "fdca:1a2b::10/128"}}, "protocol": protocol, "destination_ports": []int{port}, "reason": "Synthetic native grant"})
		}
	}
	raw, err := json.Marshal(map[string]any{"schema_version": 1, "kind": "access", "vlan_role": "untrusted", "temporary": false, "rules": rules})
	if err != nil {
		t.Fatal(err)
	}
	groupPolicy := string(raw)
	input.Directory.Groups[1].Policy = &groupPolicy
	input.Bindings = nativeOwnerBindingsFixture(now)
	input.Now = now
	authorization, err := renderer.compiler.CompileAuthorization(ctx, input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(ctx)
	if err != nil || len(candidate.Grants) != 8 {
		t.Fatalf("expected eight compiled native grants, got %d: %v, %v", len(candidate.Grants), err, candidate.Denials)
	}
	history := state.Classification{MACs: []string{"02:00:00:00:00:13"}, IPv4: []string{"10.240.3.10"}, IPv6: []string{"fdca:1a2b:3::10"}}
	install := func() {
		t.Helper()
		logical, err := renderer.prepare(ctx, replacement{authorization: authorization, cohort: history.MACs, now: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareLayoutGuards(ctx, logical, &history, layout)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.run(ctx, commandInput{op: applyGuarded, guarded: prepared}); err != nil {
			t.Fatal(err)
		}
	}
	install()
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		logNativeAccessSchema(ctx, t, layout)
		t.Fatal(err)
	}
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, protocol := range []string{"tcp", "udp"} {
		for _, family := range []int{4, 6} {
			for _, fromDevice := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/ipv%d/from_device=%t", protocol, family, fromDevice), func(t *testing.T) {
					peerIP, deviceIP := netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("10.240.3.10")
					if family == 6 {
						peerIP, deviceIP = netip.MustParseAddr("fdca:1a2b::10"), netip.MustParseAddr("fdca:1a2b:3::10")
					}
					original := packetDatagram{source: peerIP, destination: deviceIP, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: 51000 + uint16(family), destinationPort: 6090, isTCP: protocol == "tcp", tcpFlags: 2, payload: "native-directory"} // #nosec G115 -- family is exactly 4 or 6.
					if protocol == "udp" {
						original.destinationPort = 6092
					}
					incoming, outgoing := peer, device
					if fromDevice {
						original.source, original.destination = deviceIP, peerIP
						original.sourceMAC, original.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
						original.sourcePort += 100
						incoming, outgoing = device, peer
					}
					transmit := func(packet packetDatagram, reverse, allowed bool) {
						t.Helper()
						in, out := incoming, outgoing
						if reverse {
							in, out = out, in
						}
						frame := packetFrame(t, packet)
						sendPacket(ctx, t, in, frame)
						receivePacket(ctx, t, out, frame, allowed)
					}
					transmit(original, false, true)
					reply := original
					reply.source, reply.destination = original.destination, original.source
					reply.sourcePort, reply.destinationPort = original.destinationPort, original.sourcePort
					reply.tcpFlags = 18
					reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
					if fromDevice {
						reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
					}
					transmit(reply, true, true)
					wrongProtocol := original
					wrongProtocol.isTCP = !wrongProtocol.isTCP
					wrongProtocol.sourcePort += 50
					transmit(wrongProtocol, false, false)
					absent := original
					absent.sourcePort += 10
					absent.destinationPort = 6091
					transmit(absent, false, false)
					wrong := original
					wrong.sourcePort += 11
					wrong.sourceMAC = "02:00:00:00:00:ee"
					if !fromDevice {
						wrong.source = peerIP.Next()
					}
					transmit(wrong, false, false)
					// Fault injection occurs after confirmation, at egress -1.
					// Only the physical proof is deleted; the logical grants and
					// source epoch stay unchanged. Counters prove both packets
					// reached this point with an admitted directory tag and lease.
					direction := "to"
					if fromDevice {
						direction = "from"
					}
					lease := nativeLeaseSet(fmt.Sprintf("lease_%s%d_%s", direction, family, protocol))
					address := "ip"
					if family == 6 {
						address = "ip6"
					}
					withdrawal := []string{
						"add counter netdev " + ownedTable + " native_withdrawal",
						"add chain netdev " + ownedTable + " native_withdrawal",
					}
					for _, iface := range []string{"lan10", "lan13"} {
						hook := "native_withdrawal_" + iface
						withdrawal = append(withdrawal,
							"add chain netdev "+ownedTable+" "+hook+" { type filter hook egress device \""+iface+"\" priority -1; policy accept; }",
							"add rule netdev "+ownedTable+" "+hook+" jump native_withdrawal")
					}
					for _, reverse := range []bool{false, true} {
						deviceField, peerField, portField := "saddr", "daddr", "dport"
						if fromDevice == reverse {
							deviceField, peerField = "daddr", "saddr"
						}
						if reverse {
							portField = "sport"
						}
						key := address + " " + deviceField + " . " + address + " " + peerField + " . " + protocol + " " + portField
						withdrawal = append(withdrawal, fmt.Sprintf("add rule netdev %s native_withdrawal meta mark & 0xff000000 == %#x %s @%s counter name native_withdrawal delete @%s { %s }", ownedTable, nativeDirectoryTag(reverse), key, lease, lease, key))
					}
					packetNft(ctx, t, strings.Join(withdrawal, "\n"))
					denied := original
					denied.sourcePort += 20
					transmit(denied, false, false)
					install()
					transmit(reply, true, false)
					if guardFamilyCounter(ctx, t, "netdev", ownedTable, "native_withdrawal") != 2 {
						t.Fatal("withdrawal did not occur after confirmation for both admitted directions")
					}
					packetNft(ctx, t, "flush chain netdev "+ownedTable+" native_withdrawal_lan10; delete chain netdev "+ownedTable+" native_withdrawal_lan10; flush chain netdev "+ownedTable+" native_withdrawal_lan13; delete chain netdev "+ownedTable+" native_withdrawal_lan13; flush chain netdev "+ownedTable+" native_withdrawal; delete chain netdev "+ownedTable+" native_withdrawal; delete counter netdev "+ownedTable+" native_withdrawal")
					// Existing owner permission is independent of delegated grant withdrawal.
					ownerPacket := original
					if !fromDevice && protocol == "tcp" {
						ownerPacket.sourcePort += 40
						ownerPacket.destinationPort = 6061
						transmit(ownerPacket, false, true)
					}
					install()
					transmit(denied, false, true)
				})
			}
		}
	}
	t.Run("physical grant expiry does not inherit the logical lifetime", func(t *testing.T) {
		expiry := packetDatagram{source: netip.MustParseAddr("10.240.3.10"), destination: netip.MustParseAddr("10.240.0.10"), sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13", sourcePort: 52900, destinationPort: 6092, payload: "native-expiry"}
		frame := packetFrame(t, expiry)
		sendPacket(ctx, t, device, frame)
		receivePacket(ctx, t, peer, frame, true)
		packetNft(ctx, t, "delete element netdev "+ownedTable+" native_lease_from4_udp { 10.240.3.10 . 10.240.0.10 . 6092 }; add element netdev "+ownedTable+" native_lease_from4_udp { 10.240.3.10 . 10.240.0.10 . 6092 timeout 1s }")
		timer := time.NewTimer(1200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		expiry.sourcePort++
		frame = packetFrame(t, expiry)
		sendPacket(ctx, t, device, frame)
		receivePacket(ctx, t, peer, frame, false)
		install()
		sendPacket(ctx, t, device, frame)
		receivePacket(ctx, t, peer, frame, true)
	})
	sealed, err := prepareMappedGuardSeal(ctx, history, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = prepareNativeGuards(ctx, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.run(ctx, commandInput{op: sealGuarded, guarded: sealed}); err != nil {
		t.Fatal(err)
	}
	inventory, err := p.inspectGuards(ctx, layout)
	if err != nil || inventory.leases != 0 {
		t.Fatal("native sealing left grants or lost physical classification", err)
	}
}
