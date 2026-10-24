//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// The source-NAT component remains separate from complete image admission.
// Exercise actual source rewriting, not a metadata-only simulated translator.
func TestKernelNamedUplinkNATRetainsSourceAndGrants(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "link", "add", "wan", "type", "veth", "peer", "name", "upstream0")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "wan")
	})
	for _, entry := range []struct{ link, mac string }{{"wan", "02:00:00:00:01:40"}, {"upstream0", "02:00:00:00:00:40"}} {
		packetIP(ctx, t, "link", "set", entry.link, "address", entry.mac)
		packetIP(ctx, t, "link", "set", entry.link, "up")
	}
	packetIP(ctx, t, "address", "add", "10.243.0.1/24", "dev", "wan")
	packetIP(ctx, t, "neighbor", "replace", "10.243.0.2", "dev", "wan", "lladdr", "02:00:00:00:00:40", "nud", "permanent")
	packetNft(ctx, t, `table inet uplink_nat_fixture {
 chain packet_priority {type filter hook forward priority -151;policy accept;
 meta priority set 5 meta mark set 0x6a0000
 }
 chain floor {type filter hook forward priority 0;policy drop;
 meta mark & 0xff000000 == 0xd1000000 accept
 meta mark & 0xff000000 == 0xd2000000 accept
 meta mark & 0xff000000 == 0xd3000000 accept
 meta mark & 0xff000000 == 0xd4000000 accept
 meta mark & 0xff000000 == 0xd5000000 accept
 meta mark & 0xff000000 == 0xd6000000 accept
 }
 chain mutate_before {type filter hook forward priority 151;policy accept;}
 chain mutate_after {type filter hook postrouting priority 110;policy accept;}
 chain source_nat {type nat hook postrouting priority srcnat;policy accept;
 iifname {"lan10","lan13"} oifname "wan" ip saddr {10.240.0.0/24,10.240.3.0/24} masquerade
 }
}
table netdev uplink_nat_endpoints {
 chain restored_priority {type filter hook egress device "wan" priority 1;policy accept;
 meta priority != 5 drop
 meta mark & 0x00ff0000 != 0x006a0000 drop
 }
 chain peer_endpoint {type filter hook ingress device "peer0" priority 0;policy drop;}
 chain device_endpoint {type filter hook ingress device "device0" priority 0;policy drop;}
 chain upstream_endpoint {type filter hook ingress device "upstream0" priority 0;policy drop;}
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable+"; delete table inet uplink_nat_fixture; delete table netdev uplink_nat_endpoints")
	})
	b := nativeAccessBaseline(t)
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: sourceClassPrefixes("10.243.0.1/32"), Roles: []policy.Role{}})
	for _, entry := range []struct{ iface, prefix string }{{"lan10", "10.240.0.0/24"}, {"lan13", "10.240.3.0/24"}} {
		b.NetworkModel.UplinkNAT = append(b.NetworkModel.UplinkNAT, policy.UplinkNAT{Interface: entry.iface, Sources: sourceClassPrefixes(entry.prefix), Addresses: []netip.Addr{netip.MustParseAddr("10.243.0.1")}})
	}
	owner := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "any", From: []policy.NetworkSelector{{Interface: "lan10"}, {Interface: "lan13"}}, To: []policy.NetworkSelector{{Interface: "wan"}}}
	deny := owner
	deny.Action = "deny"
	deny.Authorization = "inherit"
	deny.From = []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.11/32")}}
	directory := owner
	directory.Authorization = "directory"
	directory.Protocol = "tcp"
	directory.Ports = []uint16{6090}
	directoryUDP := directory
	directoryUDP.Protocol = "udp"
	directoryUDP.Ports = []uint16{6092}
	callback := directory
	callback.From, callback.To = []policy.NetworkSelector{{Interface: "wan"}}, []policy.NetworkSelector{{Interface: "lan13"}}
	callbackUDP := callback
	callbackUDP.Protocol, callbackUDP.Ports = "udp", []uint16{6092}
	late := owner
	late.Action = "deny"
	late.Authorization = "inherit"
	ownerTCP, ownerUDP := owner, owner
	ownerTCP.Protocol, ownerTCP.Ports = "tcp", []uint16{6061}
	ownerUDP.Protocol, ownerUDP.Ports = "udp", []uint16{6061}
	b.NetworkModel.Rules = []policy.NetworkRule{deny, directory, directoryUDP, callback, callbackUDP, ownerTCP, ownerUDP, owner, late}
	layout, err := newNativeAccessLayout(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	renderer, err := newRenderer(b)
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
	configProof, err := renderer.compiler.CompileOwnerConfiguration(ctx, 700)
	if err != nil {
		t.Fatal(err)
	}
	config, err := renderer.prepareConfiguration(ctx, configProof)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, config.batch.data)
	now := time.Now().UTC()
	proof, err := nativeOwnerOwnershipFixture(t, renderer.compiler, now).InEpoch(ctx, 701)
	if err != nil {
		t.Fatal(err)
	}
	published, err := renderer.prepareNativeOwnership(ctx, proof, now)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, published.batch.data)
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		logNativeAccessSchema(ctx, t, layout)
		t.Fatal(err)
	}
	receipt, err := nativeSourceReceipt(ctx, published)
	if err != nil {
		t.Fatal(err)
	}
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
			rules = append(rules, map[string]any{"id": direction + protocol, "direction": direction, "peer": map[string]any{"addresses": []string{"10.243.0.2/32"}}, "protocol": protocol, "destination_ports": []int{port}, "reason": "Synthetic source NAT grant"})
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
	if err != nil || len(candidate.Grants) != 4 {
		t.Fatalf("expected four grants, got %d: %v %v", len(candidate.Grants), err, candidate.Denials)
	}
	history := state.Classification{MACs: []string{"02:00:00:00:00:13"}, IPv4: []string{"10.240.3.10"}, IPv6: []string{}}
	install := func() {
		t.Helper()
		utc := time.Now().UTC()
		logical, err := renderer.prepare(ctx, replacement{authorization: authorization, cohort: history.MACs, now: utc})
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := prepareMappedGuards(ctx, logical, &history, nil)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareNativeGuardsWithSource(ctx, mapped, receipt, renderer.compiler.BaselineHash(), utc)
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
	peer, device, wan := packetSocket(t, "peer0"), packetSocket(t, "device0"), packetSocket(t, "upstream0")
	nextPort := uint16(56000)
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			request := packetDatagram{source: netip.MustParseAddr("10.240.3.10"), destination: netip.MustParseAddr("10.243.0.2"), sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13", destinationPort: 6061, isTCP: protocol == "tcp", tcpFlags: 2, payload: "source-nat-current-proof"}
			transmit := func(t *testing.T, value packetDatagram, input packetEndpoint, allowed bool) packetDatagram {
				t.Helper()
				nextPort++
				value.sourcePort = nextPort
				value.payload = fmt.Sprintf("%s-%d", value.payload, nextPort)
				wire := value
				wire.source = netip.MustParseAddr("10.243.0.1")
				sendPacket(ctx, t, input, packetFrame(t, value))
				if allowed {
					receivePacket(ctx, t, wan, packetFrame(t, wire), true)
				} else {
					rejectNATPayload(ctx, t, wan, value.payload)
				}
				return value
			}
			admitted := transmit(t, request, device, true)
			reply := admitted
			reply.source, reply.destination = admitted.destination, netip.MustParseAddr("10.243.0.1")
			reply.sourcePort, reply.destinationPort = admitted.destinationPort, admitted.sourcePort
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:40", "02:00:00:00:01:40"
			reply.tcpFlags = 18
			restored := reply
			restored.destination = admitted.source
			sendPacket(ctx, t, wan, packetFrame(t, reply))
			receivePacket(ctx, t, device, packetFrame(t, restored), true)
			// Same-MAC second IPv4 address must retain a distinct address identity.
			second := request
			second.source = netip.MustParseAddr("10.240.3.12")
			transmit(t, second, device, true)
			transmit(t, request, peer, false) // The same IP and MAC on the wrong wire.
			for _, mutation := range []struct{ name, expression string }{{"other owned source", "ip saddr set 10.240.3.12"}, {"other MAC owned source", "ip saddr set 10.240.3.11"}, {"unowned source", "ip saddr set 10.240.3.99"}, {"router source", "ip saddr set 10.240.3.1"}, {"other port", protocol + " dport set 6099"}} {
				t.Run(mutation.name, func(t *testing.T) {
					packetNft(ctx, t, "add rule inet uplink_nat_fixture mutate_before iifname lan13 "+mutation.expression)
					transmit(t, request, device, false)
					packetNft(ctx, t, "flush chain inet uplink_nat_fixture mutate_before")
				})
			}
			// An unclassified owner flow works with no grant. Its saved source class
			// must still retain an earlier host deny after the source address is erased.
			static := request
			static.source = netip.MustParseAddr("10.240.0.10")
			static.sourceMAC, static.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
			transmit(t, static, peer, true)
			blocked := static
			blocked.source = netip.MustParseAddr("10.240.0.11")
			transmit(t, blocked, peer, false)
			packetNft(ctx, t, "add rule inet uplink_nat_fixture mutate_before iifname lan10 ip saddr set 10.240.0.11")
			transmit(t, static, peer, false)
			packetNft(ctx, t, "flush chain inet uplink_nat_fixture mutate_before")
			delegated := request
			delegated.destinationPort = 6090
			if protocol == "udp" {
				delegated.destinationPort = 6092
			}
			transmit(t, delegated, device, true)
			// A WAN-initiated flow has a null SNAT binding. Its admitted reply
			// must keep its native source, rather than inventing a translation.
			callback := request
			callback.source, callback.destination = request.destination, request.source
			callback.sourceMAC, callback.destinationMAC = "02:00:00:00:00:40", "02:00:00:00:01:40"
			nextPort++
			callback.sourcePort, callback.destinationPort = nextPort, delegated.destinationPort
			callback.payload = fmt.Sprintf("null-binding-%s-%d", protocol, nextPort)
			sendPacket(ctx, t, wan, packetFrame(t, callback))
			receivePacket(ctx, t, device, packetFrame(t, callback), true)
			callbackReply := callback
			callbackReply.source, callbackReply.destination = callback.destination, callback.source
			callbackReply.sourcePort, callbackReply.destinationPort = callback.destinationPort, callback.sourcePort
			callbackReply.sourceMAC, callbackReply.destinationMAC = request.sourceMAC, request.destinationMAC
			callbackReply.tcpFlags = 18
			sendPacket(ctx, t, device, packetFrame(t, callbackReply))
			receivePacket(ctx, t, wan, packetFrame(t, callbackReply), true)
			// Delete only the physical current grant after confirmation and NAT.
			chain := "nat_fixture_withdraw"
			packetNft(ctx, t, "add chain netdev "+ownedTable+" "+chain+" {type filter hook egress device wan priority -1;policy accept;}")
			set := "native_id_lease_from4_" + protocol
			packetNft(ctx, t, "add rule netdev "+ownedTable+" "+chain+" "+protocol+" dport "+fmt.Sprint(delegated.destinationPort)+" delete @"+set+" { meta priority . (meta mark & 0xe000) . ip daddr . "+protocol+" dport }")
			transmit(t, delegated, device, false)
			packetNft(ctx, t, "flush chain netdev "+ownedTable+" "+chain+"; delete chain netdev "+ownedTable+" "+chain)
			install()
			transmit(t, delegated, device, true)
			for _, mutation := range []string{"ip saddr set 10.243.0.99", protocol + " dport set 6099", "meta mark set meta mark & 0x00ffffff"} {
				packetNft(ctx, t, "add rule inet uplink_nat_fixture mutate_after iifname lan13 "+mutation)
				transmit(t, delegated, device, false)
				packetNft(ctx, t, "flush chain inet uplink_nat_fixture mutate_after")
			}
			// An opaque source ID cannot outlive its actual source proof.
			packetNft(ctx, t, "add chain netdev "+ownedTable+" "+chain+" {type filter hook egress device wan priority -1;policy accept;}")
			packetNft(ctx, t, "add rule netdev "+ownedTable+" "+chain+" delete @"+nativeSourceLive4+" { (meta mark & 0xe000) . (meta priority & 0x3ff) }")
			transmit(t, request, device, false)
			packetNft(ctx, t, "flush chain netdev "+ownedTable+" "+chain+"; delete chain netdev "+ownedTable+" "+chain)
			// Refresh from the original proof; this is not a grant renewal.
			refreshed, err := renderer.prepareNativeOwnership(ctx, proof, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			executeGuardFixture(ctx, t, refreshed.batch.data)
			transmit(t, request, device, true)
			if protocol == "udp" {
				// Remove the original source epoch immediately before egress.
				old := transmit(t, request, device, true)
				packetNft(ctx, t, "flush set netdev "+ownedTable+" "+func() string { _, name := epochChannelNames(false); return name }())
				sendPacket(ctx, t, device, packetFrame(t, old))
				rejectNATPayload(ctx, t, wan, old.payload)
				refreshed, err := renderer.prepareNativeOwnership(ctx, proof, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				executeGuardFixture(ctx, t, refreshed.batch.data)
				transmit(t, request, device, true)
			}
		})
	}
	// Source/config epoch withdrawal also blocks already admitted connections.
	revocation, err := prepareNativeOwnershipClear(ctx)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, revocation.batch.data)
	static := packetDatagram{source: netip.MustParseAddr("10.240.0.10"), destination: netip.MustParseAddr("10.243.0.2"), sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: 59000, destinationPort: 6061, payload: "static-owner-without-NAS"}
	expected := static
	expected.source = netip.MustParseAddr("10.243.0.1")
	sendPacket(ctx, t, peer, packetFrame(t, static))
	receivePacket(ctx, t, wan, packetFrame(t, expected), true)
}

// A denied rewrite must not leak under a different source, listener or checksum.
// Match the unique payload independently of the proposed wire tuple.
func rejectNATPayload(ctx context.Context, t *testing.T, endpoint packetEndpoint, payload string) {
	t.Helper()
	deadline := time.Now().Add(300 * time.Millisecond)
	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		n, address, err := syscall.Recvfrom(endpoint.fd, buffer, 0)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		link, ok := address.(*syscall.SockaddrLinklayer)
		if ok && link.Pkttype != syscall.PACKET_OUTGOING && bytes.HasSuffix(buffer[:n], []byte(payload)) {
			t.Fatal("source NAT leaked a denied packet under an altered tuple")
		}
	}
}
