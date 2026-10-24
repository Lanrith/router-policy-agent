//go:build integration && kernel && linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestKernelNamedPhysicalFloorAndSourcePairing(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	for _, pair := range []struct{ host, peer, hostMAC, peerMAC, address, neighbor string }{
		{"wan", "upstream0", "02:00:00:00:01:40", "02:00:00:00:00:40", "10.243.0.1/24", "10.243.0.2"},
		{"spare", "unknown0", "02:00:00:00:01:50", "02:00:00:00:00:50", "10.242.0.1/24", "10.242.0.2"},
		{"services0", "service0", "02:00:00:00:01:30", "02:00:00:00:00:30", "10.241.254.1/24", "10.241.254.10"},
	} {
		packetIP(ctx, t, "link", "add", pair.host, "type", "veth", "peer", "name", pair.peer)
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", pair.host)
		})
		for _, entry := range []struct{ name, mac string }{{pair.host, pair.hostMAC}, {pair.peer, pair.peerMAC}} {
			packetIP(ctx, t, "link", "set", entry.name, "address", entry.mac)
			packetIP(ctx, t, "link", "set", entry.name, "up")
		}
		packetIP(ctx, t, "address", "add", pair.address, "dev", pair.host)
		packetIP(ctx, t, "neighbor", "replace", pair.neighbor, "dev", pair.host, "lladdr", pair.peerMAC, "nud", "permanent")
	}
	packetIP(ctx, t, "link", "add", "lan11", "type", "dummy")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "lan11")
	})
	packetIP(ctx, t, "-6", "address", "add", "fdca:1a2b:fe02::1/64", "dev", "services0", "nodad")
	packetIP(ctx, t, "neighbor", "replace", "fdca:1a2b:fe02::10", "dev", "services0", "lladdr", "02:00:00:00:00:30", "nud", "permanent")
	packetNft(ctx, t, `table inet physical_floor_fixture {
 chain provisional {type filter hook forward priority 0;policy drop;
 meta mark & 0xff000000 == 0xd3000000 accept
 meta mark & 0xff000000 == 0xd4000000 accept
 meta mark & 0xff000000 == 0xb1000000 accept
 meta mark & 0xff000000 == 0xb2000000 accept
 }
 chain mutate_after_confirmation {type filter hook forward priority 151;policy accept;}
}
table netdev physical_floor_endpoints {
 chain peer_endpoint {type filter hook ingress device "peer0" priority 0;policy drop;}
 chain device_endpoint {type filter hook ingress device "device0" priority 0;policy drop;}
 chain upstream_endpoint {type filter hook ingress device "upstream0" priority 0;policy drop;}
 chain unused_endpoint {type filter hook ingress device "unknown0" priority 0;policy drop;}
 chain service_endpoint {type filter hook ingress device "service0" priority 0;policy drop;}
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable+"; delete table inet physical_floor_fixture; delete table netdev physical_floor_endpoints")
	})
	b := nativeCoreBaseline(t)
	b.Zones = append(b.Zones, policy.Zone{Role: policy.Guest, VLAN: 11, Interfaces: []string{"lan11"}, Networks: sourceClassPrefixes("10.240.1.0/24")})
	b.NetworkModel.ManagedNetworks = []policy.Role{policy.Guest}
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: sourceClassPrefixes("10.240.0.1/32", "10.240.3.1/32", "fdca:1a2b::1/128", "fdca:1a2b:3::1/128", "10.243.0.1/32"), Roles: []policy.Role{}}, policy.NetworkBlock{ProtectionID: "P03", Networks: sourceClassPrefixes("10.240.3.20/32", "fdca:1a2b:3::20/128"), Roles: []policy.Role{}})
	b.NetworkModel.ServicePrefixes = sourceClassPrefixes("10.241.254.0/24", "fdca:1a2b:fe02::/64")
	b.NetworkModel.CoreServices[0].Clients = []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.0/24", "fdca:1a2b::/64")}}
	scoped := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{6061}, From: []policy.NetworkSelector{
		{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.10/32", "fdca:1a2b::10/128")},
		{Interface: "lan11", Addresses: sourceClassPrefixes("10.240.0.20/32", "fdca:1a2b::20/128")},
	}, To: []policy.NetworkSelector{
		{Interface: "lan13", Addresses: sourceClassPrefixes("10.240.3.10/32", "fdca:1a2b:3::10/128")},
		{Interface: "lan11", Addresses: sourceClassPrefixes("10.240.3.20/32", "fdca:1a2b:3::20/128")},
	}}
	scopedUDP := scoped
	scopedUDP.Protocol = "udp"
	broad := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "any", From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}}
	b.NetworkModel.Rules = []policy.NetworkRule{scoped, scopedUDP, broad}
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
	proof, err := renderer.compiler.CompileOwnerConfiguration(ctx, 800)
	if err != nil {
		t.Fatal(err)
	}
	config, err := renderer.prepareConfiguration(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, config.batch.data)
	p, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		logNativeAccessSchema(ctx, t, layout)
		t.Fatal(err)
	}
	peer, device, wan, unknown, service := packetSocket(t, "peer0"), packetSocket(t, "device0"), packetSocket(t, "upstream0"), packetSocket(t, "unknown0"), packetSocket(t, "service0")
	nextPort := uint16(57000)
	for _, protocol := range []string{"tcp", "udp"} {
		for _, family := range []int{4, 6} {
			t.Run(fmt.Sprintf("%s/ipv%d", protocol, family), func(t *testing.T) {
				source, target, otherSource, otherTarget, gateway, management, wrongZone, spelling := "10.240.0.10", "10.240.3.10", "10.240.0.20", "10.240.3.20", "10.240.0.1", "10.241.0.20", "10.240.3.99", "ip"
				if family == 6 {
					source, target, otherSource, otherTarget, gateway, management, wrongZone, spelling = "fdca:1a2b::10", "fdca:1a2b:3::10", "fdca:1a2b::20", "fdca:1a2b:3::20", "fdca:1a2b::1", "::1", "fdca:1a2b:3::99", "ip6"
				}
				original := packetDatagram{source: netip.MustParseAddr(source), destination: netip.MustParseAddr(target), sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", destinationPort: 6061, isTCP: protocol == "tcp", tcpFlags: 2, payload: "physical-floor"}
				transmit := func(t *testing.T, value packetDatagram, input, output packetEndpoint, allowed bool) packetDatagram {
					t.Helper()
					nextPort++
					value.sourcePort = nextPort
					value.payload = fmt.Sprintf("floor-%d", nextPort)
					sendPacket(ctx, t, input, packetFrame(t, value))
					if allowed {
						receivePacket(ctx, t, output, packetFrame(t, value), true)
					} else {
						rejectNATPayload(ctx, t, output, value.payload)
					}
					return value
				}
				admitted := transmit(t, original, peer, device, true)
				// The later broad permission makes a real new flow valid. It must not make
				// an already admitted partial rule borrow a different endpoint alternative.
				other := original
				other.source = netip.MustParseAddr(otherSource)
				transmit(t, other, peer, device, true)
				packetNft(ctx, t, "add rule inet physical_floor_fixture mutate_after_confirmation iifname lan10 "+spelling+" saddr set "+otherSource)
				transmit(t, original, peer, device, false)
				packetNft(ctx, t, "flush chain inet physical_floor_fixture mutate_after_confirmation")
				reply := admitted
				reply.source, reply.destination = admitted.destination, admitted.source
				reply.sourcePort, reply.destinationPort = admitted.destinationPort, admitted.sourcePort
				reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
				reply.tcpFlags = 18
				sendPacket(ctx, t, device, packetFrame(t, reply))
				receivePacket(ctx, t, peer, packetFrame(t, reply), true)
				packetNft(ctx, t, "add rule inet physical_floor_fixture mutate_after_confirmation iifname lan13 "+spelling+" saddr set "+otherTarget)
				sendPacket(ctx, t, device, packetFrame(t, reply))
				rejectNATPayload(ctx, t, peer, reply.payload)
				packetNft(ctx, t, "flush chain inet physical_floor_fixture mutate_after_confirmation")
				wide := original
				wide.destinationPort = 6062
				for _, expression := range []string{spelling + " saddr set " + gateway, spelling + " saddr set " + wrongZone, spelling + " daddr set " + management, "meta mark set 0 meta priority set 0"} {
					packetNft(ctx, t, "add rule inet physical_floor_fixture mutate_after_confirmation iifname lan10 "+expression)
					transmit(t, wide, peer, device, false)
					packetNft(ctx, t, "flush chain inet physical_floor_fixture mutate_after_confirmation")
				}
				// Delegation ceilings do not prohibit this owner flow.
				packetIP(ctx, t, "neighbor", "replace", otherTarget, "dev", "lan13", "lladdr", "02:00:00:00:00:13", "nud", "permanent")
				limited := wide
				limited.destination = netip.MustParseAddr(otherTarget)
				transmit(t, limited, peer, device, true)
				dns := original
				dns.destinationPort = 53
				dns.destination = netip.MustParseAddr("10.241.254.10")
				if family == 6 {
					dns.destination = netip.MustParseAddr("fdca:1a2b:fe02::10")
				}
				transmit(t, dns, peer, service, true)
				dns.destinationPort = 8443
				transmit(t, dns, peer, service, false)
				if family == 4 {
					unused := wide
					unused.destination = netip.MustParseAddr("10.242.0.2")
					transmit(t, unused, peer, unknown, false)
					external := wide
					external.source = netip.MustParseAddr("10.243.0.2")
					external.sourceMAC, external.destinationMAC = "02:00:00:00:00:40", "02:00:00:00:01:40"
					transmit(t, external, wan, device, true)
					external.source = netip.MustParseAddr("10.241.254.99")
					transmit(t, external, wan, device, false)
				}
			})
		}
	}
}
