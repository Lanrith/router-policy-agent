//go:build integration && kernel && linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

func TestKernelNamedCoreServicesWithoutDirectory(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "link", "add", "wan", "type", "dummy")
	packetIP(ctx, t, "link", "add", "services0", "type", "veth", "peer", "name", "service0")
	for _, entry := range []struct{ name, mac string }{{"services0", "02:00:00:00:01:30"}, {"service0", "02:00:00:00:00:30"}} {
		packetIP(ctx, t, "link", "set", entry.name, "address", entry.mac)
		packetIP(ctx, t, "link", "set", entry.name, "up")
	}
	packetIP(ctx, t, "address", "add", "10.241.254.1/24", "dev", "services0")
	packetIP(ctx, t, "-6", "address", "add", "fdca:1a2b:fe02::1/64", "dev", "services0", "nodad")
	for _, address := range []string{"10.241.254.10", "10.241.254.11", "10.241.254.40", "10.241.254.50", "fdca:1a2b:fe02::10", "fdca:1a2b:fe02::11", "fdca:1a2b:fe02::40", "fdca:1a2b:fe02::50"} {
		packetIP(ctx, t, "neighbor", "replace", address, "dev", "services0", "lladdr", "02:00:00:00:00:30", "nud", "permanent")
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "wan")
		packetIP(cleanup, t, "link", "delete", "services0")
	})
	packetNft(ctx, t, `table inet core_fixture {
 chain floor { type filter hook forward priority 0; policy drop;
 meta mark & 0xff000000 == 0xb1000000 accept
 meta mark & 0xff000000 == 0xb2000000 accept
 }
 chain after_confirmation { type filter hook forward priority 151; policy accept; }
 chain time_redirect { type nat hook prerouting priority dstnat; policy accept;
  iifname "lan13" udp dport 123 meta nfproto ipv4 dnat ip to 10.241.254.40
  iifname "lan13" udp dport 123 meta nfproto ipv6 dnat ip6 to fdca:1a2b:fe02::40
 }
}
table netdev core_endpoints {
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
 chain service_endpoint { type filter hook ingress device "service0" priority 0; policy drop; }
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet core_fixture; delete table netdev core_endpoints")
	})
	baseline := nativeAccessBaseline(t)
	baseline.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "any", From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}}}
	baseline.ProtectedNetworks = append(baseline.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: []netip.Prefix{netip.MustParsePrefix("10.240.3.1/32"), netip.MustParsePrefix("fdca:1a2b:3::1/128")}, Roles: []policy.Role{}})
	baseline.ProtectedNetworks = append(baseline.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P03", Networks: []netip.Prefix{netip.MustParsePrefix("10.241.254.0/24"), netip.MustParsePrefix("fdca:1a2b:fe02::/64")}, Roles: []policy.Role{}})
	for _, kind := range []string{"dns", "ntp", "authoritative", "metrics"} {
		suffix := "10"
		switch kind {
		case "ntp":
			suffix = "40"
		case "authoritative":
			suffix = "11"
		case "metrics":
			suffix = "50"
		}
		baseline.NetworkModel.CoreServices = append(baseline.NetworkModel.CoreServices, policy.CoreService{Kind: kind, Interface: "services0", Addresses: []netip.Addr{netip.MustParseAddr("10.241.254." + suffix), netip.MustParseAddr("fdca:1a2b:fe02::" + suffix)}, Clients: []policy.NetworkSelector{{Interface: "lan13", Addresses: []netip.Prefix{netip.MustParsePrefix("10.240.3.0/24"), netip.MustParsePrefix("fdca:1a2b:3::/64")}}}})
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
	history := state.Classification{MACs: []string{"02:00:00:00:00:13"}, IPv4: []string{"10.240.3.10"}, IPv6: []string{"fdca:1a2b:3::10"}}
	sealed, err := prepareMappedGuardSeal(ctx, history, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = prepareNativeGuards(ctx, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardSeal(ctx, sealed); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, sealed.batch.data)
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
	device, service, peer := packetSocket(t, "device0"), packetSocket(t, "service0"), packetSocket(t, "peer0")
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			for _, kind := range []string{"dns", "ntp", "authoritative", "metrics"} {
				if kind == "ntp" && protocol == "tcp" || kind == "metrics" && protocol == "udp" {
					continue
				}
				t.Run(fmt.Sprintf("ipv%d/%s/%s", family, protocol, kind), func(t *testing.T) {
					client, listener, remote := netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("10.241.254.10"), netip.MustParseAddr("198.51.100.2")
					port := uint16(53)
					if family == 6 {
						client, listener, remote = netip.MustParseAddr("fdca:1a2b:3::10"), netip.MustParseAddr("fdca:1a2b:fe02::10"), netip.MustParseAddr("2001:db8::123")
					}
					if kind == "ntp" {
						port = 123
						if family == 4 {
							listener = netip.MustParseAddr("10.241.254.40")
						} else {
							listener = netip.MustParseAddr("fdca:1a2b:fe02::40")
						}
					}
					if kind == "authoritative" {
						listener = netip.MustParseAddr("10.241.254.11")
						if family == 6 {
							listener = netip.MustParseAddr("fdca:1a2b:fe02::11")
						}
					}
					if kind == "metrics" {
						port = 9100
						listener = netip.MustParseAddr("10.241.254.50")
						if family == 6 {
							listener = netip.MustParseAddr("fdca:1a2b:fe02::50")
						}
					}
					request := packetDatagram{source: client, destination: listener, sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13", sourcePort: 54000 + uint16(family) + port, destinationPort: port, isTCP: protocol == "tcp", tcpFlags: 2, payload: "core-without-ownership"} // #nosec G115 -- family 4/6 and fixed listeners bound the port below 63110.
					actual := request
					if kind == "ntp" {
						request.destination = remote
					}
					sendPacket(ctx, t, device, packetFrame(t, request))
					receivePacket(ctx, t, service, packetFrame(t, actual), true)
					reply := actual
					reply.source, reply.destination = listener, client
					reply.sourcePort, reply.destinationPort = port, actual.sourcePort
					reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:30", "02:00:00:00:01:30"
					reply.tcpFlags = 18
					expected := reply
					if kind == "ntp" {
						expected.source = remote
					}
					sendPacket(ctx, t, service, packetFrame(t, reply))
					receivePacket(ctx, t, device, packetFrame(t, expected), true)
					spellingReply, gatewayReply := "ip", "10.240.3.1"
					if family == 6 {
						spellingReply, gatewayReply = "ip6", "fdca:1a2b:3::1"
					}
					packetNft(ctx, t, "add rule inet core_fixture after_confirmation iifname services0 "+protocol+" sport "+fmt.Sprint(port)+" "+spellingReply+" daddr set "+gatewayReply)
					alteredReply := expected
					alteredReply.destination = netip.MustParseAddr(gatewayReply)
					sendPacket(ctx, t, service, packetFrame(t, reply))
					receivePacket(ctx, t, device, packetFrame(t, alteredReply), false)
					packetNft(ctx, t, "flush chain inet core_fixture after_confirmation")

					// The declared service is static connectivity, even after all source,
					// configuration and delegated evidence has been withdrawn.
					withdrawal, err := prepareNativeOwnershipClear(ctx)
					if err != nil {
						t.Fatal(err)
					}
					executeGuardFixture(ctx, t, withdrawal.batch.data)
					sendPacket(ctx, t, service, packetFrame(t, reply))
					receivePacket(ctx, t, device, packetFrame(t, expected), true)
					wrong := actual
					wrong.sourcePort += 10
					wrong.destinationPort = 8443
					sendPacket(ctx, t, device, packetFrame(t, wrong))
					receivePacket(ctx, t, service, packetFrame(t, wrong), false)
					wrong = actual
					wrong.sourcePort += 11
					sendPacket(ctx, t, peer, packetFrame(t, wrong))
					receivePacket(ctx, t, service, packetFrame(t, wrong), false)
					spelling, gateway := "ip", "10.240.3.1"
					if family == 6 {
						spelling, gateway = "ip6", "fdca:1a2b:3::1"
					}
					for _, mutation := range []string{"listener", "router source", "lost tag"} {
						altered := actual
						altered.sourcePort += 30
						expression := protocol + " dport set 8443"
						expectedAltered := altered
						switch mutation {
						case "listener":
							expectedAltered.destinationPort = 8443
						case "router source":
							expression = spelling + " saddr set " + gateway
							expectedAltered.source = netip.MustParseAddr(gateway)
						case "lost tag":
							expression = "meta mark set meta mark & 0x00ff0000"
						}
						packetNft(ctx, t, "add rule inet core_fixture after_confirmation iifname lan13 "+spelling+" saddr "+client.String()+" "+protocol+" dport "+fmt.Sprint(port)+" "+expression)
						sendPacket(ctx, t, device, packetFrame(t, altered))
						receivePacket(ctx, t, service, packetFrame(t, expectedAltered), false)
						packetNft(ctx, t, "flush chain inet core_fixture after_confirmation")
					}

				})
			}
		}
	}
}
