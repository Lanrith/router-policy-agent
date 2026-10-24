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

func TestKernelNamedCoreDependenciesThroughSourceNAT(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	for _, pair := range []struct{ host, peer, hostMAC, peerMAC string }{{"services0", "service0", "02:00:00:00:01:30", "02:00:00:00:00:30"}, {"wan", "upstream0", "02:00:00:00:01:40", "02:00:00:00:00:40"}} {
		packetIP(ctx, t, "link", "add", pair.host, "type", "veth", "peer", "name", pair.peer)
		for _, link := range []struct{ name, mac string }{{pair.host, pair.hostMAC}, {pair.peer, pair.peerMAC}} {
			packetIP(ctx, t, "link", "set", link.name, "address", link.mac)
			packetIP(ctx, t, "link", "set", link.name, "up")
		}
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", pair.host)
		})
	}
	for _, entry := range []struct{ iface, address string }{{"services0", "10.241.254.1/24"}, {"services0", "fdca:1a2b:fe02::1/64"}, {"services0", "fdca:1a2b:fe03::1/64"}, {"wan", "10.243.0.1/24"}, {"wan", "fdca:1a2b:ee00::1/64"}} {
		args := []string{"address", "add", entry.address, "dev", entry.iface}
		if netip.MustParsePrefix(entry.address).Addr().Is6() {
			args = append([]string{"-6"}, args...)
			args = append(args, "nodad")
		}
		packetIP(ctx, t, args...)
	}
	for _, entry := range []struct{ iface, address, mac string }{{"services0", "10.241.254.10", "02:00:00:00:00:30"}, {"services0", "10.241.254.40", "02:00:00:00:00:30"}, {"services0", "fdca:1a2b:fe02::10", "02:00:00:00:00:30"}, {"services0", "fdca:1a2b:fe02::40", "02:00:00:00:00:30"}, {"services0", "fdca:1a2b:fe03::10", "02:00:00:00:00:30"}, {"wan", "10.243.0.2", "02:00:00:00:00:40"}, {"wan", "fdca:1a2b:ee00::2", "02:00:00:00:00:40"}, {"wan", "10.243.0.3", "02:00:00:00:00:40"}} {
		packetIP(ctx, t, "neighbor", "replace", entry.address, "dev", entry.iface, "lladdr", entry.mac, "nud", "permanent")
	}
	packetNft(ctx, t, `table inet core_dependency_fixture {
 chain floor {type filter hook forward priority 0;policy drop;
  meta mark & 0xff000000 == 0xb1000000 accept
  meta mark & 0xff000000 == 0xb2000000 accept
 }
 chain after_confirmation {type filter hook forward priority 151;policy accept;}
 chain after_source_nat {type filter hook postrouting priority 110;policy accept;}
 chain source_nat4 {type nat hook postrouting priority srcnat;policy accept;
  iifname "services0" oifname "wan" ip saddr 10.241.254.0/24 masquerade
 }
 chain source_nat6 {type nat hook postrouting priority srcnat;policy accept;
  iifname "services0" oifname "wan" ip6 saddr fdca:1a2b:fe02::/64 masquerade
 }
}
table netdev core_dependency_endpoints {
 chain service_endpoint {type filter hook ingress device "service0" priority 0;policy drop;}
 chain upstream_endpoint {type filter hook ingress device "upstream0" priority 0;policy drop;}
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet core_dependency_fixture; delete table netdev core_dependency_endpoints")
	})
	b := nativeAccessBaseline(t)
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "any", From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}}}
	b.ProtectedNetworks = append(b.ProtectedNetworks, policy.NetworkBlock{ProtectionID: "P01", Networks: []netip.Prefix{netip.MustParsePrefix("10.243.0.1/32"), netip.MustParsePrefix("fdca:1a2b:ee00::1/128")}, Roles: []policy.Role{}}, policy.NetworkBlock{ProtectionID: "P03", Networks: []netip.Prefix{netip.MustParsePrefix("10.241.254.0/24"), netip.MustParsePrefix("fdca:1a2b:fe02::/64"), netip.MustParsePrefix("fdca:1a2b:fe03::/64")}, Roles: []policy.Role{}})
	paths := []struct{ kind, address, remote, translated string }{{"dns", "10.241.254.10", "10.243.0.2", "10.243.0.1"}, {"ntp", "10.241.254.40", "10.243.0.2", "10.243.0.1"}, {"ntp_dns", "10.241.254.40", "10.243.0.2", "10.243.0.1"}, {"dns", "fdca:1a2b:fe02::10", "fdca:1a2b:ee00::2", "fdca:1a2b:ee00::1"}, {"ntp", "fdca:1a2b:fe02::40", "fdca:1a2b:ee00::2", "fdca:1a2b:ee00::1"}, {"ntp_dns", "fdca:1a2b:fe02::40", "fdca:1a2b:ee00::2", "fdca:1a2b:ee00::1"}, {"dns", "fdca:1a2b:fe03::10", "fdca:1a2b:ee00::2", ""}}
	for _, path := range paths {
		source, remote := netip.MustParseAddr(path.address), netip.MustParseAddr(path.remote)
		destination := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		if source.Is4() {
			destination = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}
		if path.kind == "ntp_dns" {
			destination = netip.PrefixFrom(remote, remote.BitLen())
		}
		entry := policy.CoreEgress{Kind: path.kind, Interface: "services0", Address: source, Destinations: []netip.Prefix{destination}, Masquerade: path.translated != ""}
		if entry.Masquerade {
			entry.TranslatedAddresses = []netip.Addr{netip.MustParseAddr(path.translated)}
		}
		b.NetworkModel.CoreEgress = append(b.NetworkModel.CoreEgress, entry)
	}
	layout, err := newNativeAccessLayout(ctx, b)
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
	process, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := process.inspectGuards(ctx, layout); err != nil {
		logNativeAccessSchema(ctx, t, layout)
		t.Fatal(err)
	}
	service, wan, wrongAttachment := packetSocket(t, "service0"), packetSocket(t, "upstream0"), packetSocket(t, "device0")
	for index, path := range paths {
		protocols, ports := nativeCoreTransport(path.kind)
		port := ports[0]
		for _, protocol := range protocols {
			t.Run(fmt.Sprintf("%s/%s/%s", path.kind, path.address, protocol), func(t *testing.T) {
				request := packetDatagram{source: netip.MustParseAddr(path.address), destination: netip.MustParseAddr(path.remote), sourceMAC: "02:00:00:00:00:30", destinationMAC: "02:00:00:00:01:30", sourcePort: 55000 + uint16(index)*100 + port, destinationPort: port, isTCP: protocol == "tcp", tcpFlags: 2, payload: "core-dependency-without-directory"} // #nosec G115 -- seven fixed cases keep this below 55800.
				expected := request
				if path.translated != "" {
					expected.source = netip.MustParseAddr(path.translated)
				}
				sendPacket(ctx, t, service, packetFrame(t, request))
				receivePacket(ctx, t, wan, packetFrame(t, expected), true)
				reply := request
				reply.source, reply.destination = expected.destination, expected.source
				reply.sourcePort, reply.destinationPort = port, request.sourcePort
				reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:40", "02:00:00:00:01:40"
				reply.tcpFlags = 18
				expectedReply := reply
				expectedReply.destination = request.source
				sendPacket(ctx, t, wan, packetFrame(t, reply))
				receivePacket(ctx, t, service, packetFrame(t, expectedReply), true)
				wrong := request
				wrong.sourcePort++
				wrong.destinationPort = 8443
				sendPacket(ctx, t, service, packetFrame(t, wrong))
				wrongExpected := wrong
				wrongExpected.source = expected.source
				receivePacket(ctx, t, wan, packetFrame(t, wrongExpected), false)
				wrong = request
				wrong.sourcePort += 2
				sendPacket(ctx, t, wrongAttachment, packetFrame(t, wrong))
				wrongExpected = wrong
				wrongExpected.source = expected.source
				receivePacket(ctx, t, wan, packetFrame(t, wrongExpected), false)
				spelling, badSource := "ip", "10.243.0.99"
				if request.source.Is6() {
					spelling, badSource = "ip6", "fdca:1a2b:ee00::99"
				}
				// Source changes before SNAT would disappear behind the same WAN
				// address. The all-packet guard must reject them before rewriting.
				beforeSource := "10.241.254.99"
				if request.source.Is6() {
					beforeSource = "fdca:1a2b:fe02::99"
				}
				for _, expression := range []string{spelling + " saddr set " + beforeSource, protocol + " dport set 8443"} {
					altered := request
					altered.sourcePort += 30
					altered.payload = "before-SNAT-" + expression
					packetNft(ctx, t, "add rule inet core_dependency_fixture after_confirmation iifname services0 "+expression)
					sendPacket(ctx, t, service, packetFrame(t, altered))
					rejectNATPayload(ctx, t, wan, altered.payload)
					packetNft(ctx, t, "flush chain inet core_dependency_fixture after_confirmation")
				}
				for _, mutation := range []string{"wrong source", "wrong port", "lost tag"} {
					altered := request
					altered.sourcePort += 10
					expression := spelling + " saddr set " + badSource
					alteredExpected := expected
					alteredExpected.sourcePort = altered.sourcePort
					alteredExpected.source = netip.MustParseAddr(badSource)
					if mutation == "wrong port" {
						expression = protocol + " dport set 8443"
						alteredExpected.source = expected.source
						alteredExpected.destinationPort = 8443
					}
					if mutation == "lost tag" {
						expression = "meta mark set meta mark & 0x00ff0000"
						alteredExpected.source = expected.source
					}
					packetNft(ctx, t, "add rule inet core_dependency_fixture after_source_nat iifname services0 "+spelling+" daddr "+path.remote+" "+protocol+" dport "+fmt.Sprint(port)+" "+expression)
					sendPacket(ctx, t, service, packetFrame(t, altered))
					receivePacket(ctx, t, wan, packetFrame(t, alteredExpected), false)
					packetNft(ctx, t, "flush chain inet core_dependency_fixture after_source_nat")
				}
				if path.kind == "ntp_dns" && request.source.Is4() {
					wrong = request
					wrong.sourcePort += 20
					wrong.destination = netip.MustParseAddr("10.243.0.3")
					wrongExpected = wrong
					wrongExpected.source = expected.source
					sendPacket(ctx, t, service, packetFrame(t, wrong))
					receivePacket(ctx, t, wan, packetFrame(t, wrongExpected), false)
				}
			})
		}
	}
}
