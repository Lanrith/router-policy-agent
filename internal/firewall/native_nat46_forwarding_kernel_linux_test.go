//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Exercise the complete native/raw/wire graph with a real userspace
// translator. Binding and delegated grant inputs remain synthetic. This is
// separate from installed profile admission and private image qualification.
func TestKernelNamedNAT46JoinedTAYGA(t *testing.T) {
	testKernelNamedNAT46JoinedTAYGA(t, false, false)
}

func TestKernelNamedNAT46JoinedTAYGAUID4(t *testing.T) {
	testKernelNamedNAT46JoinedTAYGA(t, true, false)
}

func TestKernelNamedNAT46JoinedTAYGAConfiguration(t *testing.T) {
	testKernelNamedNAT46JoinedTAYGA(t, false, true)
}

func testKernelNamedNAT46JoinedTAYGA(t *testing.T, managedClient, configurationOnly bool) {
	t.Helper()
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "link", "add", "wan", "type", "dummy")
	packetIP(ctx, t, "tuntap", "add", "dev", "nat46", "mode", "tun")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "nat46")
		packetIP(cleanup, t, "link", "delete", "wan")
	})
	packetIP(ctx, t, "link", "set", "nat46", "up")
	packetIP(ctx, t, "address", "add", "10.250.0.1/32", "dev", "nat46")
	packetIP(ctx, t, "-6", "address", "add", "fdca:1a2b:ffff::1/128", "dev", "nat46", "nodad")
	packetIP(ctx, t, "route", "add", "10.250.0.0/24", "dev", "nat46")
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:e046::/96", "dev", "nat46")
	b := nat46ForwardingBaseline(t)
	for index := 1; index < 6; index++ {
		mapping := policy.NAT46{ID: fmt.Sprintf("mapped%d", index), Alias: netip.MustParseAddr(fmt.Sprintf("10.250.0.%d", 20+index)), Target: netip.MustParseAddr(fmt.Sprintf("fdca:1a2b:3::%x", 16+index)), Ready: true}
		b.NAT46 = append(b.NAT46, mapping)
		packetIP(ctx, t, "neighbor", "replace", mapping.Target.String(), "dev", "lan13", "lladdr", "02:00:00:00:00:13", "nud", "permanent")
	}
	if managedClient {
		b.NetworkModel.ManagedNetworks = []policy.Role{policy.Trusted, policy.Untrusted}
	}
	if configurationOnly {
		b.NetworkModel.ManagedNetworks = []policy.Role{}
		b.NetworkModel.Rules = b.NetworkModel.Rules[2:]
	} else {
		// Exercise explicit directory TCP and inherited directory UDP against
		// the real target policy hidden by the original TUN output interface.
		b.NetworkModel.Rules[1].Authorization = "inherit"
		deny := b.NetworkModel.Rules[2]
		deny.Action, deny.Authorization, deny.Protocol, deny.Ports = "deny", "inherit", "udp", []uint16{6062}
		reverse := deny
		reverse.From, reverse.To, reverse.Ports = deny.To, deny.From, []uint16{61999}
		if managedClient {
			reverse.Ports = []uint16{64999}
		}
		b.NetworkModel.Rules = append([]policy.NetworkRule{deny, reverse}, b.NetworkModel.Rules...)
	}
	layout, err := newNativeNAT46AccessLayout(ctx, b)
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
		packetNft(cleanup, t, "delete table inet "+ownedTable+";delete table netdev "+ownedTable)
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
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		logNativeAccessSchema(ctx, t, layout)
		t.Fatal("complete joined graph differs from its immutable schema", err)
	}
	packetNft(ctx, t, `table netdev n46_join_endpoints {
 chain peer_endpoint {type filter hook ingress device "peer0" priority 0;policy drop;}
 chain device_endpoint {type filter hook ingress device "device0" priority 0;policy drop;}
}
table netdev n46_join_physical_trace {
 counter tun_before {}
 counter tun_after {}
 counter target_before {}
 counter target_after {}
 counter target_source_kind {}
 counter target_source_epoch {}
 counter target_mac {}
 counter wire_reply_before {}
 counter wire_reply_after {}
 counter raw_reply_before {}
 counter raw_reply_after {}
 chain tun_before {type filter hook egress device "nat46" priority -1;policy accept;
 ip daddr 10.250.0.20 udp dport 6061 counter name tun_before
 ip6 saddr fdca:1a2b:3::10 udp sport 6061 counter name wire_reply_before
 }
 chain tun_after {type filter hook egress device "nat46" priority 1;policy accept;
 ip daddr 10.250.0.20 udp dport 6061 counter name tun_after
 ip6 saddr fdca:1a2b:3::10 udp sport 6061 counter name wire_reply_after
 }
 chain target_before {type filter hook egress device "lan13" priority -1;policy accept;
 ip6 daddr fdca:1a2b:3::10 udp dport 6061 counter name target_before
 ip6 daddr fdca:1a2b:3::10 udp dport 6061 meta mark & 0xff000000 == 0xf1000000 counter name target_source_kind
 ip6 daddr fdca:1a2b:3::10 udp dport 6061 meta priority & 0xfffffc00 == 0x1c00 counter name target_source_epoch
 ip6 daddr fdca:1a2b:3::10 udp dport 6061 ether daddr 02:00:00:00:00:13 counter name target_mac
 }
 chain client_before {type filter hook egress device "lan10" priority -1;policy accept;
 ip saddr 10.250.0.20 udp sport 6061 counter name raw_reply_before
 }
 chain client_after {type filter hook egress device "lan10" priority 1;policy accept;
 ip saddr 10.250.0.20 udp sport 6061 counter name raw_reply_after
 }
 chain target_after {type filter hook egress device "lan13" priority 1;policy accept;
 ip6 daddr fdca:1a2b:3::10 udp dport 6061 counter name target_after
 }
}`)
	traceNAT46JoinedPackets(ctx, t)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		if t.Failed() {
			t.Logf("synthetic physical counters: %s", kernelFixtureCommand(cleanup, t, "list", "table", "netdev", "n46_join_physical_trace"))
			for _, name := range []string{"native_n46_static_bindings6", "native_n46_static_source_live", "native_source_epoch6", "current_ownership6"} {
				t.Logf("synthetic physical source proof %s: %s", name, kernelFixtureCommand(cleanup, t, "list", "set", "netdev", ownedTable, name))
			}
		}
		packetNft(cleanup, t, "delete table netdev n46_join_endpoints;delete table netdev n46_join_physical_trace")
	})
	startNAT46JoinedTranslator(ctx, t, b)
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := renderer.prepareNativeNAT46Configuration(ctx, configurationProofFixture(t, b), layout.nat46Sources())
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, configuration.batch.data)
	var publication *nativeSourcePublication
	if !configurationOnly {
		now := time.Now().UTC()
		record := binding.Record{MAC: "02:00:00:00:00:13", NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: "synthetic-joined-targets"}
		for index, mapping := range b.NAT46 {
			record.Addresses = append(record.Addresses, binding.Address{IP: mapping.Target, Source: "qualified_ipv6", OwnershipID: fmt.Sprintf("synthetic-target-%d", index), ObservedAt: now, ValidUntil: now.Add(80 * time.Second)})
		}
		snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "synthetic-joined-targets", ObservedAt: now, Complete: true, Records: []binding.Record{record}}
		if managedClient {
			snapshot.Records = append(snapshot.Records, binding.Record{MAC: "02:00:00:00:00:10", NAS: "synthetic-nas", Interface: "lan10", VLAN: 10, AssociatedAt: now, AssociationID: "synthetic-client", Addresses: []binding.Address{{IP: netip.MustParseAddr("10.240.0.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-client4", ObservedAt: now, ValidUntil: now.Add(80 * time.Second)}}})
		}
		proof, err := renderer.compiler.CompileOwnership(ctx, snapshot, now, policy.CaptureAge())
		if err != nil {
			t.Fatal(err)
		}
		proof, err = proof.InEpoch(ctx, 7)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := renderer.prepareNativeOwnership(ctx, proof, now)
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, owned.batch.data)
		publication, err = nativeSourceReceipt(ctx, owned)
		if err != nil {
			t.Fatal(err)
		}
		source, err := layout.nat46Sources().prepareSourceEpoch(ctx, publication, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, source.batch.data)
	}
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	client, alias, target := netip.MustParseAddr("10.240.0.10"), b.NAT46[0].Alias, b.NAT46[0].Target
	embedded := netip.MustParseAddr("fdca:1a2b:e046::af0:a")
	serial := uint16(61000)
	if managedClient {
		serial = 64000
	}
	if configurationOnly {
		serial = 65000
	}
	protocol := "udp"
	request := func(listener uint16, allowed bool) packetDatagram {
		t.Helper()
		serial++
		packet := packetDatagram{source: client, destination: alias, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: serial, destinationPort: listener, payload: fmt.Sprintf("joined-request-%d", serial)}
		if listener == 6063 {
			packet.sourcePort = 61999
			if managedClient {
				packet.sourcePort = 64999
			}
		}
		if protocol == "tcp" {
			packet.isTCP, packet.tcpFlags, packet.sequence, packet.payload = true, 2, 100, ""
		}
		if protocol == "echo" {
			packet.isICMP, packet.icmpType, packet.icmpData = true, 8, uint32(serial)<<16|1
		}
		sendPacket(ctx, t, peer, packetFrame(t, packet))
		wire := packet
		wire.source, wire.destination = embedded, target
		if packet.isICMP {
			wire.icmpType = 128
		}
		receivePacket(ctx, t, device, packetFrame(t, wire), allowed, 61)
		return packet
	}
	reply := func(original packetDatagram, allowed bool) {
		t.Helper()
		packet := packetDatagram{source: target, destination: embedded, sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13", sourcePort: original.destinationPort, destinationPort: original.sourcePort, payload: fmt.Sprintf("joined-reply-%d", original.sourcePort)}
		if original.isTCP {
			packet.isTCP, packet.tcpFlags, packet.sequence, packet.acknowledgment, packet.payload = true, 18, 200, 101, ""
		}
		if original.isICMP {
			packet.isICMP, packet.icmpType, packet.icmpData = true, 129, original.icmpData
		}
		sendPacket(ctx, t, device, packetFrame(t, packet))
		packet.source, packet.destination = alias, client
		if packet.isICMP {
			packet.icmpType = 0
		}
		receivePacket(ctx, t, peer, packetFrame(t, packet), allowed, 61)
		if original.isTCP && allowed {
			original.tcpFlags, original.sequence, original.acknowledgment, original.payload = 16, 101, 201, "joined-established-tcp"
			sendPacket(ctx, t, peer, packetFrame(t, original))
			original.source, original.destination = embedded, target
			receivePacket(ctx, t, device, packetFrame(t, original), true, 61)
		}
	}
	if !configurationOnly {
		request(6053, false)
	}
	owner := request(6061, true)
	reply(owner, true)
	for _, mapping := range b.NAT46 {
		alias, target = mapping.Alias, mapping.Target
		for _, candidate := range []string{"tcp", "udp", "echo"} {
			protocol = candidate
			original := request(6061, true)
			reply(original, true)
		}
	}
	protocol = "udp"
	alias, target = b.NAT46[0].Alias, b.NAT46[0].Target
	if configurationOnly {
		for _, family := range []string{"inet", "netdev"} {
			packetNft(ctx, t, "add element "+family+" "+ownedTable+" "+classified4Set+" {10.250.0.20};add element "+family+" "+ownedTable+" "+classified6Set+" {fdca:1a2b:3::10}")
		}
		request(6061, false)
		reply(owner, false)
		return
	}
	if managedClient {
		spoofed := owner
		spoofed.sourcePort += 100
		spoofed.sourceMAC = "02:00:00:00:00:ee"
		spoofed.payload = "owner-cannot-borrow-another-nas-mac"
		sendPacket(ctx, t, peer, packetFrame(t, spoofed))
		rejectNATPayload(ctx, t, device, spoofed.payload)
	}
	request(6062, false) // an ordered owner deny precedes the broad permit
	request(6080, false) // the independent root floor is still mandatory
	reverse := request(6063, true)
	reply(reverse, false)
	late := request(6061, true)
	waitKernelFixture(ctx, t, 2200*time.Millisecond)
	reply(late, true) // return admission does not reuse an expired F tuple
	unsolicited := late
	unsolicited.sourcePort++
	reply(unsolicited, false)
	wrong := late
	wrong.source, wrong.sourcePort, wrong.payload = netip.MustParseAddr("10.240.3.10"), wrong.sourcePort+2, "wrong-original-attachment"
	sendPacket(ctx, t, peer, packetFrame(t, wrong))
	rejectNATPayload(ctx, t, device, wrong.payload)
	unknown := late
	unknown.destination, unknown.sourcePort, unknown.payload = netip.MustParseAddr("10.250.0.99"), unknown.sourcePort+3, "unmapped-alias"
	sendPacket(ctx, t, peer, packetFrame(t, unknown))
	rejectNATPayload(ctx, t, device, unknown.payload)
	logical := guardChanges{}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	for _, name := range []string{"lease_to4_tcp", "lease_to4_udp"} {
		values := []json.RawMessage{}
		for _, mapping := range b.NAT46 {
			value, err := json.Marshal(map[string]any{"elem": map[string]any{"timeout": 45, "val": map[string]any{"concat": []any{"lan13", "02:00:00:00:00:13", mapping.Alias.String(), client.String(), 6053}}}})
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
		}
		logical.Commands = append(logical.Commands, guardAdd("inet", name, values))
	}
	raw, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	utc, anchor := time.Now().UTC(), time.Now()
	mapped, err := prepareMappedGuards(ctx, &preparedBatch{data: raw, preparedAt: utc, startedAt: anchor, startBefore: utc.Add(preparationBudget)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := prepareNativeNAT46Guards(ctx, mapped, publication, layout.nat46Sources().model, utc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedGuardBatch(ctx, grants); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, grants.batch.data)
	for _, mapping := range b.NAT46 {
		alias, target = mapping.Alias, mapping.Target
		for _, candidate := range []string{"tcp", "udp"} {
			protocol = candidate
			original := request(6053, true)
			reply(original, true)
		}
	}
	protocol = "udp"
	alias, target = b.NAT46[0].Alias, b.NAT46[0].Target
	delegated := request(6053, true)
	reply(delegated, true)
	// Removing the wire target's individual mirror revokes both owner and
	// directory flows, including replies whose connection facts remain valid.
	packetNft(ctx, t, "flush set netdev "+ownedTable+" "+nativeSourceEpoch6)
	request(6061, false)
	request(6053, false)
	reply(owner, false)
	reply(delegated, false)
}

func traceNAT46JoinedPackets(ctx context.Context, t *testing.T) {
	t.Helper()
	traceRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := traceRoot.Close(); err != nil {
			t.Error(err)
		}
	})
	trace, err := traceRoot.Create("synthetic-nat46-trace.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := trace.Close(); err != nil {
			t.Error(err)
		}
	})
	monitor := exec.CommandContext(ctx, "/usr/bin/stdbuf", "-oL", "-eL", "/usr/sbin/nft", "monitor", "trace")
	monitor.Stdout, monitor.Stderr = trace, trace
	monitor.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := monitor.Wait(); err != nil && ctx.Err() == nil {
			t.Error(err)
		}
		if t.Failed() {
			data, err := traceRoot.ReadFile("synthetic-nat46-trace.log")
			if err == nil {
				if len(data) > 16000 {
					data = data[len(data)-16000:]
				}
				t.Logf("synthetic packet trace: %s", data)
			}
		}
	})
	packetNft(ctx, t, `table inet n46_join_trace {
 counter raw_start {}
 counter raw_forward {}
 counter raw_confirm {}
 counter wire_start {}
 counter wire_forward {}
 counter wire_confirm {}
 counter wire_reply_start {}
 counter wire_reply_forward {}
 counter wire_reply_confirm {}
 counter raw_reply_start {}
 counter raw_reply_forward {}
 counter raw_reply_confirm {}
 chain mandatory_floor {type filter hook forward priority 0;policy accept;
 udp dport 6080 drop
 tcp dport 6080 drop
 }
 chain trace_packet {type filter hook prerouting priority -301;policy accept;
 iifname "lan13" ip6 saddr fdca:1a2b:3::10 udp sport 6061 counter name wire_reply_start meta nftrace set 1
 iifname "nat46" ip saddr 10.250.0.20 udp sport 6061 counter name raw_reply_start meta nftrace set 1
 iifname "lan10" ip saddr 10.240.0.10 udp dport 6061 counter name raw_start meta nftrace set 1
 iifname "nat46" ip6 saddr fdca:1a2b:e046::af0:a udp dport 6061 counter name wire_start meta nftrace set 1
 }
 chain early {type filter hook forward priority -149;policy accept;
 iifname "lan13" udp sport 6061 counter name wire_reply_forward
 iifname "nat46" udp sport 6061 counter name raw_reply_forward
 iifname "lan10" udp dport 6061 counter name raw_forward
 iifname "nat46" udp dport 6061 counter name wire_forward
 }
 chain late {type filter hook forward priority 151;policy accept;
 iifname "lan13" udp sport 6061 counter name wire_reply_confirm
 iifname "nat46" udp sport 6061 counter name raw_reply_confirm
 iifname "lan10" udp dport 6061 counter name raw_confirm
 iifname "nat46" udp dport 6061 counter name wire_confirm
 }
}`)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		if t.Failed() {
			t.Logf("synthetic stage counters: %s", kernelFixtureCommand(cleanup, t, "list", "table", "inet", "n46_join_trace"))
		}
		packetNft(cleanup, t, "delete table inet n46_join_trace")
	})
}

func startNAT46JoinedTranslator(ctx context.Context, t *testing.T, b policy.Baseline) {
	t.Helper()
	configuration := filepath.Join(t.TempDir(), "nat46.conf")
	text := "tun-device nat46\nipv4-addr 10.250.0.1\nipv6-addr fdca:1a2b:ffff::1\nprefix fdca:1a2b:e046::/96\n"
	for _, mapping := range b.NAT46 {
		text += "map " + mapping.Alias.String() + " " + mapping.Target.String() + "\n"
	}
	if err := os.WriteFile(configuration, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- Fixed reviewed translator and synthetic temporary config.
	translator := exec.CommandContext(ctx, "/usr/local/sbin/tayga", "--nodetach", "--config", configuration)
	translator.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	if err := translator.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := translator.Wait(); err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	})
	ready, done := context.WithTimeout(ctx, 2*time.Second)
	defer done()
	for {
		if ready.Err() != nil {
			t.Fatal("joined translator did not become ready")
		}
		link, err := net.InterfaceByName("nat46")
		if err != nil {
			t.Fatal(err)
		}
		if link.Flags&net.FlagRunning != 0 {
			return
		}
		waitKernelFixture(ctx, t, 10*time.Millisecond)
	}
}
