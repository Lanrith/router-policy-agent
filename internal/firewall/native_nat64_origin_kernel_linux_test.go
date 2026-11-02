//go:build integration && kernel && linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Exercise the origin word independently of the wire authorization marker.
// The surrounding table supplies synthetic authority; the shared origin
// chains must preserve it, retain unrelated labels and reject substitution.
func TestKernelNamedNAT64OriginCaptureAndConnectionBinding(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	transport, err := newNativeNAT64Transport(ctx, nat64TransportFixture(t), "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	markers := []uint32{0x1c02, 0x80002403, 0xfedcba98, 0xffffffff, 0x55aa1234, 0x10203040}
	origins, connections, expected := []string{}, []string{}, []string{}
	for index, marker := range markers {
		port := 6161 + index
		origins = append(origins, fmt.Sprintf("%d : %s", port, epochClassID(marker)))
		connections = append(connections, fmt.Sprintf("%d : %#x", port, marker))
		expected = append(expected, fmt.Sprintf("%s . %d", epochClassID(marker), port))
	}
	const table = "n64_origin_fixture"
	setupPacketEndpointSinks(ctx, t, table)
	lines := []string{"table inet " + table + " {",
		"map origin_by_port { type inet_service : classid; elements = { " + strings.Join(origins, ", ") + " }; }",
		"map connection_by_port { type inet_service : mark; elements = { " + strings.Join(connections, ", ") + " }; }",
		"set expected_origins { type classid . inet_service; elements = { " + strings.Join(expected, ", ") + " }; }",
	}
	chains := transport.originChains()
	for _, name := range nativeChainNames(chains) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(chains[name])...)
		lines = append(lines, "}")
	}
	prefix := transport.name + "_origin"
	lines = append(lines,
		"chain legacy_gate {}",
		"chain original {",
		"ct status & confirmed == 0 ct label set 100",
		"ct mark set 0x40000003",
		"jump legacy_gate",
		"meta priority set udp dport map @origin_by_port goto capture",
		"drop", "}",
		"chain capture {",
		"jump "+prefix+"_capture",
		"ct mark != 0x40000003 drop",
		"ct label & 100 != 100 drop",
		"meta priority set 0x12345678",
		"jump "+prefix+"_restore",
		"meta priority . udp dport @expected_origins goto connection",
		"drop", "}",
		"chain connection {",
		"ct mark set udp dport map @connection_by_port goto match",
		"drop", "}",
		"chain match {",
		"jump "+prefix+"_connection",
		"ct mark set 0x40000003 accept", "}",
		"chain forward { type filter hook forward priority 0; policy drop;",
		"ct direction original meta l4proto udp goto original", "}", "}")
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+table)
	})
	client, target := packetSocket(t, "peer0"), packetSocket(t, "device0")
	attempt := 0
	probe := func(t *testing.T, index int, allowed bool) {
		t.Helper()
		attempt++
		packet := packetDatagram{source: netip.MustParseAddr("10.240.0.10"), destination: netip.MustParseAddr("10.240.3.10"),
			sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: uint16(63000 + index), destinationPort: uint16(6161 + index), payload: fmt.Sprintf("origin-word-%d-%d", index, attempt)} // #nosec G115 -- indices are bounded to six fixture cases.
		sendPacket(ctx, t, client, packetFrame(t, packet))
		packet.sourceMAC, packet.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
		receivePacket(ctx, t, target, packetFrame(t, packet), allowed)
	}
	for index, marker := range markers[:4] {
		t.Run(fmt.Sprintf("retain-all-bits-%08x", marker), func(t *testing.T) { probe(t, index, true) })
	}
	t.Run("changed-original-marker", func(t *testing.T) {
		packetNft(ctx, t, "delete element inet "+table+" origin_by_port { 6161 }; add element inet "+table+" origin_by_port { 6161 : "+epochClassID(markers[1])+" }")
		probe(t, 0, false)
	})
	t.Run("different-original-connection", func(t *testing.T) {
		packetNft(ctx, t, fmt.Sprintf("delete element inet %s connection_by_port { 6162 }; add element inet %s connection_by_port { 6162 : %#x }", table, table, markers[0]))
		probe(t, 1, false)
	})
	t.Run("confirmed-connection-cannot-rebind", func(t *testing.T) {
		packetNft(ctx, t, "add rule inet "+table+" legacy_gate udp dport 6165 accept")
		probe(t, 4, true)
		packetNft(ctx, t, "flush chain inet "+table+" legacy_gate")
		probe(t, 4, false)
	})
	t.Run("unconfirmed-foreign-labels-cannot-bind", func(t *testing.T) {
		packetNft(ctx, t, "add rule inet "+table+" legacy_gate udp dport 6166 ct label set 0")
		probe(t, 5, false)
	})
	t.Run("unaffected-existing-connection", func(t *testing.T) { probe(t, 3, true) })
	if got := guardFamilyCounter(ctx, t, "netdev", table, "device_datagrams"); got != 6 {
		t.Fatal("raw endpoint did not observe exactly the admitted datagrams", got)
	}
}
