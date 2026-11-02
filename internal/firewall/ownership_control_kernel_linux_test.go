//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// Do not preinstall the gateway neighbour: real ARP must continue while the
// managed MAC is sealed and has neither current ownership nor a directory grant.
func TestKernelNamedLocalNeighborControl(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "-6", "address", "add", "fe80::1/64", "dev", "lan13", "nodad")
	baseline := nativeAccessBaseline(t)
	layout, err := newNativeAccessLayout(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	packetIP(ctx, t, "link", "add", "wan", "type", "dummy")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "wan")
	})
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
	for _, family := range []string{"inet", "netdev"} {
		packetNft(ctx, t, "add element "+family+" "+ownedTable+" "+cohortSet+" { 02:00:00:00:00:13 }")
	}
	router, client := packetSocket(t, "lan13"), packetSocket(t, "device0")
	request := neighborARP(t, false)
	request[0], request[1], request[2], request[3], request[4], request[5] = 255, 255, 255, 255, 255, 255
	copy(request[6:12], client.mac)
	copy(request[22:28], client.mac)
	copy(request[28:32], []byte{10, 240, 3, 10})
	clear(request[32:38])
	copy(request[38:42], []byte{10, 240, 3, 1})
	sendPacket(ctx, t, client, request)
	reply := neighborARP(t, true)
	receiveNeighbor(ctx, t, client, reply, true)
	// Use a real kernel NA reply to a client's link-local NS source. The
	// destination is deliberately absent from application ownership evidence.
	target := netip.MustParseAddr("fdca:1a2b:3::1").As16()
	option := append([]byte{1, 1}, client.mac...)
	ns := packetFrame(t, packetDatagram{source: netip.MustParseAddr("fe80::13"), destination: netip.MustParseAddr("ff02::1:ff00:1"),
		sourceMAC: "02:00:00:00:00:13", destinationMAC: "33:33:ff:00:00:01", isICMP: true, icmpType: 135, payload: string(append(target[:], option...))})
	ns[21] = 255
	sendPacket(ctx, t, client, ns)
	receiveNeighborMatch(ctx, t, client, func(frame []byte) bool {
		return len(frame) >= 86 && bytes.Equal(frame[:6], client.mac) && bytes.Equal(frame[6:12], router.mac) &&
			binary.BigEndian.Uint16(frame[12:14]) == 0x86dd && frame[20] == 58 && frame[21] == 255 &&
			bytes.Equal(frame[22:38], target[:]) && bytes.Equal(frame[38:54], ns[22:38]) &&
			frame[54] == 136 && frame[55] == 0 && frame[58]&0x40 != 0 && bytes.Equal(frame[62:78], target[:])
	}, true)
	for _, tc := range []struct {
		name    string
		mutate  func([]byte)
		allowed bool
	}{
		{name: "local ARP reply", allowed: true},
		{name: "local unicast ARP request", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[20:22], 1); clear(p[32:38]) }, allowed: true},
		{name: "wrong hardware type", mutate: func(p []byte) { p[15] = 2 }},
		{name: "wrong protocol", mutate: func(p []byte) { p[16] = 0x86; p[17] = 0xdd }},
		{name: "wrong hardware length", mutate: func(p []byte) { p[18] = 5 }},
		{name: "wrong protocol length", mutate: func(p []byte) { p[19] = 16 }},
		{name: "unsupported ARP operation", mutate: func(p []byte) { p[21] = 3 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := neighborARP(t, true)
			if tc.mutate != nil {
				tc.mutate(frame)
			}
			sendNeighbor(ctx, t, router, frame, tc.allowed)
			receiveNeighbor(ctx, t, client, frame, tc.allowed)
		})
	}
	for _, tc := range []struct {
		name            string
		kind, code, hop byte
		allowed         bool
	}{
		{name: "router solicitation", kind: 133, hop: 255, allowed: true},
		{name: "router advertisement", kind: 134, hop: 255, allowed: true},
		{name: "neighbor solicitation", kind: 135, hop: 255, allowed: true},
		{name: "neighbor advertisement", kind: 136, hop: 255, allowed: true},
		{name: "invalid hop limit", kind: 136, hop: 254},
		{name: "invalid ICMP code", kind: 136, hop: 255, code: 1},
		{name: "redirect remains closed", kind: 137, hop: 255},
		{name: "echo remains closed", kind: 129, hop: 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := packetFrame(t, packetDatagram{source: netip.MustParseAddr("fe80::1"), destination: netip.MustParseAddr("fe80::13"), sourceMAC: "02:00:00:00:01:13", destinationMAC: "02:00:00:00:00:13", isICMP: true, icmpType: tc.kind, icmpCode: tc.code, payload: "local-control"})
			frame[21] = tc.hop
			sendNeighbor(ctx, t, router, frame, tc.allowed)
			receiveNeighbor(ctx, t, client, frame, tc.allowed)
		})
	}
	t.Run("ordinary local UDP remains closed", func(t *testing.T) {
		frame := packetFrame(t, packetDatagram{source: netip.MustParseAddr("10.240.3.1"), destination: netip.MustParseAddr("10.240.3.10"),
			sourceMAC: "02:00:00:00:01:13", destinationMAC: "02:00:00:00:00:13", sourcePort: 44000, destinationPort: 443, payload: "not-neighbor-control"})
		sendNeighbor(ctx, t, router, frame, false)
		receiveNeighbor(ctx, t, client, frame, false)
	})
	t.Run("forged local-origin token does not admit forwarding", func(t *testing.T) {
		packetNft(ctx, t, `table inet neighbor_spoof {
 chain inject { type filter hook prerouting priority -300; policy accept; iifname "lan10" udp dport 6053 meta mark set 0xbc000000; }
}`)
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetNft(cleanup, t, "delete table inet neighbor_spoof")
		})
		peer := packetSocket(t, "peer0")
		frame := packetFrame(t, packetDatagram{source: netip.MustParseAddr("10.240.0.10"), destination: netip.MustParseAddr("10.240.3.10"), sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: 44001, destinationPort: 6053, payload: "forged-origin-without-ownership"})
		sendPacket(ctx, t, peer, frame)
		receiveNeighbor(ctx, t, client, frame, false)
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
		t.Fatal("local control schema differs from installed kernel rules", err)
	}
}

// A local PF_PACKET sender sees ENOBUFS when the real netdev hook drops its
// frame. Still check the remote endpoint, so an errno alone cannot prove denial.
func sendNeighbor(ctx context.Context, t *testing.T, endpoint packetEndpoint, frame []byte, allowed bool) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	err := syscall.Sendto(endpoint.fd, frame, 0, nil)
	if err != nil && (allowed || !errors.Is(err, syscall.ENOBUFS)) {
		t.Fatal("local control packet send failed", err)
	}
}

func neighborARP(t *testing.T, reply bool) []byte {
	t.Helper()
	source, err := net.ParseMAC("02:00:00:00:01:13")
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.ParseMAC("02:00:00:00:00:13")
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 42)
	copy(frame[:6], target)
	copy(frame[6:12], source)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18], frame[19] = 6, 4
	binary.BigEndian.PutUint16(frame[20:22], 1)
	if reply {
		binary.BigEndian.PutUint16(frame[20:22], 2)
	}
	copy(frame[22:28], source)
	copy(frame[28:32], []byte{10, 240, 3, 1})
	copy(frame[32:38], target)
	copy(frame[38:42], []byte{10, 240, 3, 10})
	return frame
}

func receiveNeighbor(ctx context.Context, t *testing.T, endpoint packetEndpoint, frame []byte, expected bool) {
	t.Helper()
	receiveNeighborMatch(ctx, t, endpoint, func(received []byte) bool {
		return len(received) >= len(frame) && bytes.Equal(received[:len(frame)], frame)
	}, expected)
}

func receiveNeighborMatch(ctx context.Context, t *testing.T, endpoint packetEndpoint, matches func([]byte) bool, expected bool) {
	t.Helper()
	deadline := time.Now().Add(150 * time.Millisecond)
	if expected {
		deadline = time.Now().Add(time.Second)
	}
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
		if !ok || link.Pkttype == syscall.PACKET_OUTGOING || !matches(buffer[:n]) {
			continue
		}
		if !expected {
			t.Fatal("invalid or non-control local packet escaped ownership guard")
		}
		return
	}
	if expected {
		t.Fatal("local neighbor control did not reach the managed client")
	}
}
