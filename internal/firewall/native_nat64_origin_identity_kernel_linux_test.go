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

// A metadata-only caller tests every carried bit, without conferring packet
// authority on the origin helper. Full policy and conversion are exercised by
// the joined four-leg and actual-TAYGA fixtures separately.
func TestKernelNamedNAT64OriginIdentityCaptureAndBinding(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	transport, err := newNativeNAT64Transport(ctx, nat64TransportFixture(t), "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	words := make([]uint32, 0, 28)
	for bit := uint(0); bit < 24; bit++ {
		words = append(words, uint32(1)<<bit)
	}
	words = append(words, 0xffffff, 0, 0x800000, 0x800000)
	contextValue := func(word uint32) uint32 {
		kind := uint32(0xd1000000)
		if word&0x800000 != 0 {
			kind = 0xd3000000
		}
		return kind | word&0x3ff | (word>>20&7)<<13
	}
	contextRows, channelRows, expected := []string{}, []string{}, []string{}
	for index, word := range words {
		port := 6160 + index
		contextRows = append(contextRows, fmt.Sprintf("%d : %#x", port, contextValue(word)))
		channelRows = append(channelRows, fmt.Sprintf("%d : %s", port, epochClassID(0x1c00|word>>10&0x3ff)))
		expected = append(expected, fmt.Sprintf("%s . %d", epochClassID(word), port))
	}
	const table = "n64_origin_identity_fixture"
	lines := []string{"table inet " + table + " {",
		"map contexts { type inet_service : mark; elements = { " + strings.Join(contextRows, ", ") + " }; }",
		"map channels { type inet_service : classid; elements = { " + strings.Join(channelRows, ", ") + " }; }",
		"set expected { type classid . inet_service; elements = { " + strings.Join(expected, ", ") + " }; }",
	}
	lines = append(lines, ownerPriorityRules(false)...)
	chains := transport.originIdentityChains()
	facts, err := nativeTranslationFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := mergeNativeChains(chains, facts); err != nil {
		t.Fatal(err)
	}
	for _, name := range nativeChainNames(chains) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(chains[name])...)
		lines = append(lines, "}")
	}
	prefix := transport.name + "_origin_identity"
	lines = append(lines,
		"chain legacy_gate {}",
		"chain original {",
		"ct mark set 0x1c00",
		"meta mark set udp dport map @contexts",
		"meta priority set udp dport map @channels",
		"ct status & confirmed == 0 ct label set 100",
		"ct status & confirmed == 0 jump native_translation_facts_capture",
		"jump legacy_gate",
		"jump "+prefix+"_capture",
		"ct mark != 0x1c00 drop",
		"ct label & 100 != 100 drop",
		"meta priority set 0xffffffff",
		"jump "+prefix+"_restore",
		"meta priority . udp dport @expected goto connection",
		"drop", "}",
		"chain connection {",
		"jump "+prefix+"_connection",
		"ct mark 0x1c00 accept", "drop", "}",
		"chain forward { type filter hook forward priority 0; policy drop;",
		"ct direction original meta l4proto udp goto original", "}", "}")
	packetNft(ctx, t, strings.Join(lines, "\n"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet "+table)
	})
	client, target := packetSocket(t, "peer0"), packetSocket(t, "device0")
	probe := func(t *testing.T, index int, allowed bool) {
		t.Helper()
		packet := packetDatagram{source: netip.MustParseAddr("10.240.0.10"), destination: netip.MustParseAddr("10.240.3.10"),
			sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: uint16(63200 + index), destinationPort: uint16(6160 + index), payload: fmt.Sprintf("origin-identity-%d", index)} // #nosec G115 -- the fixture has exactly 28 tuples.
		sendPacket(ctx, t, client, packetFrame(t, packet))
		packet.sourceMAC, packet.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
		receivePacket(ctx, t, target, packetFrame(t, packet), allowed)
	}
	for index, word := range words[:26] {
		t.Run(fmt.Sprintf("retain-%06x", word), func(t *testing.T) { probe(t, index, true) })
	}
	for _, change := range []struct {
		name string
		word uint32
	}{
		{"changed-context", words[0] | 2},
		{"changed-source-uid", words[0] | 1<<22},
		{"changed-source-kind-same-epoch", words[0] | 1<<23},
	} {
		t.Run(change.name, func(t *testing.T) {
			packetNft(ctx, t, fmt.Sprintf("delete element inet %s contexts { 6160 }; add element inet %s contexts { 6160 : %#x }", table, table, contextValue(change.word)))
			probe(t, 0, false)
			packetNft(ctx, t, fmt.Sprintf("delete element inet %s contexts { 6160 }; add element inet %s contexts { 6160 : %#x }", table, table, contextValue(words[0])))
		})
	}
	t.Run("confirmed-without-identity-cannot-bind", func(t *testing.T) {
		packetNft(ctx, t, "add rule inet "+table+" legacy_gate udp dport 6186 accept")
		probe(t, 26, true)
		packetNft(ctx, t, "flush chain inet "+table+" legacy_gate")
		probe(t, 26, false)
	})
	t.Run("unconfirmed-foreign-identity-cannot-bind", func(t *testing.T) {
		packetNft(ctx, t, "add rule inet "+table+" legacy_gate udp dport 6187 ct label set 96")
		probe(t, 27, false)
	})
	t.Run("unchanged-identity-remains-admitted", func(t *testing.T) { probe(t, 0, true) })
}
