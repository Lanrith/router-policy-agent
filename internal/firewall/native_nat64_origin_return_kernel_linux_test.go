//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// A veth makes the converter boundary observable. All four packet legs use
// the actual allocation, policy, tuple, epoch and physical guards. Origin and
// authorization are independently necessary for returning to the IPv6 client.
func TestKernelNamedNAT64OriginReturnRequiresBothProofs(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupNAT64PendingLinks(ctx, t)
	packetIP(ctx, t, "route", "add", "10.251.0.0/24", "dev", "nat64-internal")
	packetIP(ctx, t, "neighbor", "add", "10.251.0.10", "lladdr", "02:00:00:00:00:64", "dev", "nat64-internal", "nud", "permanent")
	b := nat64TransportFixture(t)
	b.NetworkModel.ManagedNetworks = []policy.Role{}
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{{
		Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10"), Ready: true}}
	b.NetworkModel.Rules = nil
	for _, port := range []uint16{6061, 6062} {
		b.NetworkModel.Rules = append(b.NetworkModel.Rules, policy.NetworkRule{
			Action: "allow", Authorization: "owner", Protocol: "udp", Ports: []uint16{port},
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
			To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}},
		})
	}
	layout, err := newNativeNAT64AccessLayout(ctx, b, "nat64-internal")
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
	transport := layout.native.nat64Transport
	ledger, err := transport.geometry.Capture(ctx, transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	allocations, err := prepareNativeNAT64Allocations(ctx, transport, ledger,
		&testNAT64Readiness{transport: transport, entries: entries, ready: true})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(ctx, 23)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareConfiguration(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, prepared.batch.data)
	tokens, err := deriveNativeNAT64Tokens(ctx, transport, layout.native, ledger, configuration, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := publisher.close(); err != nil {
			t.Error(err)
		}
	})
	state, err := prepareNativeNAT64State(ctx, []*preparedNAT64Allocations{allocations}, []*nativeNAT64Tokens{tokens})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.run(ctx, commandInput{op: applyNAT64State, nat64State: state}); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.inspectGuards(ctx, layout); err != nil {
		t.Fatal("origin return fixture differs from its immutable schema", err)
	}
	// Observe the exact export boundary, including the point where older
	// code temporarily replaced the connection mark with a registry token.
	// These counters require the admitted mark throughout export, and the
	// complete packet mark/priority restored before physical enforcement.
	for _, leg := range transport.legs {
		if leg.protocol != "udp" {
			continue
		}
		name := leg.name
		packetNft(ctx, t, fmt.Sprintf(`
add counter inet %s %s_connection {}
add counter inet %s %s_metadata {}
insert rule inet %s %s_export_checked_record ct mark %#x counter name %s_connection
insert rule inet %s %s_export meta mark set (meta mark & 0xff00e3ff) | 0x00551c00
add chain inet %s %s_observe { type filter hook postrouting priority 202; policy accept; }
add rule inet %s %s_observe oifname %q %s meta mark & 0x00ff1c00 == 0x00551c00 meta priority %s counter name %s_metadata`,
			ownedTable, name, ownedTable, name, ownedTable, name, 23<<policy.OwnershipRuleBits, name,
			ownedTable, name, ownedTable, name, ownedTable, name, transport.component,
			leg.geometry(false).text, epochClassID(23<<policy.OwnershipRuleBits), name))
	}
	client, translated, target := packetSocket(t, "peer0"), packetSocket(t, "n64peer"), packetSocket(t, "device0")
	serial := uint16(60020)
	for _, mode := range []string{"joined", "missing-origin", "wrong-origin", "missing-identity", "wrong-context", "wrong-source-identity", "wrong-source-kind", "missing-authorization", "joined-again"} {
		t.Run(mode, func(t *testing.T) {
			serial++
			original := packetDatagram{source: entries[0].Source, destination: netip.MustParseAddr("fdca:1a2b:e064::af0:30a"),
				sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: serial, destinationPort: 6061,
				payload: "joined-origin-" + mode}
			sendPacket(ctx, t, client, packetFrame(t, original))
			rawWire := original
			rawWire.sourceMAC, rawWire.destinationMAC = "02:00:00:00:01:64", "02:00:00:00:00:64"
			receivePacket(ctx, t, translated, packetFrame(t, rawWire), true)
			wire := original
			wire.source, wire.destination = entries[0].Alias, netip.MustParseAddr("10.240.3.10")
			wire.sourceMAC, wire.destinationMAC = "02:00:00:00:00:64", "02:00:00:00:01:64"
			sendPacket(ctx, t, translated, packetFrame(t, wire))
			wire.sourceMAC, wire.destinationMAC = "02:00:00:00:01:13", "02:00:00:00:00:13"
			receivePacket(ctx, t, target, packetFrame(t, wire), true)
			reply := wire
			reply.source, reply.destination = wire.destination, wire.source
			reply.sourcePort, reply.destinationPort = wire.destinationPort, wire.sourcePort
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
			packetNft(ctx, t, "flush map inet "+ownedTable+" "+transport.name+"_udp_reply_origin_proof; flush map inet "+ownedTable+" "+transport.name+"_udp_reply_identity_proof")
			exportedAt := time.Now()
			sendPacket(ctx, t, target, packetFrame(t, reply))
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:01:64", "02:00:00:00:00:64"
			receivePacket(ctx, t, translated, packetFrame(t, reply), true)
			switch mode {
			case "missing-origin":
				packetNft(ctx, t, "flush map inet "+ownedTable+" "+transport.name+"_udp_reply_origin_proof")
			case "wrong-origin":
				// Both rule markers belong to this current configuration. A
				// reply must still name the exact original connection marker.
				replaceNAT64FixtureProof(ctx, t, transport.name+"_udp_reply_origin_proof", epochClassID(23<<policy.OwnershipRuleBits), epochClassID(23<<policy.OwnershipRuleBits|1))
			case "missing-identity":
				packetNft(ctx, t, "flush map inet "+ownedTable+" "+transport.name+"_udp_reply_identity_proof")
			case "wrong-context", "wrong-source-identity", "wrong-source-kind":
				identity := uint32(1 << 23) // Configuration provenance, context/UID zero.
				replacement := identity | 1
				if mode == "wrong-source-identity" {
					replacement = identity | 1<<10
				}
				if mode == "wrong-source-kind" {
					replacement = 0
				}
				replaceNAT64FixtureProof(ctx, t, transport.name+"_udp_reply_identity_proof", epochClassID(identity), epochClassID(replacement))
			case "missing-authorization":
				packetNft(ctx, t, "flush map inet "+ownedTable+" "+transport.name+"_udp_reply_proof")
			}
			reply.source, reply.destination = original.destination, original.source
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:00:64", "02:00:00:00:01:64"
			sendPacket(ctx, t, translated, packetFrame(t, reply))
			reply.sourceMAC, reply.destinationMAC = "02:00:00:00:01:10", "02:00:00:00:00:10"
			receivePacket(ctx, t, client, packetFrame(t, reply), mode == "joined" || mode == "joined-again")
			if elapsed := time.Since(exportedAt); elapsed >= 1500*time.Millisecond {
				t.Fatalf("return probe exceeded its live proof window: %s", elapsed)
			}
		})
	}
	for _, leg := range transport.legs {
		if leg.protocol != "udp" {
			continue
		}
		for _, suffix := range []string{"_connection", "_metadata"} {
			if count := guardFixtureCounter(ctx, t, ownedTable, leg.name+suffix); count != 9 {
				t.Fatalf("NAT64 export changed connection or packet metadata: %s=%d", leg.name+suffix, count)
			}
		}
	}
}

func replaceNAT64FixtureProof(ctx context.Context, t *testing.T, name, expected, replacement string) {
	t.Helper()
	var listing struct {
		Objects []struct {
			Map *struct {
				Elements []json.RawMessage `json:"elem"`
			} `json:"map"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "map", "inet", ownedTable, name), &listing); err != nil || len(listing.Objects) != 2 || listing.Objects[1].Map == nil || len(listing.Objects[1].Map.Elements) != 1 {
		t.Fatal("return proof fixture lost its single original tuple", err)
	}
	var pair []json.RawMessage
	if err := json.Unmarshal(listing.Objects[1].Map.Elements[0], &pair); err != nil || len(pair) != 2 {
		t.Fatal("return proof fixture lost its original key/value pair", err)
	}
	var originalMarker string
	if json.Unmarshal(pair[1], &originalMarker) != nil || originalMarker != expected {
		t.Fatal("return proof did not retain the original rule marker", originalMarker)
	}
	var timed struct {
		Element struct {
			Value json.RawMessage `json:"val"`
		} `json:"elem"`
	}
	key := pair[0]
	if json.Unmarshal(key, &timed) == nil && len(timed.Element.Value) != 0 {
		key = timed.Element.Value
	}
	data, err := json.Marshal(map[string]any{"nftables": []any{
		map[string]any{"flush": map[string]any{"map": ownedRef(name)}},
		map[string]any{"add": map[string]any{"element": map[string]any{
			"family": "inet", "table": ownedTable, "name": name,
			"elem": []any{[]any{key, replacement}},
		}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, data)
}
