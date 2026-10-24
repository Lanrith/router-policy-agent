//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// kernelNAT64Readiness is test-only supervision evidence. The live supervisor
// mints it after TAYGA and its attachment are running; it cannot be decoded
// from configuration, a process listing, or an nftables observation.
type kernelNAT64Readiness struct {
	process   *os.Process
	transport *nativeNAT64Transport
	component string
	entries   []policy.NAT64Allocation
}

func (proof *kernelNAT64Readiness) verifyNAT64Readiness(ctx context.Context, transport *nativeNAT64Transport, entries []policy.NAT64Allocation) error {
	if ctx == nil || proof == nil || proof.process == nil || proof.transport != transport || proof.component != transport.component || !reflect.DeepEqual(proof.entries, entries) {
		return errors.New("test: missing original live NAT64 readiness")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := proof.process.Signal(syscall.Signal(0)); err != nil {
		return errors.New("test: supervised NAT64 translator stopped")
	}
	link, err := net.InterfaceByName(proof.component)
	if err != nil || link.Flags&net.FlagRunning == 0 {
		return errors.New("test: supervised NAT64 attachment stopped")
	}
	return nil
}

// This isolates allocation identity and tuple correlation using a real TAYGA.
// Its caller supplies synthetic admission metadata. It does not qualify source
// ownership, delegated permission, a shared router profile or a private image.
func TestKernelNamedNAT64AllocationIdentity(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	packetIP(ctx, t, "tuntap", "add", "dev", "nat64-internal", "mode", "tun")
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetIP(cleanup, t, "link", "delete", "nat64-internal")
	})
	packetIP(ctx, t, "link", "set", "nat64-internal", "up")
	packetIP(ctx, t, "address", "add", "10.251.0.1/32", "dev", "nat64-internal")
	packetIP(ctx, t, "-6", "address", "add", "fdca:1a2b:ffff::64/128", "dev", "nat64-internal", "nodad")
	packetIP(ctx, t, "route", "add", "10.251.0.0/24", "dev", "nat64-internal")
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:e064::/96", "dev", "nat64-internal")
	packetIP(ctx, t, "neighbor", "add", "fdca:1a2b::11", "lladdr", "02:00:00:00:00:10", "dev", "lan10", "nud", "permanent")
	b := nativeAccessBaseline(t)
	pool := netip.MustParsePrefix("10.251.0.0/24")
	b.NAT64 = []policy.NAT64{{ID: "nat64-internal", Prefix: netip.MustParsePrefix("fdca:1a2b:e064::/96"), Scope: "private", SourcePool: &pool}}
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "owner", Protocol: "any",
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b::/64")}}},
		To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}}}
	for index := range 2 {
		b.NAT64[0].SourceMappings = append(b.NAT64[0].SourceMappings, policy.NAT64SourceMapping{
			Source: netip.MustParseAddr(fmt.Sprintf("fdca:1a2b::%x", 16+index)), Alias: netip.MustParseAddr(fmt.Sprintf("10.251.0.%d", 10+index)), Ready: true,
		})
	}
	transport, err := newNativeNAT64Transport(ctx, b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := transport.geometry.Capture(ctx, transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	allocations, err := ledger.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{"table inet " + ownedTable + " {"}
	lines = append(lines, transport.definitions()...)
	lines = append(lines, ownerPriorityRules(false)...)
	rules, err := newNativeRuleSet(b)
	if err != nil {
		t.Fatal(err)
	}
	accessLayout, err := newNativeAccessGeometry(ctx, b, rules, []string{transport.component})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := deriveNativeNAT64Tokens(ctx, transport, accessLayout.native, ledger, configuration, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	chains := transport.chains()
	for _, name := range nativeChainNames(chains) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(chains[name])...)
		lines = append(lines, "}")
	}
	lines = append(lines, "chain allocation_zone {type filter hook prerouting priority -300;policy accept;")
	lines = append(lines, nativeRulesText(transport.zoneRules())...)
	lines = append(lines, "}",
		"chain stamp_original {",
		fmt.Sprintf("ct zone %d ip6 saddr fdca:1a2b::10 ct mark set 0x1c00 meta mark set 0xd3000000 meta priority set 0x1c00 return", nativeNAT64ZoneIdentity(10)),
		fmt.Sprintf("ct zone %d ip6 saddr fdca:1a2b::11 ct mark set 0x1c00 meta mark set 0xd3000000 meta priority set 0x1c00 return", nativeNAT64ZoneIdentity(11)), "drop", "}",
		"chain stamp_reply {",
		"ct zone 0 ct mark 0x1c00 meta mark set 0xd4000000 meta priority set 0x1c00 return", "drop", "}",
		"chain check_import {",
		"ct mark 0x1c00 meta mark & 0xff00e3ff {0xd3000000,0xd4000000} meta priority 0x1c00 return", "drop", "}",
		"chain independent_floor {type filter hook forward priority 0;policy accept; udp dport 6080 drop;}",
		"chain source_nat {type nat hook postrouting priority 100;policy accept;}")
	forward := []string{"chain forward {type filter hook forward priority 151;policy drop;"}
	for _, leg := range transport.legs {
		for _, imported := range []bool{false, true} {
			operation := "export"
			if imported {
				operation = "import"
			}
			caller := leg.name + "_" + operation + "_caller"
			forward = append(forward, leg.geometry(imported).text+" goto "+caller)
			lines = append(lines, "counter "+caller+"_begin {}", "counter "+caller+"_end {}", "chain "+caller+" {", "counter name "+caller+"_begin")
			allocationCheck := caller + "_allocation"
			lines = append(lines, "jump "+allocationCheck)
			if !imported {
				if leg.reply {
					lines = append(lines, "jump stamp_reply")
				} else {
					lines = append(lines, "jump stamp_original")
				}
			}
			lines = append(lines, "jump "+leg.name+"_"+operation)
			if imported {
				lines = append(lines, "jump check_import")
				if !leg.reply {
					lines = append(lines, "ct zone != 0 drop")
				}
			}
			lines = append(lines, "counter name "+caller+"_end", "accept", "}")
			lines = append(lines, "chain "+allocationCheck+" {", leg.allocation(transport, imported).text+" return", "drop", "}")
		}
	}
	lines = append(lines, forward...)
	lines = append(lines, "}", "}")
	lines = append(lines, `table netdev n64_identity_endpoints {
 chain peer_endpoint {type filter hook ingress device "peer0" priority 0;policy drop;}
 chain device_endpoint {type filter hook ingress device "device0" priority 0;policy drop;}
}`)
	packetNft(ctx, t, strings.Join(lines, "\n"))
	publisher, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if publisher.executable != nil {
			if err := publisher.close(); err != nil {
				t.Error(err)
			}
		}
	})
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens})
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		if t.Failed() {
			logNAT64IdentityFixture(cleanup, t)
		}
		packetNft(cleanup, t, "delete table inet "+ownedTable+";delete table netdev n64_identity_endpoints")
	})
	readiness := startNAT64IdentityTranslator(ctx, t, b.NAT64[0], transport, allocations)
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	target, encoded := netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("fdca:1a2b:e064::af0:30a")
	// A running translator, routes, token registry and synthetic admission are
	// insufficient until the original live supervisor publishes allocations.
	unpublished := packetDatagram{source: allocations[0].Source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
		sourcePort: 60999, destinationPort: 6061, payload: "allocation-not-published"}
	sendPacket(ctx, t, peer, packetFrame(t, unpublished))
	rejectNATPayload(ctx, t, device, unpublished.payload)
	preparedAllocations, err := prepareNativeNAT64Allocations(ctx, transport, ledger, readiness)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT64AllocationPreparation(ctx, preparedAllocations); err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Allocations, nat64Allocation: preparedAllocations})
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens})
	serial := uint16(61000)
	for _, allocation := range allocations {
		for _, protocol := range []string{"udp", "tcp", "echo"} {
			serial++
			request := packetDatagram{source: allocation.Source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				sourcePort: serial, destinationPort: 6061, payload: fmt.Sprintf("allocation-%s-%s", allocation.Source, protocol)}
			if protocol == "tcp" {
				request.isTCP, request.tcpFlags, request.sequence, request.payload = true, 2, 100, ""
			}
			if protocol == "echo" {
				request.isICMP, request.icmpType, request.icmpData = true, 128, uint32(serial)<<16|1
			}
			sendPacket(ctx, t, peer, packetFrame(t, request))
			wire := request
			wire.source, wire.destination = allocation.Alias, target
			if request.isICMP {
				wire.icmpType = 8
			}
			receivePacket(ctx, t, device, packetFrame(t, wire), true, 61)
			reply := packetDatagram{source: target, destination: allocation.Alias, sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
				sourcePort: 6061, destinationPort: serial, payload: "allocation-return-" + protocol}
			if request.isTCP {
				reply.isTCP, reply.tcpFlags, reply.sequence, reply.acknowledgment, reply.payload = true, 18, 200, 101, ""
			}
			if request.isICMP {
				reply.isICMP, reply.icmpType, reply.icmpData = true, 0, request.icmpData
			}
			sendPacket(ctx, t, device, packetFrame(t, reply))
			reply.source, reply.destination = encoded, allocation.Source
			if reply.isICMP {
				reply.icmpType = 129
			}
			receivePacket(ctx, t, peer, packetFrame(t, reply), true, 61)
			if request.isTCP {
				request.tcpFlags, request.sequence, request.acknowledgment, request.payload = 16, 101, 201, "allocation-established"
				sendPacket(ctx, t, peer, packetFrame(t, request))
				request.source, request.destination = allocation.Alias, target
				receivePacket(ctx, t, device, packetFrame(t, request), true, 61)
			}
		}
	}
	// Two source identities deliberately use the same transport tuple. The
	// IPv4 connections share zone zero and must acquire different SNAT ports.
	packetNft(ctx, t, "add rule inet "+ownedTable+" source_nat oifname \"lan13\" ip saddr 10.251.0.0/24 meta l4proto udp snat ip to 10.240.3.1:62000-62001")
	ports := []uint16{}
	for _, allocation := range allocations {
		request := packetDatagram{source: allocation.Source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: 62000, destinationPort: 6061, payload: "shared-source-nat-" + allocation.Source.String()}
		sendPacket(ctx, t, peer, packetFrame(t, request))
		ports = append(ports, receiveNAT64SourceNATPort(ctx, t, device, request.payload))
	}
	if ports[0] == ports[1] {
		t.Fatal("source NAT allocated an ambiguous return tuple across identities")
	}
	tokenRows, err := tokens.elements(ctx)
	if err != nil {
		t.Fatal(err)
	}
	allocationRows, err := preparedAllocations.elements(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inspect := []struct{ kind, name string }{{"map", transport.name + "_zones"}, {"map", transport.name + "_aliases"},
		{"set", transport.name + "_active_aliases"}, {"set", transport.name + "_sources"},
		{"map", transport.name + "_tokens"}, {"map", transport.name + "_token_epoch"}, {"map", transport.name + "_token_context"}, {"map", transport.name + "_token_channel"},
		{"set", transport.name + "_token_epoch_pairs"}}
	for _, leg := range transport.legs {
		inspect = append(inspect, struct{ kind, name string }{"map", leg.name + "_proof"})
	}
	for _, object := range inspect {
		// #nosec G204 -- Names originate in the reviewed synthetic fixture.
		command := exec.CommandContext(ctx, "/usr/sbin/nft", "--json", "list", object.kind, "inet", ownedTable, object.name)
		command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("live %s %s inspection failed: %v, %s", object.kind, object.name, err, output)
		}
		var listed struct {
			Objects []json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(output, &listed); err != nil || len(listed.Objects) != 2 {
			t.Fatal("live NAT64 object listing changed shape", object.name, err)
		}
		var observed struct {
			Map *listedSet `json:"map"`
			Set *listedSet `json:"set"`
		}
		if err := json.Unmarshal(listed.Objects[1], &observed); err != nil {
			t.Fatal("live NAT64 elements changed shape", object.name, err)
		}
		actualElements := observed.Map
		if object.kind == "set" {
			actualElements = observed.Set
		}
		if expectedElements, static := tokenRows[object.name]; static {
			if actualElements == nil {
				t.Fatal("live NAT64 token registry is absent", object.name)
			}
			if err := sameGuardElements(ctx, actualElements.Elements, expectedElements); err != nil {
				t.Fatal("live NAT64 token registry differs from original publication", object.name, err)
			}
		}
		if expectedElements, published := allocationRows[object.name]; published {
			if actualElements == nil {
				t.Fatal("live NAT64 allocation publication is absent", object.name)
			}
			normalized, err := normalizeNAT64TimedElements(ctx, actualElements.Elements, object.kind == "map")
			if err == nil {
				err = sameGuardElements(ctx, normalized, expectedElements)
			}
			if err != nil {
				t.Fatal("live NAT64 allocation publication differs from original readiness", object.name, err)
			}
		}
		kind, fields, err := guardObject(listed.Objects[1])
		if err != nil || kind != object.kind {
			t.Fatal("live NAT64 object kind changed", object.name, err)
		}
		schema := transport.schema()
		expected := schema.maps[object.name]
		if object.kind == "set" {
			expected = schema.sets[object.name]
		}
		if _, err := checkGuardObject(fields, expected, true); err != nil {
			t.Fatal("live NAT64 object differs from fixed schema", object.name, err)
		}
	}
	// Inspection must remain available while multiple live proof rows exist.
	// nft's raw-tuple set representation aborts its listing process here.
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", "inet", ownedTable), &listing); err != nil || len(listing.Objects) == 0 {
		t.Fatal("live tuple-map inspection failed", err)
	}
	for index, allocation := range allocations {
		reply := packetDatagram{source: target, destination: netip.MustParseAddr("10.240.3.1"), sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
			sourcePort: 6061, destinationPort: ports[index], payload: fmt.Sprintf("shared-source-nat-reply-%d", index)}
		sendPacket(ctx, t, device, packetFrame(t, reply))
		reply.source, reply.destination, reply.destinationPort = encoded, allocation.Source, 62000
		receivePacket(ctx, t, peer, packetFrame(t, reply), true, 61)
	}
	clearTokens, err := prepareNativeNAT64TokenClear(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: clearTokens})
	withoutToken := packetDatagram{source: allocations[0].Source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
		sourcePort: 62999, destinationPort: 6061, payload: "token-withdrawn"}
	sendPacket(ctx, t, peer, packetFrame(t, withoutToken))
	rejectNATPayload(ctx, t, device, withoutToken.payload)
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Tokens, nat64Tokens: tokens})
	clearAllocations, err := prepareNativeNAT64AllocationClear(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Allocations, nat64Allocation: clearAllocations})
	withoutAllocation := packetDatagram{source: allocations[0].Source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
		sourcePort: 62998, destinationPort: 6061, payload: "allocation-publication-withdrawn"}
	sendPacket(ctx, t, peer, packetFrame(t, withoutAllocation))
	rejectNATPayload(ctx, t, device, withoutAllocation.payload)
	preparedAllocations, err = prepareNativeNAT64Allocations(ctx, transport, ledger, readiness)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT64AllocationPreparation(ctx, preparedAllocations); err != nil {
		t.Fatal(err)
	}
	applyNAT64Publication(ctx, t, publisher, commandInput{op: applyNAT64Allocations, nat64Allocation: preparedAllocations})
	packetNft(ctx, t, "flush set inet "+ownedTable+" "+transport.name+"_sources")
	denied := packetDatagram{source: allocations[0].Source, destination: encoded, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
		sourcePort: 63000, destinationPort: 6061, payload: "allocation-withdrawn"}
	sendPacket(ctx, t, peer, packetFrame(t, denied))
	rejectNATPayload(ctx, t, device, denied.payload)
}

func normalizeNAT64TimedElements(ctx context.Context, values []json.RawMessage, mapped bool) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, 0, len(values))
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := json.RawMessage(nil)
		timed := value
		if mapped {
			var pair []json.RawMessage
			if err := strictjson.Decode(value, &pair, maximumOutput); err != nil || len(pair) != 2 {
				return nil, errors.New("test: invalid timed NAT64 map row")
			}
			timed, data = pair[0], slices.Clone(pair[1])
		}
		var element struct {
			Value   json.RawMessage `json:"val"`
			Timeout int             `json:"timeout"`
			Expires uint64          `json:"expires"`
		}
		if err := decodeNested(timed, "elem", &element, []string{"val", "timeout", "expires"}); err != nil ||
			element.Timeout < 1 || element.Timeout > maximumElementLifetime || element.Expires < 1 || element.Expires > uint64(element.Timeout) {
			return nil, errors.New("test: invalid live NAT64 allocation deadline")
		}
		withoutExpiry, err := json.Marshal(map[string]any{"elem": map[string]any{"val": element.Value, "timeout": element.Timeout}})
		if err != nil {
			return nil, err
		}
		if mapped {
			withoutExpiry, err = json.Marshal([]any{json.RawMessage(withoutExpiry), data})
			if err != nil {
				return nil, err
			}
		}
		result = append(result, withoutExpiry)
	}
	return result, ctx.Err()
}

func applyNAT64Publication(ctx context.Context, t *testing.T, publisher *process, input commandInput) {
	t.Helper()
	if err := publisher.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	defer publisher.release()
	if _, err := publisher.run(ctx, input); err != nil {
		t.Fatal("isolated NAT64 publication failed", err)
	}
}

func logNAT64IdentityFixture(ctx context.Context, t *testing.T) {
	t.Helper()
	var listing struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", "inet", ownedTable), &listing); err != nil {
		t.Log("cannot decode synthetic identity observations", err)
		return
	}
	for _, object := range listing.Objects {
		for kind, raw := range object {
			if kind == "counter" {
				t.Logf("synthetic counter: %s", raw)
			}
			if kind == "map" || kind == "set" {
				var value struct {
					Elements []json.RawMessage `json:"elem"`
				}
				if err := json.Unmarshal(raw, &value); err == nil && len(value.Elements) > 0 {
					t.Logf("synthetic %s: %s", kind, raw)
				}
			}
		}
	}
}

func startNAT64IdentityTranslator(ctx context.Context, t *testing.T, component policy.NAT64, transport *nativeNAT64Transport, entries []policy.NAT64Allocation) *kernelNAT64Readiness {
	t.Helper()
	configuration := filepath.Join(t.TempDir(), "nat64.conf")
	text := "tun-device " + component.ID + "\nipv4-addr 10.251.0.1\nipv6-addr fdca:1a2b:ffff::64\nprefix " + component.Prefix.String() + "\n"
	for _, mapping := range component.SourceMappings {
		text += "map " + mapping.Alias.String() + " " + mapping.Source.String() + "\n"
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
			t.Fatal("identity translator did not become ready")
		}
		link, err := net.InterfaceByName(component.ID)
		if err != nil {
			t.Fatal(err)
		}
		if link.Flags&net.FlagRunning != 0 {
			return &kernelNAT64Readiness{process: translator.Process, transport: transport, component: component.ID, entries: slices.Clone(entries)}
		}
		waitKernelFixture(ctx, t, 10*time.Millisecond)
	}
}

func receiveNAT64SourceNATPort(ctx context.Context, t *testing.T, endpoint packetEndpoint, payload string) uint16 {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		length, address, err := syscall.Recvfrom(endpoint.fd, buffer, 0)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		link, ok := address.(*syscall.SockaddrLinklayer)
		if !ok || link.Pkttype == syscall.PACKET_OUTGOING || length < 42 || !bytes.Equal(buffer[42:length], []byte(payload)) {
			continue
		}
		if binary.BigEndian.Uint16(buffer[12:14]) != 0x0800 || buffer[14] != 0x45 || buffer[23] != 17 || buffer[22] != 61 ||
			!bytes.Equal(buffer[26:30], []byte{10, 240, 3, 1}) || !bytes.Equal(buffer[30:34], []byte{10, 240, 3, 10}) {
			t.Fatal("source-NAT packet lost its expected tuple or hop limit")
		}
		port := binary.BigEndian.Uint16(buffer[34:36])
		if port < 62000 || port > 62001 {
			t.Fatal("source NAT port escaped the synthetic bounded range")
		}
		return port
	}
	t.Fatal("source-NAT translated packet was not delivered")
	return 0
}
