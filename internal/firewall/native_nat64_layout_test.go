package firewall

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT64LayoutOwnsSelectedTransportWithoutActivatingDefaultProfile(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	layout, err := newNativeNAT64AccessLayout(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte("native_n64_0_aliases"), []byte("native_n64_zone"), []byte("hook prerouting priority -300"),
		[]byte("native_n64_export"), []byte("hook postrouting priority 201")} {
		if !bytes.Contains(program, expected) {
			t.Fatal("NAT64 layout omitted selected fixed transport state", string(expected))
		}
	}
	if layout.native.nat64Transport == nil || layout.native.nat64Transport.component != "nat64-internal" {
		t.Fatal("NAT64 layout detached from selected original transport")
	}
	if _, err := newNativeAccessLayout(t.Context(), b); err == nil {
		t.Fatal("ordinary native layout silently activated NAT64")
	}
}

func TestNAT64AggregateLayoutProgramIsDeterministic(t *testing.T) {
	t.Parallel()
	baseline := nat64TransportFixture(t)
	secondPool := netip.MustParsePrefix("10.252.0.0/24")
	baseline.NAT64 = append(baseline.NAT64, policy.NAT64{
		ID: "nat64-private", Prefix: netip.MustParsePrefix("fdca:1a2b:e065::/96"), Scope: "private", SourcePool: &secondPool,
	})
	var expected []byte
	for attempt := range 32 {
		layout, err := newNativeNAT64AggregateAccessLayout(t.Context(), baseline)
		if err != nil {
			t.Fatal(err)
		}
		program, err := layout.program(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if attempt != 0 && !bytes.Equal(expected, program) {
			t.Fatal("identical NAT64 aggregate input changed immutable guard order")
		}
		expected = program
	}
}

func TestNAT64ConfirmationRechecksWithoutReimportingFacts(t *testing.T) {
	t.Parallel()
	layout, err := newNativeNAT64AccessLayout(t.Context(), nat64TransportFixture(t), "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"native_n64_wire_original_confirm", "native_n64_wire_reply_confirm", "native_n64_translated_reply_confirm"} {
		text := strings.Join(nativeRulesText(layout.native.inet[name]), "\n")
		if text == "" || strings.Contains(text, "_import") || strings.Contains(text, "facts_capture") || strings.Contains(text, "facts_restore") {
			t.Fatalf("NAT64 confirmation mutates imported facts in %s: %s", name, text)
		}
		if !strings.Contains(text, "ct mark & 0xfffffc00 @current_configuration_epoch") || !strings.Contains(text, "@native_n64_0_") {
			t.Fatalf("NAT64 confirmation lost current epoch or allocation proof in %s: %s", name, text)
		}
	}
	for _, name := range []string{"native_n64_wire_original", "native_n64_wire_reply", "native_n64_translated_reply"} {
		text := strings.Join(nativeRulesText(layout.native.inet[name]), "\n")
		if !strings.Contains(text, "_import") && !strings.Contains(text, "facts_restore") {
			t.Fatalf("NAT64 early guard lost its one-time fact import in %s: %s", name, text)
		}
	}
}

func TestNAT64AllocationRequestsPreservePolicyAndGrantNoAccess(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	b.NetworkModel.ManagedNetworks = []policy.Role{b.Zones[0].Role}
	b.NetworkModel.Rules = []policy.NetworkRule{
		{Action: "deny", Authorization: "inherit", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan10"}},
			To:   []policy.NetworkSelector{{Interface: b.NetworkModel.UplinkInterface, Addresses: sourceClassPrefixes("10.240.3.11/32")}}},
		{Action: "allow", Authorization: "directory", Protocol: "udp", Ports: []uint16{6061},
			From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("fdca:1a2b::/64")}},
			To:   []policy.NetworkSelector{{Interface: "nat64-internal", Addresses: []netip.Prefix{b.NAT64[0].Prefix}}}},
	}
	layout, err := newNativeNAT64AccessLayout(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	request := strings.Join(nativeRulesText(layout.native.inet["native_n64_0_request"]), "\n")
	if !strings.Contains(request, "fdca:1a2b:e064::af0:30b return") ||
		!strings.Contains(request, "udp dport 6061 update @native_n64_0_pending { ip6 saddr } return") ||
		strings.Contains(request, "accept") {
		t.Fatal("NAT64 request channel broadened policy or acquired packet authority", request)
	}
	original := strings.Join(nativeRulesText(layout.native.inet["native_n64_wire_original"]), "\n")
	ordered := []string{"jump validate_source", "jump native_forward_floor", `iifname "lan10" jump native_source`,
		"jump native_n64_0_request"}
	position := -1
	for _, expected := range ordered {
		next := strings.Index(original[position+1:], expected)
		if next < 0 {
			t.Fatalf("NAT64 request path omitted %q: %s", expected, original)
		}
		position += next + 1
	}
	if !strings.HasSuffix(original, "drop") {
		t.Fatal("NAT64 request path no longer fails closed", original)
	}
}

func TestNAT64LayoutRejectsCombinedOrUnknownGeometry(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	if _, err := newNativeNAT64AccessLayout(t.Context(), b, "missing"); err == nil {
		t.Fatal("unknown NAT64 component selected")
	}
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	if _, err := newNativeNAT64AccessLayout(t.Context(), b, "nat64-internal"); err == nil {
		t.Fatal("unqualified combined translation layout selected")
	}
}
