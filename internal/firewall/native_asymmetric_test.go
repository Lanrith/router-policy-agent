package firewall

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNativeAsymmetricRepliesUseDistinctConfirmedPhysicalTokens(t *testing.T) {
	t.Parallel()
	b := nativeAccessBaseline(t)
	b.NetworkModel.AsymmetricReplies = []policy.AsymmetricReply{
		{Mode: "tcp_dsr", SourceInterface: "lan13", SourceAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::/64")}, DestinationInterface: "lan13", DestinationAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::400/128")}},
		{Mode: "icmp_echo_reply", SourceInterface: "lan13", SourceAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::20/128")}, DestinationInterface: "lan13", DestinationAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::400/128")}},
	}
	layout, err := newNativeAccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range [][]byte{
		[]byte("tcp flags & (syn | ack | rst) == ack"), []byte("icmpv6 type echo-reply"),
		[]byte("0xb3000000"), []byte("meta priority 0xfffffb00"),
		[]byte("jump native_asymmetric_guard"), []byte("jump native_asymmetric_confirm"),
	} {
		if !bytes.Contains(program, fragment) {
			t.Fatalf("missing asymmetric return fragment %q", fragment)
		}
	}
	if !bytes.Contains(program, []byte("meta mark & 0xff000000 == 0xb3000000 drop")) {
		t.Fatal("stale asymmetric token is not denied")
	}
	for _, invalid := range [][]byte{
		[]byte("jump native_raw_floor jump native_forward_floor"),
		[]byte("jump save_owner_priority meta priority"),
		[]byte("0x30783030666630303030"),
	} {
		if bytes.Contains(program, invalid) {
			t.Fatalf("asymmetric graph contains an invalid nftables statement %q", invalid)
		}
	}
}
