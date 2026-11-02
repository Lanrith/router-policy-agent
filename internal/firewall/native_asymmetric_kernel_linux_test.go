//go:build integration && kernel && linux

package firewall

import (
	"context"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestKernelNamedAsymmetricRulesMatchNativeListing(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	baseline := nativeAccessBaseline(t)
	baseline.NetworkModel.AsymmetricReplies = []policy.AsymmetricReply{
		{Mode: "tcp_dsr", SourceInterface: "lan13", SourceAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::/64")},
			DestinationInterface: "lan13", DestinationAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::400/128")}},
		{Mode: "icmp_echo_reply", SourceInterface: "lan13", SourceAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::20/128")},
			DestinationInterface: "lan13", DestinationAddresses: []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::400/128")}},
	}
	layout, err := newNativeAccessLayout(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.freezeInspectionSchemas(ctx); err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created := map[string]bool{}
	for _, match := range regexp.MustCompile(`device "([a-zA-Z0-9_.-]+)"`).FindAllSubmatch(program, -1) {
		name := string(match[1])
		if created[name] {
			continue
		}
		created[name] = true
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", name)
		})
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
		t.Fatal("actual TCP flag and ICMPv6 listing differs from independently compiled expectations", err)
	}
	for _, change := range []struct{ before, after string }{
		{"tcp flags & (syn | ack | rst) == ack", "tcp flags & ack == ack"},
		{"icmpv6 type echo-reply", "icmpv6 type echo-request"},
	} {
		changed := strings.Replace(string(program), change.before, change.after, 1)
		if changed == string(program) {
			t.Fatal("asymmetric mutation missed its target")
		}
		packetNft(ctx, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable+";\n"+changed)
		if _, err := process.inspectGuards(ctx, layout); err == nil {
			t.Fatal("memoized inspection accepted broadened or changed reply scope")
		}
	}
}
