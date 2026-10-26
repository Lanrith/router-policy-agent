//go:build integration && kernel && conntrackreplay && linux

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// A transport fixture can leave an ICMP connection after its links and rules
// are removed. Its epoch mark must not contaminate the ordered-wire fixture.
// Run this deliberate state collision in its own network namespace so it cannot
// affect the remaining packet fixtures.
func TestKernelNamedNAT46OrderedWirePolicyAfterTransport(t *testing.T) {
	t.Run("seed-prior-transport", func(t *testing.T) {
		requireKernelIsolation(t)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		setupPacketLinks(ctx, t)
		packetIP(
			ctx,
			t,
			"link",
			"add",
			"nat46",
			"type",
			"veth",
			"peer",
			"name",
			"translated0",
		)
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(
				cleanup,
				t,
				"link",
				"delete",
				"nat46",
			)
		})
		packetIP(
			ctx,
			t,
			"link",
			"set",
			"nat46",
			"address",
			"02:00:00:00:01:46",
		)
		packetIP(
			ctx,
			t,
			"link",
			"set",
			"translated0",
			"address",
			"02:00:00:00:00:46",
		)
		packetIP(
			ctx,
			t,
			"link",
			"set",
			"nat46",
			"up",
		)
		packetIP(
			ctx,
			t,
			"link",
			"set",
			"translated0",
			"up",
		)
		packetIP(
			ctx,
			t,
			"-6",
			"route",
			"add",
			"fdca:1a2b:e046::/96",
			"dev",
			"nat46",
		)
		packetIP(
			ctx,
			t,
			"neighbor",
			"replace",
			"fdca:1a2b:e046::af0:a",
			"dev",
			"nat46",
			"lladdr",
			"02:00:00:00:00:46",
			"nud",
			"permanent",
		)
		packetNft(ctx, t, `table inet nat46_scope_prior {
 chain forward {type filter hook forward priority 0;policy accept;
  meta l4proto ipv6-icmp ct mark set 0x1c03
 }
}
table netdev nat46_scope_prior {
 chain endpoint {type filter hook ingress device "device0" priority 0;policy drop;}
 chain input_endpoint {type filter hook ingress device "translated0" priority 0;policy drop;}
}`)
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetNft(cleanup, t, "delete table inet nat46_scope_prior;delete table netdev nat46_scope_prior")
		})
		frame := packetDatagram{
			source:         netip.MustParseAddr("fdca:1a2b:e046::af0:a"),
			destination:    netip.MustParseAddr("fdca:1a2b:3::10"),
			sourceMAC:      "02:00:00:00:00:46",
			destinationMAC: "02:00:00:00:01:46", isICMP: true, icmpType: 128,
			icmpData: 0xc0460001, payload: "prior-transport-echo",
		}
		input, output := packetSocket(t, "translated0"), packetSocket(t, "device0")
		sendPacket(
			ctx,
			t,
			input,
			packetFrame(t, frame),
		)
		receivePacket(
			ctx,
			t,
			output,
			packetFrame(t, frame),
			true,
		)
	})
	t.Run("ordered-wire-after-transport", TestKernelNamedNAT46OrderedWirePolicy)
}
