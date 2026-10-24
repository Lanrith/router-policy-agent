package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT46ContextCoverageRequiresTheEntireOriginalProduct(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"complete", "split prefixes", "partial prefix", "partial listener", "other interface", "other MAC", "other destination", "other protocol", "terminal directory", "terminal deny"} {
		t.Run(name, func(t *testing.T) {
			b := nat46ForwardingBaseline(t)
			later := b.NetworkModel.Rules[2]
			prior := later
			want := name == "complete" || name == "split prefixes" || name == "terminal directory" || name == "terminal deny"
			switch name {
			case "split prefixes":
				prior.From = []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.0/25", "10.240.0.128/25")}}
			case "partial prefix":
				prior.From = []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.0/25")}}
			case "partial listener":
				prior.Protocol, later.Protocol, prior.Ports = "tcp", "tcp", []uint16{6053}
			case "other interface":
				prior.From = []policy.NetworkSelector{{Interface: "lan13"}}
			case "other MAC":
				prior.From = []policy.NetworkSelector{{Interface: "lan10", MAC: "02:00:00:00:00:ee"}}
			case "other destination":
				prior.To = []policy.NetworkSelector{{Interface: "wan"}}
			case "other protocol":
				prior.Protocol, later.Protocol = "udp", "tcp"
			case "terminal directory":
				prior.Authorization = "directory"
			case "terminal deny":
				prior.Action, prior.Authorization = "deny", "inherit"
			}
			b.NetworkModel.Rules = []policy.NetworkRule{prior, later}
			model, err := newNativeNAT46Model(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			got, err := model.contextCovered(t.Context(), 1, 0, nativePacketContext{iface: "lan10", family: 4}, "tcp")
			if err != nil || got != want {
				t.Fatal("incorrect first-match coverage", got, want, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := model.contextCovered(ctx, 1, 0, nativePacketContext{iface: "lan10", family: 4}, "tcp"); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled coverage continued", err)
			}
		})
	}
}
