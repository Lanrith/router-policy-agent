package firewall

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeNAT46ModelFixture(t *testing.T) policy.Baseline {
	t.Helper()
	b := nativeScopeBaseline(t)
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	b.NetworkModel.Rules = []policy.NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6053},
		From: []policy.NetworkSelector{{Interface: "lan10", Addresses: sourceClassPrefixes("10.240.0.10/32"), MAC: "02:00:00:00:00:10"}},
		To:   []policy.NetworkSelector{{Interface: "lan12", Addresses: sourceClassPrefixes("fdca:1a2b:2::20/128")}}}}
	return b
}

func TestNAT46ProjectionPreservesOrderedAuthorizationAndEndpointPairing(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"native target", "raw alias", "wrong alias interface", "wrong target interface", "ipv6 rule", "ipv6 source", "unready mapping", "deny", "owner"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := nativeNAT46ModelFixture(t)
			rule := &b.NetworkModel.Rules[0]
			wantAlias := name == "native target" || name == "deny" || name == "owner"
			switch name {
			case "raw alias":
				rule.To = []policy.NetworkSelector{{Interface: "nat46", Addresses: sourceClassPrefixes("10.250.0.0/24")}}
			case "wrong alias interface":
				rule.To[0].Addresses = sourceClassPrefixes("10.250.0.20/32")
			case "wrong target interface":
				rule.To[0].Interface = "nat46"
			case "ipv6 rule":
				rule.Family = 6
			case "ipv6 source":
				rule.From[0].Addresses = sourceClassPrefixes("fdca:1a2b::10/128")
			case "unready mapping":
				b.NAT46[0].Ready = false
			case "deny":
				rule.Action = "deny"
			case "owner":
				rule.Authorization = "owner"
			}
			model, err := newNativeNAT46Model(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			actual := model.rules.rules[0]
			if len(model.rules.rules) != 1 || actual.Action != rule.Action || actual.Authorization != rule.Authorization ||
				actual.Protocol != rule.Protocol || actual.Family != rule.Family ||
				!reflect.DeepEqual(actual.From, rule.From) || !reflect.DeepEqual(actual.Ports, rule.Ports) {
				t.Fatal("projection changed rule order, original source, protocol or authorization")
			}
			if wantAlias {
				if len(actual.To) != 2 || actual.To[1].Interface != "nat46" ||
					!reflect.DeepEqual(actual.To[1].Addresses, sourceClassPrefixes("10.250.0.20/32")) {
					t.Fatal("native target did not retain its exact alias and attachment")
				}
			} else if !reflect.DeepEqual(actual.To, rule.To) {
				t.Fatal("unreachable, unready or incorrectly paired alias was added")
			}
			before := model.prefix
			*b.NetworkModel.NAT46Prefix = netip.MustParsePrefix("fdca:1a2b:e047::/96")
			b.NAT46[0].Alias = netip.MustParseAddr("10.250.0.99")
			if model.prefix != before || len(model.mappings) != 0 && model.mappings[0].alias == b.NAT46[0].Alias {
				t.Fatal("caller mutation changed owned translation geometry")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newNativeNAT46Model(ctx, nativeNAT46ModelFixture(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled projection continued", err)
	}
	b := nativeNAT46ModelFixture(t)
	b.NetworkModel.NAT46Prefix = nil
	if _, err := newNativeNAT46Model(t.Context(), b); err == nil {
		t.Fatal("projection guessed missing generated geometry")
	}
}
