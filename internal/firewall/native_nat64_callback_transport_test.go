package firewall

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func callbackTransportFixture(t *testing.T) *nativeNAT64Transport {
	t.Helper()
	b := nat64TransportFixture(t)
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{
		{Source: netip.MustParseAddr("fdca:1a2b:3::10"), Alias: netip.MustParseAddr("10.251.0.20"), Ready: true},
		{Source: netip.MustParseAddr("fdca:1a2b:3::11"), Alias: netip.MustParseAddr("10.251.0.21"), Ready: false},
	}
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func TestNAT64CallbackTransportKeepsAllocationAndDirectionNamespacesSeparate(t *testing.T) {
	t.Parallel()
	native := callbackTransportFixture(t)
	beforeDefinitions, beforeClears := len(native.definitions()), len(native.tupleProofClears())
	callback, err := newNativeNAT64CallbackTransport(t.Context(), native)
	if err != nil {
		t.Fatal(err)
	}
	if callback.native != native || native.callbacks != callback || len(callback.proof.legs) != 6 || len(native.definitions()) != beforeDefinitions+24 || len(native.tupleProofClears()) != beforeClears+24 {
		t.Fatal("callback construction lost original geometry or protocol/revocation inventory")
	}
	for name, rules := range callback.chains() {
		for _, rule := range rules {
			if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") {
				t.Fatal("callback proof acquired permission", name, rule.text)
			}
		}
	}
	schema := native.schema()
	for _, leg := range callback.proof.legs {
		if leg.translator() != native.component || leg.mapping.targetInterface != "lan13" || leg.mapping.alias.String() != "10.251.0.20" {
			t.Fatal("callback selected another mapping or attachment", leg)
		}
		for _, imported := range []bool{false, true} {
			direction := "export"
			if imported {
				direction = "import"
			}
			name := leg.name + "_" + direction
			geometry := callback.chains()[name][0].text
			expected := native.name + "_active_aliases"
			if leg.reply != imported {
				expected = native.name + "_sources"
			}
			if !strings.Contains(geometry, native.component) || !strings.Contains(geometry, expected) || len(schema.rules[name]) != 2 {
				t.Fatal("callback admission lost its exact selected geometry or live allocation", name, geometry)
			}
		}
		for _, suffix := range []string{"_epoch", "_context", "_channel", "_tuple"} {
			name := leg.name + suffix
			if schema.maps[name] == nil && schema.sets[name] == nil {
				t.Fatal("missing frozen callback object", name)
			}
		}
	}
	bytes, err := json.Marshal(native.tupleProofClears())
	if err != nil {
		t.Fatal(err)
	}
	for _, leg := range callback.proof.legs {
		if strings.Count(string(bytes), `"name":"`+leg.name+`_tuple"`) != 1 {
			t.Fatal("callback proof is not revoked exactly once", leg.name)
		}
	}
	if _, err := newNativeNAT64CallbackTransport(t.Context(), native); err == nil {
		t.Fatal("callback geometry attached twice")
	}
	b := nat64TransportFixture(t)
	layout, err := newNativeNAT64AccessLayout(t.Context(), b, "nat64-internal")
	if err != nil || layout.native.nat64Transport.callbacks != nil {
		t.Fatal("ordinary NAT64 construction activated callback admission", err)
	}
}

func TestNAT64CallbackTransportRejectsDetachedUnboundedAndAmbiguousTargets(t *testing.T) {
	t.Parallel()
	if _, err := newNativeNAT64CallbackTransport(t.Context(), nil); err == nil {
		t.Fatal("missing original transport accepted")
	}
	for _, test := range []struct {
		name   string
		change func(*nativeNAT64Transport)
	}{
		{"detached geometry", func(n *nativeNAT64Transport) { n.geometry = nil }},
		{"invalid prefix", func(n *nativeNAT64Transport) { n.prefix = netip.Prefix{} }},
		{"changed reservation", func(n *nativeNAT64Transport) { n.mappings[0].Alias = netip.MustParseAddr("10.251.0.99") }},
		{"undeclared target attachment", func(n *nativeNAT64Transport) { n.sourceNetworks = map[string][]netip.Prefix{} }},
		{"ambiguous target attachment", func(n *nativeNAT64Transport) { n.sourceNetworks["another"] = n.sourceNetworks["lan13"] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			native := callbackTransportFixture(t)
			test.change(native)
			if _, err := newNativeNAT64CallbackTransport(t.Context(), native); err == nil {
				t.Fatal("unsafe callback geometry accepted")
			}
			if native.callbacks != nil {
				t.Fatal("failed constructor retained callback state")
			}
		})
	}
	t.Run("bounded protocol and mapping product", func(t *testing.T) {
		b := nat64TransportFixture(t)
		source, alias := netip.MustParseAddr("fdca:1a2b:3::100"), netip.MustParseAddr("10.251.0.2")
		for range nativeRuleCapacity/160 + 1 {
			b.NAT64[0].SourceMappings = append(b.NAT64[0].SourceMappings, policy.NAT64SourceMapping{Source: source, Alias: alias, Ready: true})
			source, alias = source.Next(), alias.Next()
		}
		native, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newNativeNAT64CallbackTransport(t.Context(), native); err == nil || native.callbacks != nil {
			t.Fatal("unbounded callback product retained state")
		}
	})
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	native := callbackTransportFixture(t)
	if _, err := newNativeNAT64CallbackTransport(cancelled, native); err == nil || native.callbacks != nil {
		t.Fatal("cancelled constructor retained callback state")
	}
}
