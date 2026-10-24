package firewall

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nat64TransportFixture(t *testing.T) policy.Baseline {
	t.Helper()
	b := nativeAccessBaseline(t)
	pool := netip.MustParsePrefix("10.251.0.0/24")
	b.NAT64 = []policy.NAT64{{ID: "nat64-internal", Prefix: netip.MustParsePrefix("fdca:1a2b:e064::/96"), Scope: "private", SourcePool: &pool}}
	return b
}

func TestNAT64TupleTransportOwnsGeometryAndNeverGrantsAccess(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	before := transport.chains()
	if len(transport.legs) != 6 || len(transport.definitions()) != 16 {
		t.Fatal("NAT64 transport omitted a direction, protocol or fixed collection")
	}
	for name, rules := range before {
		for _, rule := range rules {
			if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") {
				t.Fatal("NAT64 tuple transport acquired packet authority", name)
			}
		}
	}
	for _, leg := range transport.legs {
		for _, imported := range []bool{false, true} {
			geometry := leg.geometry(imported).text
			if !strings.Contains(geometry, "nat64-internal") || !strings.Contains(geometry, leg.protocol) && leg.protocol != "icmp" {
				t.Fatal("NAT64 tuple escaped its attachment or protocol")
			}
			_, key := leg.tuple(imported)
			object, ok := key.(map[string]any)
			fields, fieldsOK := object["concat"].([]any)
			if !ok || !fieldsOK || len(fields) != 4 && leg.protocol != "icmp" || len(fields) != 3 && leg.protocol == "icmp" {
				t.Fatal("NAT64 proof key lost allocation, peer, or transport identity")
			}
			allocation := leg.allocation(transport, imported)
			allocationSet := transport.name + "_sources"
			if leg.reply != imported {
				allocationSet = transport.name + "_active_aliases"
			}
			if !strings.Contains(allocation.text, allocationSet) {
				t.Fatal("NAT64 leg lost its current allocation join")
			}
		}
	}
	for _, leg := range transport.legs {
		for _, imported := range []bool{false, true} {
			physical := leg.physicalGeometry(imported).text
			if strings.Contains(physical, "iifname") || strings.Contains(physical, "oifname") || strings.Contains(physical, "ct direction") || strings.Contains(physical, "ct state") {
				t.Fatalf("netdev NAT64 geometry depends on unavailable connection metadata: %s", physical)
			}
			if !strings.Contains(physical, leg.protocol) && leg.protocol != "icmp" {
				t.Fatalf("netdev NAT64 geometry lost protocol: %s", physical)
			}
			if leg.protocol != "icmp" {
				grant := leg.grantGeometry(imported).text
				physicalGrant := leg.physicalGrantGeometry(imported).text
				if strings.Contains(grant, "meta l4proto") || strings.Contains(physicalGrant, "meta l4proto") ||
					!strings.Contains(grant, leg.prefix.String()) && !strings.Contains(grant, leg.pool.String()) ||
					!strings.Contains(physicalGrant, leg.prefix.String()) && !strings.Contains(physicalGrant, leg.pool.String()) {
					t.Fatal("typed NAT64 grant geometry differs from nft canonical transport constraints", grant, physicalGrant)
				}
			}
		}
	}
	schema := transport.schema()
	if len(schema.sets) != 4 || len(schema.maps) != 12 || !reflect.DeepEqual(schema.rules, nativeRulesExpressionsByChain(before)) {
		t.Fatal("NAT64 inspection schema differs from generated transport")
	}
	pending := schema.sets[transport.name+"_pending"]
	if pending["type"] != "ipv6_addr" || pending["size"] != 4096 || pending["timeout"] != 5 ||
		!reflect.DeepEqual(pending["flags"], []string{"timeout", "dynamic"}) {
		t.Fatal("NAT64 request set lost its bounded dynamic schema", pending)
	}
	if schema.maps[transport.name+"_tokens"]["type"] == nil || schema.maps[transport.name+"_token_channel"]["map"] != "classid" {
		t.Fatal("NAT64 token registry lost its fixed datatypes")
	}
	b.NAT64[0].Prefix = netip.MustParsePrefix("fdca:1a2b:e065::/96")
	*b.NAT64[0].SourcePool = netip.MustParsePrefix("10.252.0.0/24")
	if !reflect.DeepEqual(before, transport.chains()) {
		t.Fatal("caller mutation changed immutable NAT64 transport geometry")
	}
}

func nativeRulesExpressionsByChain(chains map[string][]nativeScope) map[string][][]any {
	result := make(map[string][][]any, len(chains))
	for name, rules := range chains {
		result[name] = nativeRulesExpressions(rules)
	}
	return result
}

func TestNAT64TupleTransportRejectsAmbiguousAttachmentsAndMissingRoots(t *testing.T) {
	t.Parallel()
	b := nat64TransportFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newNativeNAT64Transport(ctx, b, "nat64-internal"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled NAT64 construction continued", err)
	}
	if _, err := newNativeNAT64Transport(nil, b, "nat64-internal"); err == nil { //nolint:staticcheck // Deliberately invalid trust-boundary input.
		t.Fatal("nil NAT64 context accepted")
	}
	for _, test := range []struct {
		name      string
		component string
		mutate    func(*policy.Baseline)
	}{
		{"missing component", "missing", func(*policy.Baseline) {}},
		{"uplink attachment", "uplink0", func(b *policy.Baseline) { b.NAT64[0].ID = b.NetworkModel.UplinkInterface }},
		{"native attachment", "lan10", func(b *policy.Baseline) { b.NAT64[0].ID = b.Zones[0].Interfaces[0] }},
		{"invalid attachment", "bad attachment", func(b *policy.Baseline) { b.NAT64[0].ID = "bad attachment" }},
		{"missing pool", "nat64-internal", func(b *policy.Baseline) { b.NAT64[0].SourcePool = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := nat64TransportFixture(t)
			test.mutate(&candidate)
			if _, err := newNativeNAT64Transport(t.Context(), candidate, test.component); err == nil {
				t.Fatal("ambiguous or missing NAT64 geometry accepted")
			}
		})
	}
}

func TestNAT64ZoneIdentityIsBijectiveAcrossOwnedPoolSuffixes(t *testing.T) {
	t.Parallel()
	seen := map[uint16]bool{}
	for _, identity := range []uint16{1, 10, 255, 256, 4096, 65534, 65535} {
		zone := nativeNAT64ZoneIdentity(identity)
		if seen[zone] || nativeNAT64ZoneIdentity(zone) != identity {
			t.Fatal("NAT64 zone identity is not a byte-order bijection", identity, zone)
		}
		seen[zone] = true
	}
}
