package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func nat46StaticGeometryFixture(t *testing.T) Baseline {
	t.Helper()
	b, _ := nat46GeometryFixture(t)
	b.NetworkModel.Rules = []NetworkRule{{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{6053}, From: []NetworkSelector{{Interface: "lan12", Addresses: prefixes("10.240.2.10/32")}}, To: []NetworkSelector{{Interface: "lan12", Addresses: []netip.Prefix{netip.PrefixFrom(b.NAT46[0].Target, 128)}}}}}
	return b
}

func TestNAT46StaticGeometryPinsReachableAddressesWithoutGrantingTrust(t *testing.T) {
	t.Parallel()
	b := nat46StaticGeometryFixture(t)
	b.NetworkModel.Rules[0].From = append(b.NetworkModel.Rules[0].From, NetworkSelector{Interface: "lan12", Addresses: prefixes("10.240.2.8/29")})
	b.ProtectedNetworks = append(b.ProtectedNetworks, NetworkBlock{ProtectionID: "P01", Networks: prefixes("10.240.2.11/32"), Roles: []Role{}}, NetworkBlock{ProtectionID: "P03", Networks: prefixes("10.240.2.12/32"), Roles: []Role{}})
	compiler := testCompiler(t, b)
	geometry, err := compiler.CompileNAT46StaticGeometry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := geometry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Sources) != 7 {
		t.Fatalf("expected a union of seven possible addresses, got %d", len(snapshot.Sources))
	}
	if snapshot.BaselineHash != compiler.BaselineHash() {
		t.Fatal("geometry changed its immutable baseline")
	}
	for index, source := range snapshot.Sources {
		if source.Interface != "lan12" || source.Original == netip.MustParseAddr("10.240.2.11") || source.ID != uint32(index+1) {
			t.Fatal("source borrowed another attachment or protected address")
		}
		raw := source.Original.As4()
		embedded := source.Embedded.As16()
		if !reflect.DeepEqual(raw[:], embedded[12:]) || !snapshot.Prefix.Contains(source.Embedded) {
			t.Fatal("source identity changed the embedded client address")
		}
	}
	found := false
	for _, source := range snapshot.Sources {
		found = found || source.Original == netip.MustParseAddr("10.240.2.12")
	}
	if !found {
		t.Fatal("delegation ceiling became an owner prohibition")
	}
	original := snapshot.Sources[0]
	snapshot.Sources[0].Original = netip.MustParseAddr("10.243.0.99")
	b.NetworkModel.Rules[0].From[0].Addresses[0] = netip.MustParsePrefix("0.0.0.0/0")
	again, err := geometry.Snapshot(t.Context())
	if err != nil || again.Sources[0] != original {
		t.Fatal("caller or snapshot mutation changed compiler-local geometry", err)
	}
	if _, err := json.Marshal(geometry); err == nil {
		t.Fatal("diagnostic serialization could restore geometry evidence")
	}
	var zero NAT46StaticGeometry
	if _, err := zero.Snapshot(t.Context()); err == nil {
		t.Fatal("empty evidence became publishable geometry")
	}
}

func TestNAT46StaticGeometryBoundsBeforeEnumerationAndKeepsEndpointPairs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		edit     func(*Baseline)
		want     int
		overflow bool
	}{
		{"exact source", func(*Baseline) {}, 1, false},
		{"wrong source attachment", func(b *Baseline) { b.NetworkModel.Rules[0].From[0].Interface = "lan13" }, 0, false},
		{"managed source stays NAS-owned", func(b *Baseline) {
			b.NetworkModel.Rules[0].From[0].Interface = "lan13"
			b.NetworkModel.Rules[0].From[0].Addresses = prefixes("10.240.3.10/32")
		}, 0, false},
		{"wrong target attachment", func(b *Baseline) { b.NetworkModel.Rules[0].To[0].Interface = "nat46" }, 0, false},
		{"IPv6 source", func(b *Baseline) { b.NetworkModel.Rules[0].From[0].Addresses = prefixes("fdca:1a2b:2::10/128") }, 0, false},
		{"deny only", func(b *Baseline) { b.NetworkModel.Rules[0].Action = "deny" }, 0, false},
		{"bounded WAN source", func(b *Baseline) {
			b.NetworkModel.Rules[0].From[0].Interface = "wan"
			b.NetworkModel.Rules[0].From[0].Addresses = prefixes("10.243.0.2/32")
		}, 1, false},
		{"WAN cannot borrow LAN source", func(b *Baseline) { b.NetworkModel.Rules[0].From[0].Interface = "wan" }, 0, false},
		{"unbounded WAN source", func(b *Baseline) {
			b.NetworkModel.Rules[0].From[0].Interface = "wan"
			b.NetworkModel.Rules[0].From[0].Addresses = nil
		}, 0, true},
		{"large LAN source", func(b *Baseline) {
			b.Zones[0].Networks = prefixes("10.128.0.0/16", "fdca:1a2b:2::/64")
			b.NetworkModel.Rules[0].From[0].Addresses = nil
		}, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			b := nat46StaticGeometryFixture(t)
			test.edit(&b)
			geometry, err := testCompiler(t, b).CompileNAT46StaticGeometry(t.Context())
			if test.overflow {
				if err == nil || !strings.Contains(err.Error(), "identity capacity") {
					t.Fatal("oversized source universe was enumerated", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := geometry.Snapshot(t.Context())
			if err != nil || len(snapshot.Sources) != test.want {
				t.Fatal("incorrect source universe", len(snapshot.Sources), test.want, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := testCompiler(t, nat46StaticGeometryFixture(t)).CompileNAT46StaticGeometry(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled source enumeration continued", err)
	}
}
