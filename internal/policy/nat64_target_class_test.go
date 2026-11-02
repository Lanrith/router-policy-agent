package policy

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestNAT64TargetClassMatchesOriginalEligibility(t *testing.T) {
	t.Parallel()
	baseline, _, geometry := allocationFixture(t)
	for _, component := range baseline.NAT64 {
		t.Run(component.ID, func(t *testing.T) {
			class, err := geometry.TargetClass(t.Context(), component.ID)
			if err != nil {
				t.Fatal(err)
			}
			check := func(address netip.Addr) {
				t.Helper()
				got := inPrefixes(address, class.Allowed) && !inPrefixes(address, class.Excluded)
				if want := eligible(component, address); got != want {
					t.Fatal("target class changed original eligibility", component.ID, address, got, want)
				}
			}
			// Check every boundary, including the addresses immediately outside
			// each prefix, and a deterministic spread across all IPv4 space.
			for _, prefix := range append(append([]netip.Prefix{}, class.Allowed...), class.Excluded...) {
				for _, address := range []netip.Addr{prefix.Addr(), prefix.Addr().Prev(), lastPoolAddress(prefix), lastPoolAddress(prefix).Next()} {
					if address.IsValid() {
						check(address)
					}
				}
			}
			for value := uint32(0); value < 10000; value++ {
				var bytes [4]byte
				binary.BigEndian.PutUint32(bytes[:], value*2654435761)
				check(netip.AddrFrom4(bytes))
			}
			check(netip.MustParseAddr("fdca:1a2b::1"))
			original, err := geometry.TargetClass(t.Context(), component.ID)
			if err != nil {
				t.Fatal(err)
			}
			class.Allowed[0] = netip.MustParsePrefix("127.0.0.0/8")
			if len(class.Excluded) != 0 {
				class.Excluded[0] = class.Allowed[0]
			}
			again, err := geometry.TargetClass(t.Context(), component.ID)
			if err != nil || !reflect.DeepEqual(original, again) {
				t.Fatal("diagnostic mutation changed original target class", err)
			}
		})
	}
}

func TestNAT64TargetClassRequiresOriginalGeometryAndContext(t *testing.T) {
	t.Parallel()
	_, _, geometry := allocationFixture(t)
	if _, err := geometry.TargetClass(t.Context(), "missing"); err == nil {
		t.Fatal("undeclared component accepted")
	}
	for _, invalid := range []*NAT64AllocationGeometry{nil, {}} {
		if _, err := invalid.TargetClass(t.Context(), "global64"); err == nil {
			t.Fatal("detached class accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := geometry.TargetClass(ctx, "global64"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled class construction continued", err)
	}
}
