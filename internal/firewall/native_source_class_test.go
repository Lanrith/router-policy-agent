package firewall

import (
	"context"
	"net/netip"
	"slices"
	"testing"
)

func sourceClassPrefixes(values ...string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

func TestPartitionRetainsEveryPartialSourceDecisionExactlyOnce(t *testing.T) {
	t.Parallel()
	pools := sourceClassPrefixes("10.240.3.0/24", "10.240.5.0/24")
	selectors := sourceClassPrefixes("0.0.0.0/0", "10.240.0.0/16", "10.240.3.128/25", "10.240.3.173/32", "10.240.3.160/28", "10.240.3.176/28", "10.240.5.10/32", "fdca:1a2b::/48")
	classes, err := partitionNativeSources(t.Context(), pools, selectors)
	if err != nil {
		t.Fatal(err)
	}
	for _, pool := range pools {
		for address := pool.Addr(); pool.Contains(address); address = address.Next() {
			found := 0
			for _, class := range classes {
				if !class.contains(address) {
					continue
				}
				found++
				for _, selector := range selectors {
					if class.within(selector) != selector.Contains(address) {
						t.Fatalf("source %s class %s changed selector %s", address, class.prefix, selector)
					}
				}
			}
			if found != 1 {
				t.Fatalf("source %s belongs to %d classes", address, found)
			}
		}
	}
	for _, class := range classes {
		for _, address := range []string{"10.240.2.1", "10.240.6.1", "fdca:1a2b::1"} {
			if class.contains(netip.MustParseAddr(address)) {
				t.Fatal("outside address entered NAT source class")
			}
		}
	}
	// Input order and caller mutations cannot change retained geometry.
	reversed := slices.Clone(selectors)
	slices.Reverse(reversed)
	other, err := partitionNativeSources(t.Context(), pools, reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(classes, other, func(a, b nativeSourceClass) bool { return a.prefix == b.prefix && slices.Equal(a.children, b.children) }) {
		t.Fatal("source classes depend on input order")
	}
	pools[0] = netip.MustParsePrefix("0.0.0.0/0")
	selectors[0] = netip.MustParsePrefix("1.0.0.0/8")
	if !slices.EqualFunc(classes, other, func(a, b nativeSourceClass) bool { return a.prefix == b.prefix && slices.Equal(a.children, b.children) }) {
		t.Fatal("caller mutation changed retained source classes")
	}
}

func TestPartitionOmitsAnEntirelyCoveredParent(t *testing.T) {
	t.Parallel()
	classes, err := partitionNativeSources(t.Context(), sourceClassPrefixes("10.10.0.0/24"), sourceClassPrefixes("10.10.0.0/25", "10.10.0.128/25"))
	if err != nil || len(classes) != 2 {
		t.Fatal(classes, err)
	}
	for _, class := range classes {
		if class.prefix.Bits() != 25 {
			t.Fatal("empty source class retained")
		}
	}
}

func TestPartitionRejectsInvalidAndExcessiveGeometry(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name              string
		pools, boundaries []netip.Prefix
	}{{"overlap", sourceClassPrefixes("10.0.0.0/24", "10.0.0.0/25"), nil}, {"duplicate", sourceClassPrefixes("10.0.0.0/24", "10.0.0.0/24"), nil}, {"default", sourceClassPrefixes("0.0.0.0/0"), nil}, {"IPv6 allocation", sourceClassPrefixes("fdca::/64"), nil}, {"hostbits", sourceClassPrefixes("10.0.0.1/24"), nil}, {"selector hostbits", sourceClassPrefixes("10.0.0.0/24"), sourceClassPrefixes("10.0.0.1/24")}, {"missing", nil, nil}} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := partitionNativeSources(t.Context(), test.pools, test.boundaries); err == nil {
				t.Fatal("unsafe source class accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := partitionNativeSources(ctx, sourceClassPrefixes("10.0.0.0/24"), nil); err == nil {
		t.Fatal("canceled source partition succeeded")
	}
	if _, err := partitionNativeSources(nil, sourceClassPrefixes("10.0.0.0/24"), nil); err == nil { //nolint:staticcheck // Deliberately test the missing-context boundary.
		t.Fatal("missing context accepted")
	}
}
