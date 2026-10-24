package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

func allocationFixture(t *testing.T) (Baseline, *Compiler, *NAT64AllocationGeometry) {
	t.Helper()
	b, _ := sourceAliasFixture(t)
	pool := netip.MustParsePrefix("10.251.0.0/24")
	b.NAT64[0].SourcePool = &pool
	compiler := testCompiler(t, b)
	geometry, err := compiler.CompileNAT64AllocationGeometry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return b, compiler, geometry
}

func allocationRecord(source, alias string) NAT64SourceMapping {
	return NAT64SourceMapping{Source: netip.MustParseAddr(source), Alias: netip.MustParseAddr(alias)}
}

func TestNAT64AllocationLedgerIndependentComponentsAndOwnedCopies(t *testing.T) {
	t.Parallel()
	b, _, geometry := allocationFixture(t)
	private := slices.Clone(b.NAT64[1].SourceMappings)
	private = append(private, allocationRecord("fdca:1a2b:3::11", "10.252.0.85"))
	// Availability is established separately, never imported from this input.
	private[0].Ready = false
	ledger, err := geometry.Capture(t.Context(), "private64", nil, private)
	if err != nil {
		t.Fatal(err)
	}
	want := []NAT64Allocation{
		{Source: private[0].Source, Alias: private[0].Alias, Identity: 84},
		{Source: private[1].Source, Alias: private[1].Alias, Identity: 85},
	}
	private[0].Alias = netip.MustParseAddr("10.252.0.86")
	b.NAT64[1].SourceMappings[0].Alias = private[0].Alias
	*b.NAT64[1].SourcePool = netip.MustParsePrefix("10.253.0.0/24")
	got, err := ledger.Snapshot(t.Context())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("caller mutation changed original allocation geometry", got, err)
	}
	got[0].Alias = private[0].Alias
	again, err := ledger.Snapshot(t.Context())
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("diagnostic mutation changed original ledger", again, err)
	}
	public, err := geometry.Capture(t.Context(), "global64", nil, []NAT64SourceMapping{
		allocationRecord("fdca:1a2b:3::11", "10.251.0.85"),
	})
	if err != nil {
		t.Fatal("independent pool rejected the same native source", err)
	}
	values, err := public.Snapshot(t.Context())
	if err != nil || len(values) != 1 || values[0].Identity != 85 {
		t.Fatal("component-local connectivity identity changed", values, err)
	}
	for _, original := range []any{geometry, ledger} {
		if _, err := json.Marshal(original); err == nil {
			t.Fatal("original process-local dependency became serializable")
		}
	}
}

func TestNAT64AllocationLedgerRetainsAllPreviousAndReservedPairs(t *testing.T) {
	t.Parallel()
	b, _, geometry := allocationFixture(t)
	reserved := slices.Clone(b.NAT64[1].SourceMappings)
	first, err := geometry.Capture(t.Context(), "private64", nil, reserved)
	if err != nil {
		t.Fatal(err)
	}
	appended := append(slices.Clone(reserved), allocationRecord("fdca:1a2b:3::11", "10.252.0.85"))
	second, err := geometry.Capture(t.Context(), "private64", first, appended)
	if err != nil {
		t.Fatal("valid append changed original identity", err)
	}
	for _, test := range []struct {
		name    string
		records []NAT64SourceMapping
	}{
		{"missing snapshot", nil},
		{"removed reservation", []NAT64SourceMapping{appended[1]}},
		{"removed dynamic allocation", reserved},
		{"reassigned reserved alias", []NAT64SourceMapping{allocationRecord("fdca:1a2b:2::11", "10.252.0.84"), appended[1]}},
		{"moved reserved source", []NAT64SourceMapping{allocationRecord("fdca:1a2b:2::10", "10.252.0.86"), appended[1]}},
		{"moved dynamic source", []NAT64SourceMapping{reserved[0], allocationRecord("fdca:1a2b:3::11", "10.252.0.86")}},
		{"recycled dynamic alias", []NAT64SourceMapping{reserved[0], allocationRecord("fdca:1a2b:3::12", "10.252.0.85")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := geometry.Capture(t.Context(), "private64", second, test.records); err == nil {
				t.Fatal("incomplete or reassigned allocation snapshot accepted")
			}
		})
	}
	slices.Reverse(appended)
	if _, err := geometry.Capture(t.Context(), "private64", second, appended); err != nil {
		t.Fatal("input order changed immutable connectivity", err)
	}
}

func TestNAT64AllocationLedgerRejectsInvalidAndChainedIdentities(t *testing.T) {
	t.Parallel()
	_, _, geometry := allocationFixture(t)
	for _, test := range []struct{ name, source, alias string }{
		{"IPv4 source", "10.240.3.10", "10.251.0.10"},
		{"mapped IPv4 source", "::ffff:10.240.3.10", "10.251.0.10"},
		{"scoped source", "fdca:1a2b:3::10%lan13", "10.251.0.10"},
		{"multicast source", "ff02::1", "10.251.0.10"},
		{"link local source", "fe80::10", "10.251.0.10"},
		{"loopback source", "::1", "10.251.0.10"},
		{"unspecified source", "::", "10.251.0.10"},
		{"public translator source", "64:ff9b::a00:1", "10.251.0.10"},
		{"private translator source", "fdca:1a2b:64::a00:1", "10.251.0.10"},
		{"other pool", "fdca:1a2b:3::10", "10.252.0.10"},
		{"IPv6 alias", "fdca:1a2b:3::10", "fdca:1a2b:2::10"},
		{"network alias", "fdca:1a2b:3::10", "10.251.0.0"},
		{"control alias", "fdca:1a2b:3::10", "10.251.0.1"},
		{"broadcast alias", "fdca:1a2b:3::10", "10.251.0.255"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := geometry.Capture(t.Context(), "global64", nil, []NAT64SourceMapping{allocationRecord(test.source, test.alias)}); err == nil {
				t.Fatal("invalid NAT64 allocation accepted")
			}
		})
	}
	for _, records := range [][]NAT64SourceMapping{
		{allocationRecord("fdca:1a2b:3::10", "10.251.0.10"), allocationRecord("fdca:1a2b:3::10", "10.251.0.11")},
		{allocationRecord("fdca:1a2b:3::10", "10.251.0.10"), allocationRecord("fdca:1a2b:3::11", "10.251.0.10")},
	} {
		if _, err := geometry.Capture(t.Context(), "global64", nil, records); err == nil {
			t.Fatal("duplicate NAT64 source or alias accepted")
		}
	}
}

func TestNAT64AllocationLedgerRequiresOriginalGeometryAndContext(t *testing.T) {
	t.Parallel()
	b, compiler, geometry := allocationFixture(t)
	other, err := compiler.CompileNAT64AllocationGeometry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	records := []NAT64SourceMapping{allocationRecord("fdca:1a2b:3::10", "10.251.0.10")}
	ledger, err := geometry.Capture(t.Context(), "global64", nil, records)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		geometry  *NAT64AllocationGeometry
		component string
	}{
		{"new geometry from same compiler", other, "global64"},
		{"absent geometry", nil, "global64"},
		{"zero geometry", &NAT64AllocationGeometry{}, "global64"},
		{"different component", geometry, "private64"},
		{"disabled component", geometry, "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.geometry.Capture(t.Context(), test.component, ledger, records); err == nil {
				t.Fatal("replacement original dependency accepted")
			}
		})
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := compiler.CompileNAT64AllocationGeometry(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("geometry ignored cancellation", err)
	}
	if _, err := geometry.Capture(canceled, "global64", ledger, records); !errors.Is(err, context.Canceled) {
		t.Fatal("capture ignored cancellation", err)
	}
	if _, err := ledger.Snapshot(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("snapshot ignored cancellation", err)
	}
	if _, err := geometry.ValidateLedger(canceled, "global64", ledger); !errors.Is(err, context.Canceled) {
		t.Fatal("original ledger validation ignored cancellation", err)
	}
	if values, err := geometry.ValidateLedger(t.Context(), "global64", ledger); err != nil || len(values) != len(records) {
		t.Fatal("original ledger validation lost its entries", values, err)
	}
	if _, err := other.ValidateLedger(t.Context(), "global64", ledger); err == nil {
		t.Fatal("replacement geometry adopted an original ledger")
	}
	if _, err := geometry.ValidateLedger(t.Context(), "private64", ledger); err == nil {
		t.Fatal("different component adopted an original ledger")
	}
	if _, err := geometry.Capture(nil, "global64", ledger, records); err == nil { //nolint:staticcheck // A nil context is an intentionally invalid trust-boundary input.
		t.Fatal("nil capture context accepted")
	}
	for _, invalid := range []*NAT64AllocationLedger{nil, {}} {
		if _, err := invalid.Snapshot(t.Context()); err == nil {
			t.Fatal("zero or diagnostic ledger accepted")
		}
	}
	b.NAT64 = nil
	if _, err := testCompiler(t, b).CompileNAT64AllocationGeometry(t.Context()); err == nil {
		t.Fatal("disabled NAT64 acquired allocation geometry")
	}
}

func TestNAT64AllocationLedgerBoundsSmallPoolBeforeAllocating(t *testing.T) {
	t.Parallel()
	b, _, _ := allocationFixture(t)
	pool := netip.MustParsePrefix("10.251.0.0/30")
	b.NAT64[0].SourcePool = &pool
	geometry, err := testCompiler(t, b).CompileNAT64AllocationGeometry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	first := allocationRecord("fdca:1a2b:3::10", "10.251.0.2")
	if _, err := geometry.Capture(t.Context(), "global64", nil, []NAT64SourceMapping{first}); err != nil {
		t.Fatal("last available allocation rejected", err)
	}
	if _, err := geometry.Capture(t.Context(), "global64", nil, []NAT64SourceMapping{first, first}); err == nil {
		t.Fatal("oversized allocation snapshot accepted")
	}
}

func TestNAT64AllocationLedgerRetainsEightReservationsWithoutReadiness(t *testing.T) {
	t.Parallel()
	b, _, _ := allocationFixture(t)
	b.NAT64[1].SourceMappings = nil
	for index := 0; index < 8; index++ {
		b.NAT64[1].SourceMappings = append(b.NAT64[1].SourceMappings,
			allocationRecord(fmt.Sprintf("fdca:1a2b:2::%x", 0x80+index), fmt.Sprintf("10.252.0.%d", 80+index)))
	}
	geometry, err := testCompiler(t, b).CompileNAT64AllocationGeometry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := geometry.Capture(t.Context(), "private64", nil, b.NAT64[1].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	values, err := ledger.Snapshot(t.Context())
	if err != nil || len(values) != 8 {
		t.Fatal("retained inactive reservations were lost", values, err)
	}
	if _, err := geometry.Capture(t.Context(), "private64", ledger, b.NAT64[1].SourceMappings[:7]); err == nil {
		t.Fatal("an inactive reservation became recyclable")
	}
}

func TestNAT64AllocationLedgerExcludesNAT46SourcesAndBoundsIdentity(t *testing.T) {
	t.Parallel()
	b, _ := nat46GeometryFixture(t)
	for index, raw := range []string{"10.251.0.0/16", "10.252.0.0/24"} {
		pool := netip.MustParsePrefix(raw)
		b.NAT64[index].SourcePool = &pool
	}
	geometry, err := testCompiler(t, b).CompileNAT64AllocationGeometry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := geometry.Capture(t.Context(), "global64", nil,
		[]NAT64SourceMapping{allocationRecord("fdca:1a2b:e046::10", "10.251.1.0")}); err == nil {
		t.Fatal("NAT46-derived identity became an original NAT64 source")
	}
	ledger, err := geometry.Capture(t.Context(), "global64", nil, []NAT64SourceMapping{
		allocationRecord("fdca:1a2b:3::10", "10.251.1.0"),
		allocationRecord("fdca:1a2b:3::11", "10.251.255.254"),
	})
	if err != nil {
		t.Fatal(err)
	}
	values, err := ledger.Snapshot(t.Context())
	if err != nil || values[0].Identity != 256 || values[1].Identity != 65534 {
		t.Fatal("allocation identity was truncated or incorrectly reserved", values, err)
	}
}
