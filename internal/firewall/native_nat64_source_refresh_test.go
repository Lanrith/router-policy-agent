package firewall

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nat64ModeGrantFlushes(t *testing.T, data []byte) int {
	t.Helper()
	var batch struct {
		Commands []struct {
			Flush map[string]objectReference `json:"flush"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, command := range batch.Commands {
		for _, ref := range command.Flush {
			for _, expected := range nativeNAT64GrantRefs() {
				if ref == expected {
					count++
				}
			}
		}
	}
	return count
}

func TestNAT64SourceTransitionsRevokeDelegatedProjectionsAtomically(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, true)
	utc := time.Now().UTC()
	renderer, err := newRenderer(fixture.baseline)
	if err != nil {
		t.Fatal(err)
	}
	source, err := renderer.prepareNativeOwnership(t.Context(), fixture.sources.evidence, utc)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT64SourceRefresh(t.Context(), source, fixture.sources, 9, fixture.transport)
	if err != nil {
		t.Fatal(err)
	}
	if nat64ModeGrantFlushes(t, prepared.batch.data) != len(nativeNAT64GrantRefs()) {
		t.Fatal("NAT64 source transition omitted an exact delegated-grant revocation")
	}
	if err := validateOwnershipPreparation(t.Context(), prepared, utc); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeSourceReceipt(t.Context(), prepared); err != nil {
		t.Fatal("NAT64 transition lost its original source receipt", err)
	}
	for _, forbidden := range (&nativeNAT64Tokens{transport: fixture.transport}).names() {
		if strings.Contains(string(prepared.batch.data), forbidden) {
			t.Fatal("source transition changed independently published NAT64 token state", forbidden)
		}
	}
	if strings.Contains(string(prepared.batch.data), fixture.transport.name+"_zones") {
		t.Fatal("source transition changed independently published NAT64 allocations")
	}

	for _, name := range []string{"missing transport", "foreign transport", "legacy source"} {
		t.Run(name, func(t *testing.T) {
			changed := *prepared
			switch name {
			case "missing transport":
				changed.nat64Transport = nil
			case "foreign transport":
				transport := *fixture.transport
				transport.baselineHash = strings.Repeat("a", 64)
				changed.nat64Transport = &transport
			case "legacy source":
				changed.nativeSources = false
			}
			if err := validateOwnershipPreparation(t.Context(), &changed, utc); err == nil {
				t.Fatal("changed NAT64 source transition accepted")
			}
		})
	}
	if source.nat64Transport != nil || nat64ModeGrantFlushes(t, source.batch.data) != 0 {
		t.Fatal("NAT64 mode changed its caller-owned ordinary source preparation")
	}
}

func TestNAT64OwnershipClearRevokesDelegatedProjectionsOnlyForSelectedLayout(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, false)
	ordinary, err := prepareNativeOwnershipClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	selected, err := prepareNativeNAT64OwnershipClear(t.Context(), fixture.transport)
	if err != nil {
		t.Fatal(err)
	}
	if nat64ModeGrantFlushes(t, ordinary.batch.data) != 0 || nat64ModeGrantFlushes(t, selected.batch.data) != len(nativeNAT64GrantRefs()) {
		t.Fatal("NAT64 ownership clear changed the wrong layout inventory")
	}
	if err := validateOwnershipPreparation(t.Context(), selected, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	changed := *selected
	changed.nat64Transport = nil
	changed.digest = sha256.Sum256(changed.batch.data)
	if err := validateOwnershipPreparation(t.Context(), &changed, time.Now().UTC()); err == nil {
		t.Fatal("NAT64 revocation bytes were accepted without their selected model")
	}
}

func TestAggregateNAT64SourceTransitionsComposeWithNAT46Revocation(t *testing.T) {
	t.Parallel()
	b := nat46ForwardingBaseline(t)
	first := nat64TransportFixture(t).NAT64[0]
	secondPool := netip.MustParsePrefix("10.252.0.0/24")
	b.NAT64 = []policy.NAT64{first, {
		ID: "nat64-private", Prefix: netip.MustParsePrefix("fdca:1a2b:e065::/96"), Scope: "private", SourcePool: &secondPool,
	}}
	layout, err := newNativeNAT46AccessLayout(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	transports := layout.native.selectedNAT64Transports()
	if len(transports) != 2 {
		t.Fatal("combined layout lost an aggregate NAT64 source mode")
	}
	prepared, err := prepareNativeNAT46OwnershipClear(t.Context(), layout.native.nat46Sources.model)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = attachNativeNAT64SourceMode(t.Context(), prepared, transports)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.nat64Transport != nil || len(prepared.nat64Transports) != 2 {
		t.Fatal("combined source revocation collapsed its independent NAT64 components")
	}
	if sourceCount, grantCount := nat46ModeFlushes(t, prepared.batch.data); sourceCount != 3 || grantCount != 8 {
		t.Fatal("combined source revocation omitted NAT46 dependent state", sourceCount, grantCount)
	}
	if nat64ModeGrantFlushes(t, prepared.batch.data) != len(nativeNAT64GrantRefs()) {
		t.Fatal("combined source revocation omitted aggregate NAT64 delegated state")
	}
	if err := validateOwnershipPreparation(t.Context(), prepared, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	evidence, err := ownershipProofFixture(t, b, now, 70*time.Second).InEpoch(t.Context(), 17)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	source, err := renderer.prepareNativeOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := prepareNativeNAT64AggregateSourceRefresh(t.Context(), source, nil, 0, transports)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.nat64Transport != nil || len(refreshed.nat64Transports) != 2 ||
		nat64ModeGrantFlushes(t, refreshed.batch.data) != len(nativeNAT64GrantRefs()) {
		t.Fatal("aggregate NAT64 source refresh duplicated or omitted its shared dependent grant inventory")
	}
	if err := validateOwnershipPreparation(t.Context(), refreshed, now); err != nil {
		t.Fatal(err)
	}
}
