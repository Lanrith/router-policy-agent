package firewall

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

func reobservedSource(t *testing.T, observed, compiled time.Time, generation, association string, lifetime time.Duration) policy.Ownership {
	t.Helper()
	compiler, err := policy.New(nativeAccessBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: generation, ObservedAt: observed, Complete: true, Records: []binding.Record{{
		MAC: "02:00:00:00:00:13", NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: observed, AssociationID: association,
		Addresses: []binding.Address{{IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-lease", ObservedAt: observed, ValidUntil: observed.Add(lifetime)}},
	}}}
	proof, err := compiler.CompileOwnership(t.Context(), snapshot, compiled, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.InEpoch(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestNativeSourceReobservationKeepsOriginalPublishedDeadline(t *testing.T) {
	t.Parallel()
	utc := time.Now().UTC()
	proof := reobservedSource(t, utc, utc, "same-input", "same-association", 60*time.Second)
	renderer, err := newRenderer(nativeAccessBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeOwnership(t.Context(), proof, utc)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := nativeSourceReceipt(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	next := reobservedSource(t, utc, utc.Add(2*time.Second), "same-input", "same-association", 60*time.Second)
	// Republishing this input shortens the relative parent window and must
	// withdraw ID grants. Reusing its original publication avoids that mutation.
	aged, err := renderer.prepareNativeOwnership(t.Context(), next, utc.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	aged, err = prepareNativeSourceRefresh(t.Context(), aged, receipt, 7)
	if err != nil || !aged.withdrawNativeIDs {
		t.Fatal("shrinking publication control did not withdraw grants", err)
	}
	start, timeout := receipt.startedAt, receipt.timeouts[0]
	reuse, err := reuseNativeSource(t.Context(), receipt, next, 7, utc.Add(2*time.Second), time.Now())
	if err != nil || !reuse {
		t.Fatal("unchanged evidence discarded a current publication", err)
	}
	if receipt.startedAt != start || receipt.timeouts[0] != timeout {
		t.Fatal("re-observation renewed the installed source window")
	}
	for _, tc := range []struct {
		name   string
		proof  policy.Ownership
		epoch  uint32
		now    time.Time
		expire bool
	}{
		{name: "new producer generation", proof: reobservedSource(t, utc, utc, "new-input", "same-association", 60*time.Second), epoch: 7, now: utc},
		{name: "shorter source deadline", proof: reobservedSource(t, utc, utc, "same-input", "same-association", 59*time.Second), epoch: 7, now: utc},
		{name: "longer source deadline", proof: reobservedSource(t, utc, utc, "same-input", "same-association", 61*time.Second), epoch: 7, now: utc},
		{name: "different association", proof: reobservedSource(t, utc, utc, "same-input", "other-association", 60*time.Second), epoch: 7, now: utc},
		{name: "missing kernel epoch", proof: proof, epoch: 0, now: utc},
		{name: "different kernel epoch", proof: proof, epoch: 8, now: utc},
		{name: "source evidence expired", proof: proof, epoch: 7, now: utc.Add(100 * time.Second)},
		{name: "installed publication expired", proof: proof, epoch: 7, now: utc, expire: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := *receipt
			if tc.expire {
				prior.startedAt = time.Now().Add(-time.Hour)
			}
			reused, err := reuseNativeSource(t.Context(), &prior, tc.proof, tc.epoch, tc.now, time.Now())
			if err != nil || reused {
				t.Fatal("changed or expired evidence skipped normal fencing", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reuseNativeSource(ctx, receipt, proof, 7, utc, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled re-observation ignored", err)
	}
	if _, err := reuseNativeSource(t.Context(), receipt, next, 7, utc, time.Now()); err == nil {
		t.Fatal("future compiled evidence reused")
	}
}
