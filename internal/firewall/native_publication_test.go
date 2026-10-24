package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"
)

func TestNativeSourceReceiptPreservesPublishedDeadlinesAndOwnsItsTimeouts(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	baseline := nativeAccessBaseline(t)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	evidence := ownershipProofFixture(t, baseline, now, 60*time.Second)
	evidence, err = evidence.InEpoch(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := nativeSourceReceipt(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.timeouts) == 0 {
		t.Fatal("source receipt lacks a positive control")
	}
	expected := min(prepared.timeouts[0], prepared.epochTimeout)
	deadline := prepared.batch.startedAt.Add(time.Duration(expected) * time.Second)
	halfway := prepared.batch.startedAt.Add(time.Second)
	remaining, err := receipt.remaining(t.Context(), 0, halfway)
	if err != nil || !halfway.Add(remaining).Equal(deadline) {
		t.Fatal("receipt did not keep the original installed lower deadline", remaining, err)
	}
	prepared.timeouts[0] = 90
	remaining, err = receipt.remaining(t.Context(), 0, halfway.Add(time.Second))
	if err != nil || !halfway.Add(time.Second).Add(remaining).Equal(deadline) {
		t.Fatal("caller mutation or later observation renewed the source receipt", remaining, err)
	}
	if _, err := receipt.remaining(t.Context(), 0, deadline); err == nil {
		t.Fatal("expired publication supplied evidence")
	}
	if _, err := receipt.remaining(t.Context(), 0, prepared.batch.startedAt.Add(-time.Second)); err == nil {
		t.Fatal("receipt accepted a regressed elapsed clock")
	}
	if _, err := receipt.remaining(t.Context(), len(receipt.timeouts), halfway); err == nil {
		t.Fatal("receipt accepted an unknown source address")
	}
}

func TestNativeSourceRefreshCannotAdoptAnObservedEpisodeOrRetainGrantsPastAShorterDeadline(t *testing.T) {
	t.Parallel()
	utc := time.Now().UTC()
	b := nativeAccessBaseline(t)
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownershipProofFixture(t, b, utc, 60*time.Second).InEpoch(t.Context(), 7)
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
	if _, err := prepareNativeSourceRefresh(t.Context(), prepared, nil, 7); err == nil {
		t.Fatal("kernel listing adopted a source episode")
	}
	if _, err := prepareNativeSourceRefresh(t.Context(), prepared, receipt, 8); err == nil {
		t.Fatal("observed source epoch mismatch accepted")
	}
	changedProof, err := proof.InEpoch(t.Context(), 8)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := renderer.prepareNativeOwnership(t.Context(), changedProof, utc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeSourceRefresh(t.Context(), changed, receipt, 7); err == nil {
		t.Fatal("new epoch borrowed the previous source publication")
	}
	unchanged, err := prepareNativeSourceRefresh(t.Context(), prepared, receipt, 7)
	if err != nil || unchanged.withdrawNativeIDs {
		t.Fatal("unchanged source publication revoked current grants", err)
	}
	shortened, err := renderer.prepareNativeOwnership(t.Context(), proof, utc.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := prepareNativeSourceRefresh(t.Context(), shortened, receipt, 7)
	if err != nil || !refreshed.withdrawNativeIDs {
		t.Fatal("shorter source deadline retained grant IDs", err)
	}
	if err := validateOwnershipPreparation(t.Context(), refreshed, utc); err != nil {
		t.Fatal(err)
	}
	for _, ref := range nativeIDLeaseRefs() {
		if !bytes.Contains(refreshed.batch.data, []byte(ref.Name)) {
			t.Fatal("source shrink omitted a fixed grant revocation", ref.Name)
		}
	}
	if _, err := nativeSourceReceipt(t.Context(), refreshed); err != nil {
		t.Fatal("verified source shrink could not mint its original-deadline receipt", err)
	}
	// A conservative older lower deadline models time already spent in the
	// previous publication. The next deadline is later, but its configured
	// window is smaller; existing child grants still need atomic revocation.
	aged := *receipt
	aged.startedAt = aged.startedAt.Add(-10 * time.Second)
	window, err := prepareNativeSourceRefresh(t.Context(), shortened, &aged, 7)
	if err != nil || !window.withdrawNativeIDs {
		t.Fatal("smaller source window retained incompatible child grant timeouts", err)
	}
	if err := validateOwnershipPreparation(t.Context(), window, utc); err != nil {
		t.Fatal("bounded window replacement lost its original source proof", err)
	}
	modified := *refreshed
	modified.withdrawNativeIDs = false
	modified.digest = sha256.Sum256(modified.batch.data)
	if err := validateOwnershipPreparation(t.Context(), &modified, utc); err == nil {
		t.Fatal("source revocation flag substituted independently of canonical bytes")
	}
	if prepared.withdrawNativeIDs || shortened.withdrawNativeIDs {
		t.Fatal("refresh modified its caller-owned preparation")
	}
}

func TestNativeSourceReceiptCannotBeRestoredOrMintedFromAnEmptyOrLegacySource(t *testing.T) {
	t.Parallel()
	var receipt nativeSourcePublication
	if _, err := json.Marshal(receipt); err == nil {
		t.Fatal("native source receipt was serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &receipt); err == nil {
		t.Fatal("native source receipt was restored")
	}
	if _, err := receipt.remaining(t.Context(), 0, time.Now()); err == nil {
		t.Fatal("zero receipt supplied source evidence")
	}
	for _, prepared := range []*preparedOwnership{nil, {nativeSources: true}, {nativeSources: true, clear: true}, {}} {
		if _, err := nativeSourceReceipt(t.Context(), prepared); err == nil {
			t.Fatal("unpublished source minted a receipt")
		}
	}
}
