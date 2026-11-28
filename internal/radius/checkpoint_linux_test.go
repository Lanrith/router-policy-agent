package radius

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/kea"
)

func journalRecord(t *testing.T, raw accountingEvent, seq int) []byte {
	t.Helper()
	entry := fixtureEntry(t, raw)
	entry["__CURSOR"] = "fixture-entry-" + strconv.Itoa(seq)
	entry["__MONOTONIC_TIMESTAMP"] = strconv.FormatInt(int64(1000+seq)*1000000+100, 10)
	return encodeEntries(t, entry)
}

func TestCheckpointAcrossBootCaptureLimitRestartAndClockStep(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cp := newCheckpoint("scope-a")
	const count = maximumEvents + 3
	mono := time.Unix(1000+count, 0).UTC()
	now := fixtureTime().Add(count * time.Second)
	var last []byte
	for i := 0; i < count; i++ {
		raw := fixtureEvent("Interim-Update", i)
		if i == 0 {
			raw.Status = "Start"
		}
		if i >= maximumEvents {
			raw.ReceivedAt -= 20
		}
		line := journalRecord(t, raw, i)
		batch := append(slices.Clone(last), line...)
		if err := cp.advance(batch, fixtureScope(), mono, false); err != nil {
			t.Fatalf("continuous receipt %d: %v", i, err)
		}
		last = line
	}
	now = now.Add(-20 * time.Second)
	offset := now.Add(-mono.Sub(time.Unix(0, 0)))
	before := cp.observe(now, offset)
	if len(before.Sessions) != 1 || before.Sessions[0].ValidUntil.After(now.Add(89*time.Second)) {
		t.Fatalf("lost active session or renewed original evidence: %+v", before)
	}
	uid := uint32(os.Getuid())
	if err := cp.save(t.Context(), root, uid); err != nil {
		t.Fatal(err)
	}
	cp, err = readCheckpoint(t.Context(), root, uid, "scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.advance(last, fixtureScope(), mono, false); err != nil {
		t.Fatal(err)
	}
	resumed := cp.observe(now.Add(time.Second), offset)
	if !slices.Equal(resumed.Sessions, before.Sessions) {
		t.Fatal("restart refreshed the evidence or lost the original Start")
	}
	if got := cp.observe(now.Add(Freshness), offset); len(got.Sessions) != 0 {
		t.Fatal("checkpoint restored expired ownership")
	}
	if err := cp.advance(journalRecord(t, fixtureEvent("Alive", count), count), fixtureScope(), mono.Add(time.Second), false); !errors.Is(err, errGap) {
		t.Fatalf("missing anchor accepted: %v", err)
	}
	stop := journalRecord(t, fixtureEvent("Stop", count), count)
	if err := cp.advance(append(slices.Clone(last), stop...), fixtureScope(), mono.Add(time.Second), false); err != nil {
		t.Fatal(err)
	}
	if err := cp.save(t.Context(), root, uid); err != nil {
		t.Fatal(err)
	}
	cp, err = readCheckpoint(t.Context(), root, uid, "scope-a")
	if err != nil {
		t.Fatal(err)
	}
	reuse := fixtureEvent("Start", count+1)
	reuse.SessionSeconds = "0"
	if err := cp.advance(append(slices.Clone(stop), journalRecord(t, reuse, count+1)...), fixtureScope(), mono.Add(2*time.Second), false); err != nil {
		t.Fatal(err)
	}
	if got := cp.observe(now, offset); len(got.Sessions) != 0 {
		t.Fatal("closed session reopened")
	}
	fresh, err := readCheckpoint(t.Context(), root, uid, "new-boot-or-policy")
	if err != nil || len(fresh.States) != 0 || fresh.Cursor != "" {
		t.Fatal("checkpoint crossed source/boot boundary")
	}
}

func TestEnrolledCollectionPreservesUnrelatedOwnershipAndWithholdsSharedEvidence(t *testing.T) {
	for _, kind := range []string{"unrelated", "unknown-delay", "shared-address", "uncertain-shared-address", "missing-enrolled-lease"} {
		t.Run(kind, func(t *testing.T) {
			h := fixtureCapturedHistory(t)
			first := fixtureEvent("Start", 0)
			other := fixtureEvent("Start", 0)
			other.MAC = "02AABBCCDDFF"
			other.SessionIDHex = hex.EncodeToString([]byte("other"))
			other.IPv4 = "192.0.2.82"
			if kind == "unknown-delay" || kind == "uncertain-shared-address" {
				other.DelaySeconds = ""
			}
			if kind == "shared-address" || kind == "uncertain-shared-address" {
				other.IPv4 = first.IPv4
			}
			h.data = fixtureHistory(t, first, other)
			options := fixtureCollectorOptions()
			options.managedMACs = []string{"02:aa:bb:cc:dd:ee"}
			reads := 0
			got, err := collectIPv4(t.Context(), options, collectionSources{now: func() time.Time { return h.observedAt }, history: func(context.Context) (history, error) { return h, nil },
				lease: func(_ context.Context, mac string) (kea.Observation, error) {
					if mac != options.managedMACs[0] {
						t.Fatal("queried unrelated lease")
					}
					reads++
					if kind == "missing-enrolled-lease" {
						return kea.Observation{ObservedAt: h.observedAt}, nil
					}
					return fixtureLeaseObservation(), nil
				}})
			want := kind == "unrelated" || kind == "unknown-delay"
			if err != nil || (len(got.Candidates) == 1) != want || (reads > 0) != (want || kind == "missing-enrolled-lease") {
				t.Fatalf("wrong evidence result %v %+v, %d reads", err, got, reads)
			}
		})
	}
}

func TestUncertainReceiptAndReauthenticationAfterGap(t *testing.T) {
	cp := newCheckpoint("fixture")
	cp.Cutoff = 1001 * 1000000
	raw := fixtureEvent("Start", 0)
	raw.ReceivedAt += 2
	raw.DelaySeconds = "2"
	start := journalRecord(t, raw, 2)
	mono := time.Unix(1003, 0).UTC()
	if err := cp.advance(start, fixtureScope(), mono, false); err != nil {
		t.Fatal(err)
	}
	offset := fixtureTime().Add(-1000 * time.Second)
	if got := cp.observe(fixtureTime().Add(3*time.Second), offset); len(got.Sessions) != 0 {
		t.Fatal("pre-gap Start qualified")
	}
	raw = fixtureEvent("Start", 3)
	raw.SessionSeconds = "0"
	raw.SessionIDHex = "1234"
	again := journalRecord(t, raw, 3)
	if err := cp.advance(append(slices.Clone(start), again...), fixtureScope(), mono.Add(time.Second), false); err != nil {
		t.Fatal(err)
	}
	// A new, qualified association cannot bypass the fresh uncertain owner for
	// the same MAC. The new association becomes eligible after the old one stops.
	raw = fixtureEvent("Stop", 4)
	stop := journalRecord(t, raw, 4)
	if err := cp.advance(append(slices.Clone(again), stop...), fixtureScope(), mono.Add(2*time.Second), false); err != nil {
		t.Fatal(err)
	}
	if got := cp.observe(fixtureTime().Add(5*time.Second), offset); len(got.Sessions) != 1 {
		t.Fatal("fresh post-gap Start failed", got)
	}
}

func TestCheckpointRejectsChangedStateAndForeignFileOwner(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cp := newCheckpoint("fixture")
	uid := uint32(os.Getuid())
	if err := cp.save(t.Context(), root, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpoint(t.Context(), root, uid+1, "fixture"); err == nil {
		t.Fatal("foreign checkpoint owner accepted")
	}
	if err := root.WriteFile(checkpointFile, []byte(`{"Sum":"incorrect","State":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpoint(t.Context(), root, uid, "fixture"); !errors.Is(err, errGap) {
		t.Fatalf("inconsistent state restored: %v", err)
	}
}

func TestBoundedStopHistoryKeepsVerifiedOwnersAndNeverReopensRetiredKeys(t *testing.T) {
	cp := newCheckpoint("fixture")
	mono := time.Unix(1010, 0).UTC()
	data := journalRecord(t, fixtureEvent("Start", 0), 0)
	if err := cp.advance(data, fixtureScope(), mono, false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= exactClosedLimit; i++ {
		cp.retire(digest("closed", strconv.Itoa(i)))
	}
	if len(cp.Closed) != 0 || len(cp.Retired) != retiredBytes {
		t.Fatal("stop history is unbounded")
	}
	for i := 0; i <= exactClosedLimit; i++ {
		if !cp.wasClosed(digest("closed", strconv.Itoa(i))) {
			t.Fatal("lost a Stop during compaction")
		}
	}
	// Model the most conservative possible filter result. Existing associations
	// can advance. A new matching key can only contribute negative evidence.
	for i := range cp.Retired {
		cp.Retired[i] = 0xff
	}
	alive := journalRecord(t, fixtureEvent("Alive", 3), 3)
	if err := cp.advance(append(slices.Clone(data), alive...), fixtureScope(), mono, false); err != nil {
		t.Fatal(err)
	}
	other := fixtureEvent("Start", 4)
	other.SessionSeconds = "0"
	other.SessionIDHex = "5432"
	other.MAC = "02AABBCCDDFF"
	other.IPv4 = "192.0.2.83"
	line := journalRecord(t, other, 4)
	if err := cp.advance(append(slices.Clone(alive), line...), fixtureScope(), mono, false); err != nil {
		t.Fatal(err)
	}
	got := cp.observe(fixtureTime().Add(10*time.Second), fixtureTime().Add(-1000*time.Second))
	if len(got.Sessions) != 1 || got.Sessions[0].MAC != "02:aa:bb:cc:dd:ee" || got.Withheld != 1 {
		t.Fatal("retirement collision affected a verified owner", got)
	}
}
