package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestOwnershipDoesNotNeedOrSupplyDirectoryPermission(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	input.Directory.Complete = false
	input.Directory.Devices[0].Active = false
	compiler := testCompiler(t, b)
	evidence, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := evidence.Snapshot(t.Context())
	if err != nil || len(snapshot.Addresses) != 1 || snapshot.BaselineHash != compiler.BaselineHash() {
		t.Fatalf("qualified ownership lost during directory outage: %+v, %v", snapshot, err)
	}
	if _, err := compiler.Compile(input); err == nil {
		t.Fatal("ownership supplied a directory authorization")
	}
	input.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::11")
	snapshot.Addresses[0].Interface = "forged"
	current, err := evidence.Snapshot(t.Context())
	if err != nil || current.Addresses[0].Interface != "lan13" || current.Addresses[0].Address.String() != "fdca:1a2b:3::10" {
		t.Fatal("caller mutated owned evidence", err)
	}
}

func TestOwnershipEpochDoesNotRenewOrMutatePhysicalEvidence(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	compiler := testCompiler(t, b)
	evidence, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	bound, err := evidence.InEpoch(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	original, err := evidence.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current, err := bound.Snapshot(t.Context())
	if err != nil || original.Epoch != 0 || current.Epoch != 7 || current.Fingerprint != original.Fingerprint ||
		!current.CompiledAt.Equal(original.CompiledAt) || !current.Addresses[0].ExpiresAt.Equal(original.Addresses[0].ExpiresAt) {
		t.Fatal("epoch changed or renewed physical evidence", err)
	}
	if _, err := json.Marshal(bound); err == nil {
		t.Fatal("epoch made positive evidence persistable")
	}
	for _, epoch := range []uint32{0, ^uint32(0)} {
		if _, err := evidence.InEpoch(t.Context(), epoch); err == nil {
			t.Fatal("reserved connection generation accepted", epoch)
		}
	}
	if _, err := (Ownership{}).InEpoch(t.Context(), 7); err == nil {
		t.Fatal("generation created physical evidence from nothing")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := evidence.InEpoch(ctx, 7); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled generation binding continued", err)
	}
}

func TestOwnershipFingerprintTracksEpisodesInsteadOfRoutineRefreshes(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	compiler := testCompiler(t, b)
	makeSnapshot := func() OwnershipSnapshot {
		t.Helper()
		evidence, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, CaptureAge())
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := evidence.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	first := makeSnapshot()
	input.Now = input.Now.Add(time.Second)
	input.Bindings.ObservedAt = input.Now
	input.Bindings.Generation = "new-producer-observation"
	input.Bindings.Records[0].AssociatedAt = input.Now
	input.Bindings.Records[0].Addresses[0].ObservedAt = input.Now
	refreshed := makeSnapshot()
	if first.Fingerprint != refreshed.Fingerprint || !refreshed.Addresses[0].ExpiresAt.After(first.Addresses[0].ExpiresAt) {
		t.Fatal("routine observation changed identity or did not retain its actual lifetime")
	}
	input.Bindings.Records[0].AssociationID = "new-association-episode"
	if next := makeSnapshot(); next.Fingerprint == refreshed.Fingerprint {
		t.Fatal("changed physical association retained a previous identity fence")
	}
	input.Bindings.Records[0].AssociationID = "association-v1"
	input.Bindings.Records[0].Addresses[0].OwnershipID = "new-address-episode"
	if next := makeSnapshot(); next.Fingerprint == refreshed.Fingerprint {
		t.Fatal("changed address owner retained a previous identity fence")
	}
}

func TestOwnershipRejectsStaleAndUnqualifiedEvidence(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		mutate func(*Input)
		err    bool
	}{
		{"incomplete producer", func(i *Input) { i.Bindings.Complete = false }, true},
		{"stale snapshot", func(i *Input) { i.Bindings.ObservedAt = i.Now.Add(-90 * time.Second) }, true},
		{"future snapshot", func(i *Input) { i.Bindings.ObservedAt = i.Now.Add(time.Second) }, true},
		{"expired ownership", func(i *Input) { i.Bindings.Records[0].Addresses[0].ValidUntil = i.Now }, true},
		{"neighbor observation alone", func(i *Input) { i.Bindings.Records[0].Addresses[0].Source = "ndp" }, true},
		{"noncanonical identity", func(i *Input) { i.Bindings.Records[0].MAC = "020000000001" }, true},
		{"wrong attachment", func(i *Input) { i.Bindings.Records[0].Interface = "lan12" }, false},
		{"wrong vlan", func(i *Input) { i.Bindings.Records[0].VLAN = 12 }, false},
		{"wrong native scope", func(i *Input) { i.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:2::10") }, false},
		{"association without addresses", func(i *Input) { i.Bindings.Records[0].Addresses = nil }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, input := namedFixture(t)
			tt.mutate(&input)
			evidence, err := testCompiler(t, b).CompileOwnership(t.Context(), input.Bindings, input.Now, CaptureAge())
			if (err != nil) != tt.err {
				t.Fatal("unexpected ownership validation result", err)
			}
			if err == nil {
				snapshot, err := evidence.Snapshot(t.Context())
				if err != nil || len(snapshot.Addresses) != 0 {
					t.Fatal("unqualified source gained a positive tuple", err)
				}
			}
		})
	}
}

func TestOwnershipUsesOriginalAgeAndRejectsSerialization(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	input.Bindings.Records[0].Addresses[0].ValidUntil = input.Now.Add(10 * time.Second)
	compiler := testCompiler(t, b)
	evidence, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	if remaining, err := evidence.Remaining(0, input.Now); err != nil || remaining <= 0 || remaining > 10*time.Second {
		t.Fatal("ownership lifetime escaped its original evidence", err)
	}
	if _, err := evidence.Remaining(0, input.Now.Add(-time.Nanosecond)); err == nil {
		t.Fatal("UTC rollback renewed evidence")
	}
	old, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, AgeAnchor{tick: time.Now().Add(-11 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Remaining(0, input.Now); err == nil {
		t.Fatal("queue delay renewed expired evidence")
	}
	if _, err := json.Marshal(evidence); err == nil {
		t.Fatal("positive ownership evidence was serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &evidence); err == nil {
		t.Fatal("ownership evidence was deserialized")
	}
	if _, err := evidence.Snapshot(t.Context()); err == nil {
		t.Fatal("failed deserialization retained an earlier proof")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := compiler.CompileOwnership(ctx, input.Bindings, input.Now, CaptureAge()); !errors.Is(err, context.Canceled) {
		t.Fatal("ownership compilation ignored cancellation", err)
	}
	if _, err := (Ownership{}).Remaining(0, input.Now); err == nil {
		t.Fatal("zero ownership value supplied evidence")
	}
}
