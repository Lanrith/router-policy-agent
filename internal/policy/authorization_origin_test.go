package policy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAuthorizationOriginMatchesExactPhysicalEpisode(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.NAT64 = nil
	baseline.NAT46 = nil
	baseline.NAT46Pools = nil
	baseline.NetworkModel = &NetworkModel{SchemaVersion: 1, UplinkInterface: "wan", ManagedNetworks: []Role{Untrusted}, Rules: []NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "any", From: []NetworkSelector{{}}, To: []NetworkSelector{{}}}}}
	compiler := testCompiler(t, baseline)
	input := testInput(t)
	authorization, err := compiler.CompileAuthorization(t.Context(), input, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("original grant missing", err)
	}
	owned, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	physical, err := owned.Snapshot(t.Context())
	if err != nil || len(physical.Addresses) != 1 {
		t.Fatal("original ownership missing", err)
	}
	reference, err := authorization.BindingReference(t.Context(), 0)
	if err != nil || reference != physical.Addresses[0].BindingRef {
		t.Fatal("authorization was not pinned to its actual ownership episode", err)
	}
	for _, name := range []string{"association", "address episode", "NAS", "refresh timestamp"} {
		t.Run(name, func(t *testing.T) {
			current := testInput(t)
			switch name {
			case "association":
				current.Bindings.Records[0].AssociationID = "replacement-association"
			case "address episode":
				current.Bindings.Records[0].Addresses[0].OwnershipID = "replacement-owner"
			case "NAS":
				current.Bindings.Records[0].NAS = "replacement-nas"
			case "refresh timestamp":
				current.Now = current.Now.Add(time.Second)
				current.Bindings.ObservedAt = current.Now
				current.Bindings.Records[0].AssociatedAt = current.Now
				current.Bindings.Records[0].Addresses[0].ObservedAt = current.Now
			}
			// The pure identity hash is checked independently of NAS admission. A
			// changed producer name cannot silently remain the same physical episode.
			expected, err := ownershipBindingReference(current.Bindings.Records[0], current.Bindings.Records[0].Addresses[0])
			if err != nil {
				t.Fatal(err)
			}
			equal := expected == reference
			if equal != (name == "refresh timestamp") {
				t.Fatal("ownership origin confused a refresh and replacement")
			}
		})
	}
	input.Bindings.Records[0].AssociationID = "caller-mutated"
	candidate.Grants[0].MAC = "02:00:00:00:00:04"
	after, err := authorization.BindingReference(t.Context(), 0)
	if err != nil || after != reference {
		t.Fatal("caller changed original grant provenance", err)
	}
}
func TestAuthorizationObservationRetainsSavedDigests(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	authorization, err := testCompiler(t, testBaseline()).CompileAuthorization(t.Context(), input, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	observation, err := authorization.Observation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := DirectoryFingerprint(input.Directory)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := LedgerFingerprint(candidate.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.DirectoryObservedAt.Equal(input.Directory.ObservedAt) || observation.DirectorySHA256 != directory || observation.LedgerSHA256 != ledger {
		t.Fatal("original directory/ledger provenance changed")
	}
	input.Directory.Devices[0].Active = false
	changed, err := DirectoryFingerprint(input.Directory)
	if err != nil || changed == observation.DirectorySHA256 {
		t.Fatal("directory revocation had the same observation digest", err)
	}
	observation.DirectorySHA256 = "caller-mutated"
	again, err := authorization.Observation(t.Context())
	if err != nil || again.DirectorySHA256 != directory {
		t.Fatal("diagnostic view edited original authorization", err)
	}
	if _, err := json.Marshal(authorization); err == nil {
		t.Fatal("provenance made authorization restorable")
	}
	var zero Authorization
	if _, err := zero.BindingReference(t.Context(), 0); err == nil {
		t.Fatal("zero evidence supplied a physical reference")
	}
	if _, err := zero.Observation(t.Context()); err == nil {
		t.Fatal("zero evidence supplied a directory observation")
	}
	for _, index := range []int{-1, len(candidate.Grants)} {
		if _, err := authorization.BindingReference(t.Context(), index); err == nil {
			t.Fatal("out-of-range reference returned")
		}
	}
	cancelled, done := context.WithCancel(t.Context())
	done()
	if _, err := authorization.BindingReference(cancelled, 0); !errors.Is(err, context.Canceled) {
		t.Fatal("binding provenance ignored cancellation", err)
	}
	if _, err := authorization.Observation(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("observation provenance ignored cancellation", err)
	}
}
