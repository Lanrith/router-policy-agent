//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"github.com/lanrith/router-policy-agent/internal/state"
	"os"
	"strings"
	"testing"
	"time"
)

type nat46PublicationFixture struct {
	backend              *guardedBackend
	root                 *os.Root
	inspect              func() (*guardTableObservation, *guardTableObservation)
	assertState          func(bool, bool, bool)
	refreshSource        func(time.Duration)
	refreshConfiguration func()
	apply                func() state.Classification
}

func setupNAT46PublicationFixture(ctx context.Context, t *testing.T) *nat46PublicationFixture {
	t.Helper()
	layout, baseline := nat46PublicationLayoutFixture(t)
	raw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	profileData, err := json.Marshal(profileEnvelope{SchemaVersion: 1, Baseline: raw, ReviewedRuleset: json.RawMessage(reviewedArtifactFixture)})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := decodePinnedProfile(ctx, profileData, routerProfileDigest(profileData))
	if err != nil {
		t.Fatal(err)
	}
	// The default loader remains closed to the new packet path. This explicit
	// test selection owns only the additional publication inventory.
	profile.layout = layout
	for _, name := range layout.interfaces {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer done()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program)+reviewedKernelFixture)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer done()
		packetNft(cleanup, t, "delete table inet reviewed_floor; delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	p, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.close(); err != nil {
			t.Error(err)
		}
	})
	gate, root, _ := generationGateFixture(t)
	expected := writerGenerationFixture()
	expected.FloorHash = profile.ruleset.digest
	writeGenerationFixture(t, root, expected)
	backend, err := newGuardedBackend(backendOptions{profile: profile, executor: p, generation: gate, expected: expected, clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	inspect := func() (*guardTableObservation, *guardTableObservation) {
		t.Helper()
		if _, err := profile.inspect(ctx, p); err != nil {
			t.Fatal("whole publication profile failed independent inspection", err)
		}
		observations := []*guardTableObservation{}
		for _, item := range []struct {
			family string
			op     operation
		}{{"inet", inspectOwned}, {"netdev", inspectGuardEgress}} {
			data, err := p.execute(ctx, item.op, nil)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := layout.inspectTable(ctx, item.family, data)
			if err != nil {
				t.Fatal(err)
			}
			observations = append(observations, observed)
		}
		return observations[0], observations[1]
	}
	assertState := func(source, configuration, grants bool) {
		t.Helper()
		inet, netdev := inspect()
		for _, name := range []string{ownership4Set, ownership6Set, nativeNAT46StaticSourceChannel, nativeNAT46StaticSourceLive} {
			if (len(inet.sets[name].Elements) != 0) != source {
				t.Fatal("source publication or revocation differs", name, source)
			}
		}
		if (len(netdev.sets[nativeNAT46StaticSourceLive].Elements) != 0) != source {
			t.Fatal("source epoch physical mirror differs")
		}
		for _, name := range []string{configurationEpochSet, configurationEpochMap, nativeNAT46StaticChannel} {
			if (len(inet.sets[name].Elements) != 0) != configuration {
				t.Fatal("configuration publication or revocation differs", name, configuration)
			}
		}
		for _, ref := range nativeNAT46TargetGrantRefs() {
			observed := inet
			if ref.Family == "netdev" {
				observed = netdev
			}
			if (len(observed.sets[ref.Name].Elements) != 0) != grants {
				t.Fatal("mixed target grant publication or revocation differs", ref, grants)
			}
		}
	}
	refreshSource := func(lifetime time.Duration) {
		t.Helper()
		proof, err := ownershipProofFixture(t, baseline, time.Now().UTC(), lifetime).InEpoch(ctx, 7)
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.refreshOwnership(ctx, proof); err != nil {
			t.Fatal("typed parent and source-GID publication failed", err)
		}
	}
	refreshConfiguration := func() {
		t.Helper()
		if err := backend.refreshConfiguration(ctx, configurationProofFixture(t, baseline)); err != nil {
			t.Fatal(err)
		}
	}
	apply := func() state.Classification {
		t.Helper()
		authorization, history := backendAuthorizationFixture(t, profile, 0)
		if err := backend.apply(ctx, authorization, history); err != nil {
			t.Fatal("original authorization did not publish typed native and mixed grants", err)
		}
		return history
	}

	return &nat46PublicationFixture{backend: backend, root: root, inspect: inspect, assertState: assertState, refreshSource: refreshSource, refreshConfiguration: refreshConfiguration, apply: apply}
}

// These fixtures qualify the typed backend and writer transactions on the
// publication-only skeleton. They do not qualify translated forwarding, TAYGA
// hooks, a live binding producer, a signed image or runtime activation.
func TestKernelNamedNAT46PublicationFences(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	f := setupNAT46PublicationFixture(ctx, t)
	f.assertState(false, false, false)
	f.refreshConfiguration()
	f.refreshSource(90 * time.Second)
	f.assertState(true, true, false)
	f.apply()
	f.assertState(true, true, true)
	packetNft(ctx, t, "add table inet unexpected_nat46_writer")
	proof, err := ownershipProofFixture(t, f.backend.options.profile.baseline, time.Now().UTC(), 90*time.Second).InEpoch(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.backend.refreshOwnership(ctx, proof); err == nil {
		t.Fatal("unreviewed external writer allowed source publication")
	}
	packetNft(ctx, t, "delete table inet unexpected_nat46_writer")
	f.assertState(false, true, false)
	f.refreshSource(90 * time.Second)
	expected := f.backend.options.expected
	closed := expected
	closed.Ready = false
	writeGenerationFixture(t, f.root, closed)
	if err := f.backend.refreshConfiguration(ctx, configurationProofFixture(t, f.backend.options.profile.baseline)); err == nil {
		t.Fatal("closed generation admitted configuration")
	}
	f.assertState(true, false, false)
	if err := f.backend.refreshOwnership(ctx, proof); err == nil {
		t.Fatal("closed generation admitted source facts")
	}
	f.assertState(false, false, false)
	writeGenerationFixture(t, f.root, expected)
	f.refreshSource(90 * time.Second)
	f.refreshConfiguration()
	f.assertState(true, true, false)
	// A new helper may not adopt a live observed epoch as its original receipt.
	restarted, err := newGuardedBackend(f.backend.options)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.refreshOwnership(ctx, proof); err == nil {
		t.Fatal("restart adopted source authority from a listing")
	}
	f.assertState(false, true, false)
	f.refreshSource(90 * time.Second)
	f.assertState(true, true, false)
}

func TestKernelNamedNAT46GrantPublicationFences(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	f := setupNAT46PublicationFixture(ctx, t)
	f.refreshConfiguration()
	f.refreshSource(90 * time.Second)
	history := f.apply()
	f.assertState(true, true, true)
	// Malformed leased content cannot disable revocation. Deny-only addresses
	// retained by the physical table survive and regain both representations.
	packetNft(ctx, t, "flush set inet "+ownedTable+" native_n46_to4_tcp; add element inet "+ownedTable+" native_n46_to4_tcp {0:1c00 . 10.250.0.20 . 10.240.0.99 . 6053 timeout 20s}; add element netdev "+ownedTable+" "+classified4Set+" {10.240.3.99}")
	if err := f.backend.seal(ctx, history); err != nil {
		t.Fatal("directory seal rejected native mode or removed independent source facts", err)
	}
	f.assertState(true, true, false)
	inet, netdev := f.inspect()
	for _, observed := range []*guardTableObservation{inet, netdev} {
		if !nat46PublicationContainsAddress(observed, classified4Set, "10.240.3.99") || !nat46PublicationContainsAddress(observed, classified6Set, "fdca:1a2b:e046::af0:363") {
			t.Fatal("sealing lost physical deny history or its translated counterpart")
		}
	}
	f.apply()
	// Shrinking one individual address under the same association and epoch
	// withdraws derived grants in the parent transaction before any new child.
	f.refreshSource(25 * time.Second)
	f.assertState(true, true, false)
	f.apply()
	f.assertState(true, true, true)
	if err := f.backend.clearConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	f.assertState(true, false, true)
	f.refreshConfiguration()
	if err := f.backend.clearOwnership(ctx); err != nil {
		t.Fatal(err)
	}
	f.assertState(false, true, false)
	f.refreshSource(90 * time.Second)
	// Even refreshing the same episode replaces its original local receipt.
	// A queued grant cannot borrow that newer parent to renew its own proof.
	authorization, queuedHistory := backendAuthorizationFixture(t, f.backend.options.profile, 0)
	queued, original, err := f.backend.prepareApplication(ctx, authorization, queuedHistory)
	if err != nil {
		t.Fatal(err)
	}
	f.refreshSource(90 * time.Second)
	if _, err := f.backend.commitApplication(ctx, queued, original); err == nil || !strings.Contains(err.Error(), "source publication changed during grant preparation") {
		t.Fatal("queued grant adopted another source publication", err)
	}
	f.assertState(true, true, false)
	f.apply()
	f.assertState(true, true, true)
}

func nat46PublicationContainsAddress(observed *guardTableObservation, name, address string) bool {
	for _, raw := range observed.sets[name].Elements {
		var value string
		if json.Unmarshal(raw, &value) == nil && value == address {
			return true
		}
	}
	return false
}
