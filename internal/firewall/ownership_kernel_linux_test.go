//go:build integration && kernel && linux

package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

func applyOwnershipFixture(ctx context.Context, t *testing.T, baseline policy.Baseline) {
	t.Helper()
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proof := ownershipProofFixture(t, baseline, now, 90*time.Second)
	prepared, err := renderer.prepareOwnership(ctx, proof, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnershipPreparation(ctx, prepared, now); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, prepared.batch.data)
}

func TestKernelNamedOwnershipRefreshAndExpiry(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	baseline := namedOwnershipBaseline(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.interfaces {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
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
	applyOwnershipFixture(ctx, t, baseline)
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		t.Fatal("real ownership schema/mirrors rejected", err)
	}
	sealed, err := prepareGuardSeal(ctx, state.EmptyClassification())
	if err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, sealed.batch.data)
	data, err := p.execute(ctx, inspectOwned, nil)
	if err != nil {
		t.Fatal(err)
	}
	listing, err := layout.inspectTable(ctx, "inet", data)
	if err != nil || len(listing.sets[ownership4Set].Elements) != 1 || len(listing.sets[ownership6Set].Elements) != 1 {
		t.Fatal("directory seal revoked independently current physical evidence", err)
	}
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proof := ownershipProofFixture(t, baseline, now, 8*time.Second)
	prepared, err := renderer.prepareOwnership(ctx, proof, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = p.run(ctx, commandInput{op: applyOwnership, ownership: prepared})
	p.release()
	if err != nil {
		t.Fatal(err)
	}
	waitKernelFixture(ctx, t, 4*time.Second)
	if _, err := p.inspectGuards(ctx, layout); err != nil {
		t.Fatal(err)
	}
	data, err = p.execute(ctx, inspectOwned, nil)
	if err != nil {
		t.Fatal(err)
	}
	listing, err = layout.inspectTable(ctx, "inet", data)
	if err != nil || len(listing.sets[ownership4Set].Elements) != 0 || len(listing.sets[ownership6Set].Elements) != 0 {
		t.Fatal("expired physical evidence remained positive", err)
	}
	revocation, err := prepareOwnershipClear(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = p.run(ctx, commandInput{op: applyOwnership, ownership: revocation})
	p.release()
	if err != nil {
		t.Fatal(err)
	}
}

func TestKernelNamedOwnershipUsesWriterAndFloorFences(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	backend, root := setupBackendPacketFixture(ctx, t, true)
	refresh := func() error {
		proof, err := ownershipProofFixture(t, backend.options.profile.baseline,
			time.Now().UTC(), 90*time.Second).InEpoch(ctx, 7)
		if err != nil {
			return err
		}
		return backend.refreshOwnership(ctx, proof)
	}
	assertEmpty := func() {
		t.Helper()
		data, err := backend.options.executor.execute(ctx, inspectOwned, nil)
		if err != nil {
			t.Fatal(err)
		}
		listing, err := backend.options.profile.layout.inspectTable(ctx, "inet", data)
		if err != nil || len(listing.sets[ownership4Set].Elements) != 0 || len(listing.sets[ownership6Set].Elements) != 0 {
			t.Fatal("failed floor or generation check retained positive ownership", err)
		}
	}
	if err := refresh(); err != nil {
		t.Fatal(err)
	}
	if err := backend.seal(ctx, state.EmptyClassification()); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.options.profile.inspect(ctx, backend.options.executor); err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, "add table inet unexpected_ownership_writer")
	if err := refresh(); err == nil {
		t.Fatal("ownership refresh bypassed changed external floor")
	}
	assertEmpty()
	// The helper must not repair or erase a different writer's objects.
	packetNft(ctx, t, "delete table inet unexpected_ownership_writer")
	if err := refresh(); err != nil {
		t.Fatal(err)
	}
	closed := backend.options.expected
	closed.Ready = false
	writeGenerationFixture(t, root, closed)
	if err := refresh(); err == nil {
		t.Fatal("closed writer generation admitted physical evidence")
	}
	assertEmpty()
	writeGenerationFixture(t, root, backend.options.expected)
	if err := refresh(); err != nil {
		t.Fatal(err)
	}
	if err := backend.clearOwnership(ctx); err != nil {
		t.Fatal(err)
	}
	assertEmpty()
	refreshConfiguration := func() error {
		return backend.refreshConfiguration(ctx, configurationProofFixture(t, backend.options.profile.baseline))
	}
	assertConfigurationEmpty := func() {
		t.Helper()
		data, err := backend.options.executor.execute(ctx, inspectOwned, nil)
		if err != nil {
			t.Fatal(err)
		}
		listing, err := backend.options.profile.layout.inspectTable(ctx, "inet", data)
		if err != nil || len(listing.sets[configurationEpochSet].Elements) != 0 || len(listing.sets[configurationEpochMap].Elements) != 0 {
			t.Fatal("failed floor or generation check retained a configuration epoch", err)
		}
	}
	if err := refreshConfiguration(); err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, "add table inet unexpected_configuration_writer")
	if err := refreshConfiguration(); err == nil {
		t.Fatal("static configuration bypassed changed external floor")
	}
	assertConfigurationEmpty()
	packetNft(ctx, t, "delete table inet unexpected_configuration_writer")
	if err := refreshConfiguration(); err != nil {
		t.Fatal(err)
	}
	writeGenerationFixture(t, root, closed)
	if err := refreshConfiguration(); err == nil {
		t.Fatal("closed writer generation admitted configuration")
	}
	assertConfigurationEmpty()
	writeGenerationFixture(t, root, backend.options.expected)
	if err := refreshConfiguration(); err != nil {
		t.Fatal(err)
	}
	if err := backend.clearConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	assertConfigurationEmpty()
}
