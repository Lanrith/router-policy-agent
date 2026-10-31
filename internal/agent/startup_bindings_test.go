package agent

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
)

func TestStartupBindingsWaitForActualPostStartObservation(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f, options := newOwnershipFixture(t)
		var published atomic.Pointer[binding.Snapshot]
		options.Bindings = func(ctx context.Context) (binding.Snapshot, error) {
			value := published.Load()
			if value == nil {
				return binding.Snapshot{}, binding.ErrIncomplete
			}
			return *value, ctx.Err()
		}
		engine := f.engine(t, options)
		clone := func(snapshot binding.Snapshot) binding.Snapshot {
			snapshot.Records = slices.Clone(snapshot.Records)
			for index := range snapshot.Records {
				snapshot.Records[index].Addresses = slices.Clone(snapshot.Records[index].Addresses)
			}
			return snapshot
		}
		previous := clone(f.bindings)
		old := engine.startupTime.Add(-time.Millisecond)
		previous.ObservedAt = old
		for index := range previous.Records {
			previous.Records[index].AssociatedAt = old
			for address := range previous.Records[index].Addresses {
				previous.Records[index].Addresses[address].ObservedAt = old
			}
		}
		published.Store(&previous)
		done := make(chan error, 1)
		go func() { done <- engine.InitializeBindings(t.Context()) }()
		synctest.Wait()
		if f.refreshes != 0 || len(f.firewall.active) != 0 || len(f.evidence.Addresses) != 0 {
			t.Fatal("pre-start evidence installed ownership or directory grants")
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if f.refreshes != 0 {
			t.Fatal("a cache reread became a fresh observation")
		}
		observed := f.utc()
		fresh := clone(f.bindings)
		fresh.ObservedAt = observed
		for index := range fresh.Records {
			fresh.Records[index].AssociatedAt = observed
			for address := range fresh.Records[index].Addresses {
				fresh.Records[index].Addresses[address].ObservedAt = observed
			}
		}
		published.Store(&fresh)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if f.refreshes != 1 || len(f.evidence.Addresses) != 1 || len(f.firewall.active) != 0 {
			t.Fatal("qualified ownership was not installed independently of directory authorization")
		}
	})
}

func TestStartupBindingWaitIsBoundedAndDoesNotRenewEvidence(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f, options := newOwnershipFixture(t)
		engine := f.engine(t, options)
		f.sourceError = binding.ErrIncomplete
		before := f.bindings.ObservedAt
		started := time.Now()
		err := engine.InitializeBindings(t.Context())
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != 90*time.Second {
			t.Fatal("incomplete startup did not respect the fixed deadline", err)
		}
		if f.refreshes != 0 || !f.bindings.ObservedAt.Equal(before) || len(f.firewall.active) != 0 {
			t.Fatal("waiting changed evidence or installed permission")
		}
	})
}

func TestStartupBindingsRejectUnsafeInputsWithoutWaiting(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*ownershipFixture)
	}{
		{name: "unsafe source", change: func(f *ownershipFixture) { f.sourceError = errFixture }},
		{name: "future envelope", change: func(f *ownershipFixture) { f.bindings.ObservedAt = f.utc().Add(time.Second) }},
		{name: "expired envelope", change: func(f *ownershipFixture) { f.bindings.ObservedAt = f.utc().Add(-91 * time.Second) }},
		{name: "duplicate owner", change: func(f *ownershipFixture) { f.bindings.Records = append(f.bindings.Records, f.bindings.Records[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				f, options := newOwnershipFixture(t)
				engine := f.engine(t, options)
				tc.change(f)
				started := time.Now()
				if err := engine.InitializeBindings(t.Context()); err == nil || errors.Is(err, ErrBindingsPending) {
					t.Fatal("unsafe input became readiness or a harmless pending interval")
				}
				if time.Since(started) != 0 || f.refreshes != 0 {
					t.Fatal("unsafe evidence was retried or installed")
				}
			})
		})
	}
}

func TestStartupEnvelopeCannotRefreshOldAssociationOrAddress(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"association", "address"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				f, options := newOwnershipFixture(t)
				engine := f.engine(t, options)
				old := engine.startupTime.Add(-time.Millisecond)
				if name == "association" {
					f.bindings.Records[0].AssociatedAt = old
				} else {
					f.bindings.Records[0].Addresses[0].ObservedAt = old
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if err := engine.InitializeBindings(ctx); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("fresh envelope admitted stale underlying evidence", err)
				}
				if f.refreshes != 0 || len(f.firewall.active) != 0 {
					t.Fatal("old association or address acquired permission")
				}
			})
		})
	}
}

func TestIncompleteBindingsSealAndDoNotReviveDirectoryGrants(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	engine := f.engine(t, options)
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	if len(f.firewall.active) != 1 {
		t.Fatal("valid initial fixture grant missing")
	}
	f.sourceError = binding.ErrIncomplete
	if err := engine.RefreshBindings(t.Context()); !errors.Is(err, ErrBindingsPending) {
		t.Fatal("successfully sealed incomplete evidence was not classified", err)
	}
	if len(f.firewall.active) != 0 || len(f.evidence.Addresses) != 0 {
		t.Fatal("incomplete publication retained an active permission")
	}
	f.sourceError = nil
	if err := engine.RefreshBindings(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.evidence.Addresses) != 1 || len(f.firewall.active) != 0 {
		t.Fatal("binding recovery restored an earlier directory grant")
	}
}

func TestIncompleteBindingsCannotMaskCleanupFailure(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	engine := f.engine(t, options)
	f.sourceError = binding.ErrIncomplete
	engine.options.Firewall.ClearOwnership = func(context.Context) error { return errFixture }
	err := engine.RefreshBindings(t.Context())
	if !errors.Is(err, errFixture) || errors.Is(err, ErrBindingsPending) {
		t.Fatal("failed sealing became a harmless producer interval", err)
	}
}

func TestStartupWaitRetainsDenyHistoryAcrossRestart(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f, options := newOwnershipFixture(t)
		engine := f.engine(t, options)
		if _, err := engine.Process(t.Context(), f.directory); err != nil {
			t.Fatal(err)
		}
		if err := engine.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		restarted, err := New(f.baseline, options)
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.sourceError = binding.ErrIncomplete
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := restarted.InitializeBindings(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("unavailable post-restart evidence did not remain closed", err)
		}
		if len(f.firewall.active) != 0 || len(f.firewall.cohort) == 0 || len(f.firewall.ipv6) == 0 {
			t.Fatal("startup waiting lost denied MAC/address history or restored a grant")
		}
	})
}
