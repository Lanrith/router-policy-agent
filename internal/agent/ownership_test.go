package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

type ownershipFixture struct {
	*fixture
	evidence          policy.OwnershipSnapshot
	configuration     policy.OwnerConfigurationSnapshot
	refreshes, clears int
	sourceError       error
	epoch             uint32
}

func newOwnershipFixture(t *testing.T) (*ownershipFixture, Options) {
	t.Helper()
	f := &ownershipFixture{fixture: newFixture(t)}
	f.baseline.NetworkModel = &policy.NetworkModel{SchemaVersion: 1, UplinkInterface: "wan",
		ManagedNetworks: []policy.Role{policy.Untrusted}, Rules: []policy.NetworkRule{
			{Action: "allow", Authorization: "directory", Protocol: "any",
				From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}},
		}}
	options := f.options(Enforce)
	options.State.AdvanceOwnershipEpoch = func(ctx context.Context) (uint32, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		f.epoch++
		return f.epoch, nil
	}
	options.Bindings = func(ctx context.Context) (binding.Snapshot, error) {
		if f.sourceError != nil {
			return binding.Snapshot{}, f.sourceError
		}
		return f.bindings, ctx.Err()
	}
	options.Firewall.RefreshOwnership = func(ctx context.Context, evidence policy.Ownership) error {
		value, err := evidence.Snapshot(ctx)
		if err == nil {
			f.evidence = value
			f.refreshes++
		}
		return err
	}
	options.Firewall.ClearOwnership = func(ctx context.Context) error {
		f.evidence = policy.OwnershipSnapshot{}
		f.clears++
		return ctx.Err()
	}
	options.Firewall.RefreshConfiguration = func(ctx context.Context, evidence policy.OwnerConfiguration) error {
		snapshot, err := evidence.Snapshot(ctx)
		if err == nil {
			f.configuration = snapshot
		}
		return err
	}
	options.Firewall.ClearConfiguration = func(ctx context.Context) error {
		f.configuration = policy.OwnerConfigurationSnapshot{}
		return ctx.Err()
	}
	return f, options
}

func TestNamedOwnershipRefreshDoesNotDependOnDirectoryOrRenewGrants(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	engine := f.engine(t, options)
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	if len(f.firewall.active) != 1 || len(f.evidence.Addresses) != 1 {
		t.Fatal("valid initial ownership/directory result lost")
	}
	expires := f.firewall.active[0].ExpiresAt()
	configurationEpoch := f.configuration.Epoch
	if configurationEpoch == 0 || configurationEpoch == f.evidence.Epoch {
		t.Fatal("configuration and binding episodes share a connection identity")
	}
	refreshes := f.refreshes
	f.directory.Complete = false
	if _, err := engine.Process(t.Context(), f.directory); err == nil {
		t.Fatal("incomplete directory observation was authorized")
	}
	if len(f.firewall.active) != 0 || len(f.evidence.Addresses) != 1 || f.refreshes != refreshes {
		t.Fatal("directory failure renewed grants or revoked independently current ownership")
	}
	if f.configuration.Epoch != configurationEpoch {
		t.Fatal("directory failure revoked static configuration")
	}
	before := f.store.document.LastDirectoryObservedAt
	if err := engine.RefreshBindings(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.refreshes != refreshes+1 || len(f.firewall.active) != 0 ||
		!f.store.document.LastDirectoryObservedAt.Equal(before) || !f.firewall.candidates[0].Grants[0].ExpiresAt().Equal(expires) {
		t.Fatal("physical refresh changed a directory decision or grant deadline")
	}
	if err := engine.Stop(t.Context()); err != nil || len(f.evidence.Addresses) != 0 || f.configuration.Epoch != 0 {
		t.Fatal("stop left positive ownership evidence", err)
	}
}

func TestNamedOwnershipEpisodeChangesRevokeOldGrantsAndRetainHistory(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	engine := f.engine(t, options)
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	clears := f.clears
	epoch := f.evidence.Epoch
	if err := engine.RefreshBindings(t.Context()); err != nil || f.clears != clears || len(f.firewall.active) != 1 {
		t.Fatal("routine refresh revoked an unchanged association", err)
	}
	if epoch == 0 || f.evidence.Epoch != epoch {
		t.Fatal("routine collection changed the connection epoch")
	}
	f.bindings.Records[0].AssociationID = "new-physical-association"
	if err := engine.RefreshBindings(t.Context()); err != nil || f.clears != clears+1 || len(f.firewall.active) != 0 {
		t.Fatal("new association reused an earlier delegated grant", err)
	}
	if f.evidence.Epoch <= epoch {
		t.Fatal("changed ownership reused a connection epoch")
	}
	f.bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::11")
	f.bindings.Records[0].Addresses[0].OwnershipID = "new-address-episode"
	if err := engine.RefreshBindings(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.store.document.ClassifiedIPv6) != 2 {
		t.Fatal("independent ownership refresh failed to persist deny-only address history")
	}
}

func TestNamedOwnershipEpochFailureLeavesNoPhysicalEvidenceOrGrants(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"persistence failure", "reused sequence", "reserved value"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, options := newOwnershipFixture(t)
			consume := options.State.AdvanceOwnershipEpoch
			fail := false
			options.State.AdvanceOwnershipEpoch = func(ctx context.Context) (uint32, error) {
				if !fail {
					return consume(ctx)
				}
				switch name {
				case "persistence failure":
					return 0, errFixture
				case "reused sequence":
					return f.epoch, nil
				default:
					return ^uint32(0), nil
				}
			}
			engine := f.engine(t, options)
			if _, err := engine.Process(t.Context(), f.directory); err != nil {
				t.Fatal(err)
			}
			fail = true
			f.bindings.Records[0].AssociationID = "replacement-session"
			if err := engine.RefreshBindings(t.Context()); err == nil || len(f.evidence.Addresses) != 0 || len(f.firewall.active) != 0 {
				t.Fatal("failed counter retained positive evidence", err)
			}
		})
	}
}

func TestNamedOwnershipRestartConsumesAnotherEpoch(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	engine := f.engine(t, options)
	if err := engine.RefreshBindings(t.Context()); err != nil {
		t.Fatal(err)
	}
	previous := f.evidence.Epoch
	if err := engine.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted := f.engine(t, options)
	if err := restarted.RefreshBindings(t.Context()); err != nil || f.evidence.Epoch <= previous {
		t.Fatal("restart reused the former ownership epoch", err)
	}
}

func TestNamedStartupCannotServeWithoutADurableEpoch(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	engine := f.engine(t, options)
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	options.State.AdvanceOwnershipEpoch = func(context.Context) (uint32, error) { return 0, errFixture }
	restarted, err := New(f.baseline, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(t.Context()); !errors.Is(err, errFixture) || restarted.started ||
		len(f.evidence.Addresses) != 0 || len(f.firewall.active) != 0 {
		t.Fatal("startup with missing sequence retained evidence or began serving", err)
	}
}

func TestNamedOwnershipFailuresClearPhysicalEvidenceAndDirectoryGrants(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"producer outage", "stale", "clock", "persistence", "before startup"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, options := newOwnershipFixture(t)
			engine := f.engine(t, options)
			if _, err := engine.Process(t.Context(), f.directory); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "producer outage":
				f.sourceError = errFixture
			case "stale":
				f.bindings.ObservedAt = f.now.Add(-90 * time.Second)
			case "clock":
				f.setUTC(f.now.Add(-time.Minute))
			case "persistence":
				f.store.loadError = errFixture
			case "before startup":
				f.bindings.Records[0].AssociatedAt = f.now.Add(-time.Second)
			}
			if err := engine.RefreshBindings(t.Context()); err == nil || len(f.evidence.Addresses) != 0 || len(f.firewall.active) != 0 {
				t.Fatal("failed ownership source left physical evidence or grants", err)
			}
		})
	}
}

func TestNamedOwnershipDependenciesAndCancellation(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	incomplete := options
	incomplete.Firewall.RefreshOwnership = nil
	if _, err := New(f.baseline, incomplete); err == nil {
		t.Fatal("named enforcement admitted no ownership refresh backend")
	}
	incomplete = options
	incomplete.Firewall.RefreshConfiguration = nil
	if _, err := New(f.baseline, incomplete); err == nil {
		t.Fatal("named enforcement admitted no configuration publisher")
	}
	incomplete = options
	incomplete.State.AdvanceOwnershipEpoch = nil
	if _, err := New(f.baseline, incomplete); err == nil {
		t.Fatal("named enforcement admitted no durable ownership sequence")
	}
	engine := f.engine(t, options)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := engine.RefreshBindings(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled supervision ignored cancellation", err)
	}
}
