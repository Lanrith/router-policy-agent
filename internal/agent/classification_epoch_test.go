package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

func addUnboundDirectoryIdentity(f *ownershipFixture) {
	f.setUTC(f.now.Add(time.Second))
	f.directory.ObservedAt, f.bindings.ObservedAt = f.now, f.now
	device := f.directory.Devices[0]
	device.ID, device.MAC = "new-unbound-device", "02:00:00:00:00:02"
	device.GroupIDs = []string{"placement"}
	f.directory.Devices = append(f.directory.Devices, device)
}

func TestClassificationWithoutAddressRevokesBothConnectionEpisodes(t *testing.T) {
	t.Parallel()
	f, options := newOwnershipFixture(t)
	seal := options.Firewall.Seal
	additions := 0
	options.Firewall.Seal = func(ctx context.Context, history state.Classification) error {
		if slices.Contains(history.MACs, "02:00:00:00:00:02") && additions == 0 {
			if f.configuration.Epoch != 0 || f.evidence.Epoch != 0 {
				t.Fatal("new classifier was published before old positive channels were withdrawn")
			}
			additions++
		}
		return seal(ctx, history)
	}
	engine := f.engine(t, options)
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	oldConfiguration, oldSource := f.configuration.Epoch, f.evidence.Epoch
	addUnboundDirectoryIdentity(f)
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	if additions != 1 || f.configuration.Epoch <= oldSource || f.evidence.Epoch <= f.configuration.Epoch || f.configuration.Epoch == oldConfiguration {
		t.Fatal("new MAC without an IP reused either old connection episode")
	}
	configuration, source := f.configuration.Epoch, f.evidence.Epoch
	if err := engine.RefreshBindings(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.directory.Complete = false
	if _, err := engine.Process(t.Context(), f.directory); err == nil {
		t.Fatal("incomplete directory accepted")
	}
	if f.configuration.Epoch != configuration || f.evidence.Epoch != source {
		t.Fatal("unchanged history or directory outage rotated static permissions")
	}
}

func TestClassificationFailedSaveStillRotatesBeforePublishing(t *testing.T) {
	t.Parallel()
	for _, advanced := range []bool{false, true} {
		t.Run(map[bool]string{false: "before rename", true: "after rename"}[advanced], func(t *testing.T) {
			t.Parallel()
			f, options := newOwnershipFixture(t)
			engine := f.engine(t, options)
			if _, err := engine.Process(t.Context(), f.directory); err != nil {
				t.Fatal(err)
			}
			oldSource := f.evidence.Epoch
			addUnboundDirectoryIdentity(f)
			f.store.failSave, f.store.advanceThenFail = f.store.saves+1, advanced
			if _, err := engine.Process(t.Context(), f.directory); !errors.Is(err, errFixture) {
				t.Fatal(err)
			}
			if f.configuration.Epoch <= oldSource || f.evidence.Epoch != 0 || !slices.Contains(f.firewall.cohort, "02:00:00:00:00:02") {
				t.Fatal("failed persistence cleanup published classifiers with a stale positive episode")
			}
			configuration := f.configuration.Epoch
			if err := engine.RefreshBindings(t.Context()); err != nil {
				t.Fatal(err)
			}
			if f.configuration.Epoch != configuration || f.evidence.Epoch <= configuration {
				t.Fatal("empty/older persisted history reset the additive classifier cache or restored an old episode")
			}
		})
	}
}

func TestClassificationTransitionFailureRequiresStartup(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"clear configuration", "clear ownership", "sequence", "seal", "publish configuration"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			f, options := newOwnershipFixture(t)
			fail := false
			clearConfiguration, clearOwnership := options.Firewall.ClearConfiguration, options.Firewall.ClearOwnership
			consume, seal, publish := options.State.AdvanceOwnershipEpoch, options.Firewall.Seal, options.Firewall.RefreshConfiguration
			options.Firewall.ClearConfiguration = func(ctx context.Context) error {
				if err := clearConfiguration(ctx); err != nil {
					return err
				}
				if fail && operation == "clear configuration" {
					fail = false
					return errFixture
				}
				return nil
			}
			options.Firewall.ClearOwnership = func(ctx context.Context) error {
				if err := clearOwnership(ctx); err != nil {
					return err
				}
				if fail && operation == "clear ownership" {
					fail = false
					return errFixture
				}
				return nil
			}
			options.State.AdvanceOwnershipEpoch = func(ctx context.Context) (uint32, error) {
				value, err := consume(ctx)
				if fail && operation == "sequence" {
					fail = false
					return 0, errFixture
				}
				return value, err
			}
			options.Firewall.Seal = func(ctx context.Context, history state.Classification) error {
				if err := seal(ctx, history); err != nil {
					return err
				}
				if fail && operation == "seal" {
					fail = false
					return errFixture
				}
				return nil
			}
			options.Firewall.RefreshConfiguration = func(ctx context.Context, proof policy.OwnerConfiguration) error {
				if err := publish(ctx, proof); err != nil {
					return err
				}
				if fail && operation == "publish configuration" {
					fail = false
					return errFixture
				}
				return nil
			}
			engine := f.engine(t, options)
			if _, err := engine.Process(t.Context(), f.directory); err != nil {
				t.Fatal(err)
			}
			oldSource := f.evidence.Epoch
			addUnboundDirectoryIdentity(f)
			fail = true
			if _, err := engine.Process(t.Context(), f.directory); !errors.Is(err, errFixture) {
				t.Fatal("transition did not fail", err)
			}
			if engine.started || f.configuration.Epoch != 0 || f.evidence.Epoch != 0 || len(f.firewall.active) != 0 {
				t.Fatal("failed transition resumed service or left positive evidence")
			}
			if err := engine.RefreshBindings(t.Context()); err == nil {
				t.Fatal("source worker served after failed transition")
			}
			if _, err := engine.Process(t.Context(), f.directory); err == nil {
				t.Fatal("reader served after failed transition")
			}
			if err := engine.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			if f.configuration.Epoch <= oldSource || f.evidence.Epoch != 0 {
				t.Fatal("restart restored an old episode or positive ownership")
			}
		})
	}
}

func TestSourceClassificationFailedSaveRevokesBothEpochs(t *testing.T) {
	t.Parallel()
	for _, advanced := range []bool{false, true} {
		t.Run(map[bool]string{false: "before rename", true: "after rename"}[advanced], func(t *testing.T) {
			t.Parallel()
			f, options := newOwnershipFixture(t)
			engine := f.engine(t, options)
			if _, err := engine.Process(t.Context(), f.directory); err != nil {
				t.Fatal(err)
			}
			old := f.evidence.Epoch
			f.bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::11")
			f.bindings.Records[0].Addresses[0].OwnershipID = "new-source-address"
			f.store.failSave, f.store.advanceThenFail = f.store.saves+1, advanced
			if err := engine.RefreshBindings(t.Context()); !errors.Is(err, errFixture) {
				t.Fatal(err)
			}
			if f.configuration.Epoch <= old || f.evidence.Epoch != 0 || !slices.Contains(f.firewall.ipv6, "fdca:1a2b:3::11") {
				t.Fatal("failed source save discarded new deny history or reused an old epoch")
			}
		})
	}
}
