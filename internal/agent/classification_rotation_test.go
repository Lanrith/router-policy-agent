package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

func TestOwnershipTransitionsWithdrawOldPermitsOnceBeforePublication(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		initial       bool
		configuration int
		change        func(*ownershipFixture)
	}{
		{name: "first classified identity", initial: true, configuration: 1},
		{name: "new historical address", configuration: 1, change: func(f *ownershipFixture) {
			f.bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::11")
			f.bindings.Records[0].Addresses[0].OwnershipID = "replacement-address"
		}},
		{name: "new association with the same history", change: func(f *ownershipFixture) {
			f.bindings.Records[0].AssociationID = "replacement-association"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f, options := newOwnershipFixture(t)
			ownership, configuration, seals := 0, 0, 0
			clearOwnership := options.Firewall.ClearOwnership
			options.Firewall.ClearOwnership = func(ctx context.Context) error {
				ownership++
				return clearOwnership(ctx)
			}
			clearConfiguration := options.Firewall.ClearConfiguration
			options.Firewall.ClearConfiguration = func(ctx context.Context) error {
				configuration++
				return clearConfiguration(ctx)
			}
			seal := options.Firewall.Seal
			options.Firewall.Seal = func(ctx context.Context, history state.Classification) error {
				seals++
				return seal(ctx, history)
			}
			publish := options.Firewall.RefreshOwnership
			options.Firewall.RefreshOwnership = func(ctx context.Context, evidence policy.Ownership) error {
				if len(f.firewall.active) != 0 {
					t.Error("source publication retained an old application permission")
					return errFixture
				}
				return publish(ctx, evidence)
			}
			engine := f.engine(t, options)
			if !test.initial {
				if _, err := engine.Process(t.Context(), f.directory); err != nil {
					t.Fatal(err)
				}
				test.change(f)
			}
			ownership, configuration, seals = 0, 0, 0
			if test.initial {
				receipt, err := engine.Process(t.Context(), f.directory)
				if err != nil || receipt.GrantCount != 1 {
					t.Fatalf("fresh enrollment failed: %+v, %v", receipt, err)
				}
			} else if err := engine.RefreshBindings(t.Context()); err != nil || len(f.firewall.active) != 0 {
				t.Fatalf("changed source restored an old directory permission: %v", err)
			}
			if ownership != 1 || seals != 1 || configuration != test.configuration {
				t.Fatalf("unexpected revocation work: ownership=%d configuration=%d seals=%d", ownership, configuration, seals)
			}
			if f.configuration.Epoch == 0 || f.evidence.Epoch <= f.configuration.Epoch {
				t.Fatal("configuration and independently published ownership lost their separate epochs")
			}
			if len(f.store.document.CohortMACs) != 1 || len(f.firewall.cohort) != 1 {
				t.Fatal("source transition lost permanent deny-only classification")
			}
		})
	}
}
