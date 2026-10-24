package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

func namedOwnershipBaseline(t *testing.T) policy.Baseline {
	t.Helper()
	_, _, baseline, _ := renderFixture(t)
	baseline.NetworkModel = &policy.NetworkModel{SchemaVersion: 1, UplinkInterface: "wan",
		ManagedNetworks: []policy.Role{policy.Untrusted}, Rules: []policy.NetworkRule{
			{Action: "allow", Authorization: "directory", Protocol: "any", From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}},
		}}
	return baseline
}

func ownershipProofFixture(t *testing.T, baseline policy.Baseline, now time.Time, lifetime time.Duration) policy.Ownership {
	t.Helper()
	compiler, err := policy.New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "synthetic-ownership", ObservedAt: now, Complete: true,
		Records: []binding.Record{{MAC: "02:00:00:00:00:13", NAS: "synthetic-nas", Interface: "lan13", VLAN: 13,
			AssociatedAt: now, AssociationID: "synthetic-association", Addresses: []binding.Address{
				{IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-lease4", ObservedAt: now, ValidUntil: now.Add(lifetime)},
				{IP: netip.MustParseAddr("fdca:1a2b:3::10"), Source: "qualified_ipv6", OwnershipID: "synthetic-lease6", ObservedAt: now, ValidUntil: now.Add(lifetime)},
			}}}}
	evidence, err := compiler.CompileOwnership(t.Context(), snapshot, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestOwnershipPreparationIsExactBoundedAndSeparateFromGrants(t *testing.T) {
	t.Parallel()
	baseline := namedOwnershipBaseline(t)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	evidence := ownershipProofFixture(t, baseline, now, 70*time.Second)
	prepared, err := renderer.prepareOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnershipPreparation(t.Context(), prepared, now); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(prepared.batch.data, []byte(`"timeout":65`)) || bytes.Contains(prepared.batch.data, []byte("lease_from")) {
		t.Fatal("physical preparation renewed a deadline or carried directory permits")
	}
	for _, validate := range []func([]byte) error{validateBatch, func(data []byte) error { return validateGuardBatch(t.Context(), data) }} {
		if err := validate(prepared.batch.data); err == nil {
			t.Fatal("unrelated mutation API accepted ownership evidence")
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*preparedOwnership)
	}{
		{"tuple", func(p *preparedOwnership) {
			p.batch.data = bytes.Replace(p.batch.data, []byte("10.240.3.10"), []byte("10.240.3.11"), 1)
			p.digest = sha256.Sum256(p.batch.data)
		}},
		{"deadline", func(p *preparedOwnership) { p.timeouts[0]++ }},
		{"diagnostic substitution", func(p *preparedOwnership) { p.evidence = policy.Ownership{} }},
		{"proof baseline", func(p *preparedOwnership) { p.baselineHash = "forged" }},
		{"clear substitution", func(p *preparedOwnership) { p.clear = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			modified, err := renderer.prepareOwnership(t.Context(), evidence, now)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(modified)
			if err := validateOwnershipPreparation(t.Context(), modified, now); err == nil {
				t.Fatal("modified preparation gained ownership")
			}
		})
	}
	if err := validateOwnershipPreparation(t.Context(), prepared, now.Add(6*time.Second)); err == nil {
		t.Fatal("delayed ownership batch escaped source deadline")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := renderer.prepareOwnership(ctx, evidence, now); !errors.Is(err, context.Canceled) {
		t.Fatal("ownership preparation ignored cancellation", err)
	}
}

func TestOwnershipClearContainsOnlyFixedRevocations(t *testing.T) {
	t.Parallel()
	prepared, err := prepareOwnershipClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnershipPreparation(t.Context(), prepared, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var decoded guardChanges
	if err := json.Unmarshal(prepared.batch.data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Commands) != 8 {
		t.Fatal("ownership revocation omitted fixed mirrors")
	}
	for _, command := range decoded.Commands {
		if command.Flush == nil || command.Add != nil {
			t.Fatal("ownership clear can add positive evidence")
		}
	}
	prepared.batch.data = bytes.Replace(prepared.batch.data, []byte(ownership4Set), []byte(cohortSet), 1)
	prepared.digest = sha256.Sum256(prepared.batch.data)
	if err := validateOwnershipPreparation(t.Context(), prepared, time.Now().UTC()); err == nil {
		t.Fatal("ownership clear erased historical classification")
	}
}

func TestOwnershipEpochPreparationRequiresFreshProofAndOriginalDeadline(t *testing.T) {
	t.Parallel()
	baseline := namedOwnershipBaseline(t)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	evidence, err := ownershipProofFixture(t, baseline, now, 70*time.Second).InEpoch(t.Context(), 19)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.epochTimeout < 1 || !bytes.Contains(prepared.batch.data, []byte(ownershipEpochMap)) {
		t.Fatal("consumed sequence was omitted from bounded ownership transaction")
	}
	if err := validateOwnershipPreparation(t.Context(), prepared, now); err != nil {
		t.Fatal(err)
	}
	prepared.epochTimeout++
	if err := validateOwnershipPreparation(t.Context(), prepared, now); err == nil {
		t.Fatal("epoch lifetime changed without its proof")
	}
	prepared.epochTimeout--
	if err := validateOwnershipPreparation(t.Context(), prepared, now.Add(90*time.Second)); err == nil {
		t.Fatal("queued ownership sequence renewed its original producer deadline")
	}
}
