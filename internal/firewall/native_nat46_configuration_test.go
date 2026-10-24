package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT46ConfigurationPublishesItsOriginalEpochAndConversionAtomically(t *testing.T) {
	t.Parallel()
	b := nativeNAT46ModelFixture(t)
	sources, err := newNativeNAT46StaticSources(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	proof := configurationProofFixture(t, b)
	ordinary, err := renderer.prepareConfiguration(t.Context(), proof)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := sources.prepareConfiguration(t.Context(), proof)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := renderer.prepareNativeNAT46Configuration(t.Context(), proof, sources)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfigurationPreparation(t.Context(), combined); err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) []json.RawMessage {
		t.Helper()
		var batch struct {
			Commands []json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(data, &batch); err != nil {
			t.Fatal(err)
		}
		return batch.Commands
	}
	expected := append(decode(ordinary.batch.data), decode(converted.batch.data)...)
	if !reflect.DeepEqual(expected, decode(combined.batch.data)) || !combined.nat46 {
		t.Fatal("configuration and source conversion were not one canonical transaction")
	}
	for _, name := range []string{ownership4Set, ownership6Set, nativeNAT46StaticSourceLive, nativeNAT46StaticSourceChannel, "lease_"} {
		if strings.Contains(string(combined.batch.data), name) {
			t.Fatal("static configuration acquired source ownership or delegated grants", name)
		}
	}
	if validateBatch(combined.batch.data) == nil || validateGuardBatch(t.Context(), combined.batch.data) == nil {
		t.Fatal("generic mutation accepted configuration publication")
	}
	foreign := b
	ownedModel := *b.NetworkModel
	ownedModel.Rules = append([]policy.NetworkRule(nil), b.NetworkModel.Rules...)
	ownedModel.Rules[0].Authorization = "owner"
	foreign.NetworkModel = &ownedModel
	otherSources, err := newNativeNAT46StaticSources(t.Context(), foreign)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing geometry", "foreign geometry", "unselected", "missing configuration"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			changed := *combined
			switch name {
			case "missing geometry":
				changed.nat46Geometry = policy.NAT46StaticGeometry{}
			case "foreign geometry":
				changed.nat46Geometry = otherSources.evidence
			case "unselected":
				changed.nat46 = false
			case "missing configuration":
				changed.evidence = policy.OwnerConfiguration{}
			}
			if err := validateConfigurationPreparation(t.Context(), &changed); err == nil {
				t.Fatal("configuration conversion accepted substituted original proofs")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := renderer.prepareNativeNAT46Configuration(ctx, proof, sources); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled configuration publication continued", err)
	}
}

func TestNAT46ConfigurationRevocationHasFiveFixedClearsAndNoPositiveMetadata(t *testing.T) {
	t.Parallel()
	ordinary, err := prepareConfigurationClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	translated, err := prepareNativeNAT46ConfigurationClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		prepared *preparedConfiguration
		clears   int
	}{{ordinary, 4}, {translated, 5}} {
		var batch struct {
			Commands []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal(item.prepared.batch.data, &batch) != nil || len(batch.Commands) != item.clears {
			t.Fatal("configuration revocation changed its selected inventory")
		}
		for _, command := range batch.Commands {
			if len(command) != 1 || command["flush"] == nil {
				t.Fatal("configuration revocation contained positive operations")
			}
		}
		if err := validateConfigurationPreparation(t.Context(), item.prepared); err != nil {
			t.Fatal(err)
		}
	}
	if !translated.batch.preparedAt.IsZero() || !translated.batch.startedAt.IsZero() || !translated.batch.startBefore.IsZero() {
		t.Fatal("configuration revocation supplied an authorization clock")
	}
	if _, err := translated.nat46Geometry.Snapshot(t.Context()); err == nil {
		t.Fatal("configuration revocation carried positive compiler geometry")
	}
	if strings.Contains(string(translated.batch.data), nativeNAT46StaticSourceLive) || strings.Contains(string(translated.batch.data), ownershipEpochSet) {
		t.Fatal("configuration revocation changed independently current source evidence")
	}
}
