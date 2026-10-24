package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func configurationProofFixture(t *testing.T, baseline policy.Baseline) policy.OwnerConfiguration {
	t.Helper()
	compiler, err := policy.New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := compiler.CompileOwnerConfiguration(t.Context(), 17)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestConfigurationPreparationCannotCreateBindingsGrantsOrArbitraryCommands(t *testing.T) {
	t.Parallel()
	baseline := namedOwnershipBaseline(t)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	proof := configurationProofFixture(t, baseline)
	prepared, err := renderer.prepareConfiguration(t.Context(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfigurationPreparation(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(prepared.batch.data, []byte(ownership4Set)) || bytes.Contains(prepared.batch.data, []byte("lease_from")) {
		t.Fatal("static configuration supplied physical ownership or delegated grants")
	}
	if err := validateBatch(prepared.batch.data); err == nil {
		t.Fatal("generic grant API accepted a configuration transaction")
	}
	for _, test := range []struct {
		name   string
		mutate func(*preparedConfiguration)
	}{
		{"changed epoch", func(p *preparedConfiguration) {
			p.batch.data = bytes.ReplaceAll(p.batch.data, []byte("17408"), []byte("18432"))
			p.digest = sha256.Sum256(p.batch.data)
		}},
		{"changed object", func(p *preparedConfiguration) {
			p.batch.data = bytes.ReplaceAll(p.batch.data, []byte(configurationEpochSet), []byte(ownershipEpochSet))
			p.digest = sha256.Sum256(p.batch.data)
		}},
		{"diagnostic substitution", func(p *preparedConfiguration) { p.evidence = policy.OwnerConfiguration{} }},
		{"baseline substitution", func(p *preparedConfiguration) { p.baselineHash = "forged" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := *prepared
			test.mutate(&candidate)
			if err := validateConfigurationPreparation(t.Context(), &candidate); err == nil {
				t.Fatal("changed configuration crossed the typed writer boundary")
			}
		})
	}
	other := baseline
	other.Generation += "-other"
	if _, err := renderer.prepareConfiguration(t.Context(), configurationProofFixture(t, other)); err == nil {
		t.Fatal("configuration proof transferred to another baseline")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := renderer.prepareConfiguration(ctx, proof); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preparation continued", err)
	}
}

func TestConfigurationRevocationContainsOnlyTheTwoFixedObjects(t *testing.T) {
	t.Parallel()
	prepared, err := prepareConfigurationClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfigurationPreparation(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Commands []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(prepared.batch.data, &decoded); err != nil || len(decoded.Commands) != 4 {
		t.Fatal("revocation omitted fixed objects", err)
	}
	for _, command := range decoded.Commands {
		if len(command) != 1 || command["flush"] == nil {
			t.Fatal("configuration revocation can add positive state")
		}
	}
}
