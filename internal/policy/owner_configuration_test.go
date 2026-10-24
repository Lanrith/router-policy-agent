package policy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestOwnerConfigurationIsIndependentOfDirectoryAndPhysicalOwnership(t *testing.T) {
	t.Parallel()
	baseline, _ := namedFixture(t)
	compiler := testCompiler(t, baseline)
	configuration, err := compiler.CompileOwnerConfiguration(t.Context(), 17)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := configuration.Snapshot(t.Context())
	if err != nil || snapshot.BaselineHash != compiler.BaselineHash() || snapshot.Epoch != 17 {
		t.Fatal("configuration epoch lost its immutable baseline", err)
	}
	snapshot.BaselineHash, snapshot.Epoch = "forged", 19
	actual, err := configuration.Snapshot(t.Context())
	if err != nil || actual.BaselineHash != compiler.BaselineHash() || actual.Epoch != 17 {
		t.Fatal("diagnostic copy changed the configuration proof", err)
	}
	if _, err := json.Marshal(configuration); err == nil {
		t.Fatal("configuration evidence became persistable")
	}
	if _, err := (OwnerConfiguration{}).Snapshot(t.Context()); err == nil {
		t.Fatal("zero configuration supplied evidence")
	}
}

func TestOwnerConfigurationRejectsMissingBaselineReservedSequencesAndCancellation(t *testing.T) {
	t.Parallel()
	baseline, _ := namedFixture(t)
	compiler := testCompiler(t, baseline)
	for _, test := range []struct {
		name  string
		epoch uint32
	}{
		{"zero", 0}, {"rule-bit overlap", MaximumOwnershipEpoch + 1}, {"overflow", ^uint32(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := compiler.CompileOwnerConfiguration(t.Context(), test.epoch); err == nil {
				t.Fatal("reserved epoch accepted")
			}
		})
	}
	if _, err := testCompiler(t, testBaseline()).CompileOwnerConfiguration(t.Context(), 17); err == nil {
		t.Fatal("legacy model gained a named configuration epoch")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := compiler.CompileOwnerConfiguration(ctx, 17); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled configuration compilation continued", err)
	}
}
