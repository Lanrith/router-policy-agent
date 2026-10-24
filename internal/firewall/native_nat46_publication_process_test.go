package firewall

import (
	"testing"
	"time"
)

func TestNAT46SourceOperationRejectsWrongOrUntrustedPreparationBeforeExecution(t *testing.T) {
	t.Parallel()
	_, receipt, _, baseline := nat46TargetGrantFixture(t, true)
	sources, err := newNativeNAT46StaticSources(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := sources.prepareSourceEpoch(t.Context(), receipt, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	altered := *prepared
	altered.publication = nil
	for _, input := range []commandInput{
		{op: applyNAT46SourceEpoch},
		{op: applyNAT46SourceEpoch, payload: prepared.batch.data},
		{op: applyNAT46SourceEpoch, nat46Source: prepared, payload: prepared.batch.data},
		{op: applyNAT46SourceEpoch, nat46Source: prepared, prepared: &prepared.batch},
		{op: applyNAT46SourceEpoch, nat46Source: prepared, ownership: &preparedOwnership{}},
		{op: applyNAT46SourceEpoch, nat46Source: prepared, configuration: &preparedConfiguration{}},
		{op: applyNAT46SourceEpoch, nat46Source: prepared, guarded: &preparedGuardBatch{}},
		{op: applyNAT46SourceEpoch, nat46Source: &preparedNAT46StaticOwnership{}},
		{op: applyNAT46SourceEpoch, nat46Source: &altered},
		{op: inspectOwned, nat46Source: prepared},
		{op: applyOwned, nat46Source: prepared},
		{op: applyOwnership, nat46Source: prepared},
		{op: applyConfiguration, nat46Source: prepared},
		{op: applyGuarded, nat46Source: prepared},
		{op: sealGuarded, nat46Source: prepared},
	} {
		// No executable exists. Invalid requests must fail at validation, rather
		// than reaching the child and hiding their failure as an nft error.
		if _, err := (&process{}).run(t.Context(), input); err == nil || err.Error() == "firewall: nftables operation failed" {
			t.Fatal("invalid source channel operation escaped its fixed boundary")
		}
	}
}
