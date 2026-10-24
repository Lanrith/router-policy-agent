package firewall

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/state"
)

func preparedNAT46TargetFixture(t *testing.T) *preparedGuardBatch {
	t.Helper()
	model, publication, _, _ := nat46TargetGrantFixture(t, true)
	logical := guardChanges{}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	logical.Commands = append(logical.Commands, idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.250.0.20", 43).Commands...)
	data, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	utc, started := time.Now().UTC(), time.Now()
	mapped, err := prepareMappedGuards(t.Context(), &preparedBatch{data: data, preparedAt: utc, startedAt: started, startBefore: utc.Add(preparationBudget)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT46Guards(t.Context(), mapped, publication, model, utc)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestNAT46TargetPreparationRequiresOriginalModelReceiptAndCompleteTransaction(t *testing.T) {
	t.Parallel()
	prepared := preparedNAT46TargetFixture(t)
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal("typed mixed positive control rejected", err)
	}
	if !bytes.Contains(prepared.batch.data, []byte("native_n46_to6_tcp")) {
		t.Fatal("mixed preparation omitted wire grant")
	}
	for _, test := range []struct {
		name   string
		mutate func(*preparedGuardBatch)
	}{
		{"missing model", func(p *preparedGuardBatch) { p.nat46Model = nil }},
		{"changed model mapping", func(p *preparedGuardBatch) { p.nat46Model.mappings[0].target = p.nat46Model.mappings[0].target.Next() }},
		{"missing receipt", func(p *preparedGuardBatch) { p.sourcePublication = nil }},
		{"missing elapsed anchor", func(p *preparedGuardBatch) { p.sourceAnchor = time.Time{} }},
		{"changed utc anchor", func(p *preparedGuardBatch) { p.sourceUTC = p.sourceUTC.Add(time.Second) }},
		{"missing native mode", func(p *preparedGuardBatch) { p.native = false }},
		{"changed epoch", func(p *preparedGuardBatch) {
			p.batch.data = bytes.ReplaceAll(p.batch.data, []byte(`"0:1c00"`), []byte(`"0:2000"`))
		}},
		{"changed embedded peer", func(p *preparedGuardBatch) {
			p.batch.data = bytes.ReplaceAll(p.batch.data, []byte(`fdca:1a2b:e046::af0:a`), []byte(`fdca:1a2b:e046::af0:b`))
		}},
		{"changed timeout", func(p *preparedGuardBatch) {
			offset := bytes.Index(p.batch.data, []byte(`"name":"native_n46_to4_tcp"`))
			if offset >= 0 {
				tail := bytes.Replace(p.batch.data[offset:], []byte(`"timeout":43`), []byte(`"timeout":44`), 1)
				p.batch.data = append(bytes.Clone(p.batch.data[:offset]), tail...)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			modified := preparedNAT46TargetFixture(t)
			test.mutate(modified)
			if err := validatePreparedGuardBatch(t.Context(), modified); err == nil {
				t.Fatal("altered mixed preparation was accepted")
			}
		})
	}
	for _, validate := range []func([]byte) error{validateBatch, func(data []byte) error { return validateGuardBatch(t.Context(), data) }} {
		if validate(prepared.batch.data) == nil {
			t.Fatal("generic mutation admitted mixed preparation")
		}
	}
	// Waiting cannot restart an original target's lower publication deadline.
	aged := *prepared.sourcePublication
	aged.startedAt = aged.startedAt.Add(-50 * time.Second)
	modified := *prepared
	modified.sourcePublication = &aged
	if err := validatePreparedGuardBatch(t.Context(), &modified); err == nil {
		t.Fatal("delayed target publication renewed its encoded grants")
	}
}

func TestNAT46TargetSealContainsOnlyFixedRevocationsAndDenyHistory(t *testing.T) {
	t.Parallel()
	model, _, _, _ := nat46TargetGrantFixture(t, true)
	mapped, err := prepareGuardSeal(t.Context(), state.EmptyClassification())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT46Guards(t.Context(), mapped, nil, model, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardSeal(t.Context(), prepared); err != nil {
		t.Fatal("mixed seal rejected", err)
	}
	var batch guardChanges
	if err := json.Unmarshal(prepared.batch.data, &batch); err != nil {
		t.Fatal(err)
	}
	seen := map[objectReference]bool{}
	for _, command := range batch.Commands {
		if command.Add != nil {
			t.Fatal("empty mixed seal added positive authority")
		}
		if command.Flush != nil {
			seen[command.Flush.Set] = true
		}
	}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		if !seen[ref] {
			t.Fatal("mixed seal omitted fixed mirror revocation", ref)
		}
	}
	if _, err := prepareNativeNAT46Guards(t.Context(), mapped, nil, model, time.Now().UTC()); err == nil {
		t.Fatal("seal acquired an authorization clock")
	}
	if _, err := prepareNativeNAT46Guards(t.Context(), mapped, nil, nil, time.Time{}); err == nil {
		t.Fatal("missing model supplied mixed preparation")
	}
}
