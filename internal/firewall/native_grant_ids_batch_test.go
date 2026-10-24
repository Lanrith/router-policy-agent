package firewall

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func preparedIDGrantFixture(t *testing.T) *preparedGuardBatch {
	t.Helper()
	publication, hash, _ := nativeIDPublicationFixture(t)
	logical := guardChanges{}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	logical.Commands = append(logical.Commands, idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.240.3.10", 43).Commands...)
	data, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	utc := time.Now().UTC()
	mapped, err := prepareMappedGuards(t.Context(), &preparedBatch{data: data, startedAt: started, preparedAt: utc, startBefore: utc.Add(preparationBudget)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeGuardsWithSource(t.Context(), mapped, publication, hash, utc)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestNativeIDBatchRequiresItsOriginalReceiptAndAgeAnchors(t *testing.T) {
	t.Parallel()
	prepared := preparedIDGrantFixture(t)
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal("positive ID batch control rejected", err)
	}
	if !bytes.Contains(prepared.batch.data, []byte(`"native_id_lease_from4_tcp","elem"`)) {
		t.Fatal("ID batch omitted physical source-grant evidence")
	}
	for _, test := range []struct {
		name   string
		mutate func(*preparedGuardBatch)
	}{
		{"missing source receipt", func(p *preparedGuardBatch) { p.sourcePublication = nil }},
		{"wrong baseline", func(p *preparedGuardBatch) {
			p.sourceBaselineHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"missing elapsed anchor", func(p *preparedGuardBatch) { p.sourceAnchor = time.Time{} }},
		{"future elapsed anchor", func(p *preparedGuardBatch) { p.sourceAnchor = time.Now().Add(time.Hour) }},
		{"before original preparation", func(p *preparedGuardBatch) { p.sourceAnchor = p.batch.startedAt.Add(-time.Second) }},
		{"changed UTC anchor", func(p *preparedGuardBatch) { p.sourceUTC = p.sourceUTC.Add(time.Second) }},
		{"changed physical epoch", func(p *preparedGuardBatch) {
			p.batch.data = bytes.Replace(p.batch.data, []byte(`"0:1c01"`), []byte(`"0:2001"`), 1)
		}},
		{"legacy preparation", func(p *preparedGuardBatch) { p.native = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			modified := preparedIDGrantFixture(t)
			test.mutate(modified)
			if err := validatePreparedGuardBatch(t.Context(), modified); err == nil {
				t.Fatal("altered source-grant preparation was accepted")
			}
		})
	}
	for _, validate := range []func([]byte) error{validateBatch, func(data []byte) error { return validateGuardBatch(t.Context(), data) }} {
		if err := validate(prepared.batch.data); err == nil {
			t.Fatal("generic mutation API accepted native ID grants")
		}
	}
}
