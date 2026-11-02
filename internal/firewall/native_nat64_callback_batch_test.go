package firewall

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/state"
)

func preparedCallbackGrantFixture(t *testing.T) (*preparedGuardBatch, callbackGrantFixture) {
	t.Helper()
	f := newCallbackGrantFixture(t, true)
	f.model.callback.grants = f.model
	logical := guardChanges{}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	logical.Commands = append(logical.Commands, idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.251.0.20", 43).Commands...)
	data, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	utc, started := time.Now().UTC(), time.Now()
	mapped, err := prepareMappedGuards(t.Context(), &preparedBatch{data: data, preparedAt: utc, startedAt: started, startBefore: utc.Add(preparationBudget)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT64Guards(t.Context(), mapped, f.receipt, f.model.callback.native, utc, f.origin)
	if err != nil {
		t.Fatal(err)
	}
	return prepared, f
}

func TestNAT64CallbackBatchRequiresOriginalModelAndCompleteRederivation(t *testing.T) {
	t.Parallel()
	prepared, _ := preparedCallbackGrantFixture(t)
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal("original callback preparation rejected", err)
	}
	if !bytes.Contains(prepared.batch.data, []byte(`"name":"native_n64_0_callback_to6_tcp","elem"`)) || len(prepared.nat64Callbacks) != 1 {
		t.Fatal("callback preparation lost its original model or wire recipient grant")
	}
	for _, test := range []struct {
		name   string
		change func(*preparedGuardBatch, callbackGrantFixture)
	}{
		{"missing model", func(p *preparedGuardBatch, _ callbackGrantFixture) { p.nat64Callbacks = nil }},
		{"missing source", func(p *preparedGuardBatch, _ callbackGrantFixture) { p.sourcePublication = nil }},
		{"missing origin", func(p *preparedGuardBatch, _ callbackGrantFixture) { p.nat64GrantOrigins = nil }},
		{"stopped translator", func(_ *preparedGuardBatch, f callbackGrantFixture) { f.readiness.ready = false }},
		{"replaced model", func(_ *preparedGuardBatch, f callbackGrantFixture) {
			changed := *f.model
			f.model.callback.grants = &changed
		}},
		{"changed namespace", func(_ *preparedGuardBatch, f callbackGrantFixture) { f.model.mapped.namespace = "native_n46" }},
		{"changed wire peer", func(p *preparedGuardBatch, _ callbackGrantFixture) {
			p.batch.data = bytes.ReplaceAll(p.batch.data, []byte("fdca:1a2b:e064::af0:a"), []byte("fdca:1a2b:e064::af0:b"))
		}},
		{"foreign collection", func(p *preparedGuardBatch, _ callbackGrantFixture) {
			p.batch.data = bytes.ReplaceAll(p.batch.data, []byte("native_n64_0_callback_to4_tcp"), []byte("native_n64_1_callback_to4_tcp"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, f := preparedCallbackGrantFixture(t)
			test.change(p, f)
			if err := validatePreparedGuardBatch(t.Context(), p); err == nil {
				t.Fatal("changed callback preparation accepted")
			}
		})
	}
	if validateBatch(prepared.batch.data) == nil || validateGuardBatch(t.Context(), prepared.batch.data) == nil {
		t.Fatal("generic mutation accepted callback grant publication")
	}
	aged := *prepared.sourcePublication
	aged.startedAt = aged.startedAt.Add(-50 * time.Second)
	changed := *prepared
	changed.sourcePublication = &aged
	if err := validatePreparedGuardBatch(t.Context(), &changed); err == nil {
		t.Fatal("callback publication restarted the original recipient deadline")
	}
}

func TestNAT64CallbackSealDoesNotNeedFreshPositiveProof(t *testing.T) {
	t.Parallel()
	_, f := preparedCallbackGrantFixture(t)
	f.readiness.ready = false
	mapped, err := prepareGuardSeal(t.Context(), state.EmptyClassification())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT64Guards(t.Context(), mapped, nil, f.model.callback.native, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardSeal(t.Context(), prepared); err != nil {
		t.Fatal("callback revocation requires positive readiness", err)
	}
	commands, err := decodePreparedGuardChanges(prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range nativeNAT64CallbackGrantRefs(prepared.nat64Callbacks) {
		count := 0
		for _, command := range commands.Commands {
			if command.Flush != nil && command.Flush.Set == ref {
				count++
			}
		}
		if count != 1 {
			t.Fatal("callback seal lost an exact mirrored revocation", ref, count)
		}
	}
}
