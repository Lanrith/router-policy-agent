package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func preparedDynamicNAT64GrantFixture(t *testing.T) (*preparedGuardBatch, *nativeNAT64GrantOrigin, *testNAT64Readiness) {
	t.Helper()
	fixture := newNAT64TokenPlanFixture(t, true, true)
	if len(fixture.transport.mappings) != 0 || len(fixture.baseline.NAT64[0].SourceMappings) != 0 {
		t.Fatal("dynamic grant fixture retained a build-time source mapping")
	}
	entries, err := fixture.ledger.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	proof := &testNAT64Readiness{transport: fixture.transport, entries: entries, ready: true}
	origin := &nativeNAT64GrantOrigin{transport: fixture.transport, ledger: fixture.ledger, readiness: proof}
	data, err := json.Marshal(nat64GrantInput(t, "tcp", 43))
	if err != nil {
		t.Fatal(err)
	}
	utc, started := time.Now().UTC(), time.Now()
	mapped, err := prepareMappedGuards(t.Context(), &preparedBatch{data: data, preparedAt: utc, startedAt: started, startBefore: utc.Add(preparationBudget)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT64Guards(t.Context(), mapped, fixture.sources, fixture.transport, utc, origin)
	if err != nil {
		t.Fatal(err)
	}
	return prepared, origin, proof
}

func TestNAT64DynamicGrantRequiresOriginalLiveLedger(t *testing.T) {
	t.Parallel()
	prepared, origin, proof := preparedDynamicNAT64GrantFixture(t)
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	if proof.calls < 2 || !bytes.Contains(prepared.batch.data, []byte(`"name":"native_n64_from4_tcp","elem"`)) ||
		!bytes.Contains(prepared.batch.data, []byte(`"name":"native_n64_from6_tcp","elem"`)) {
		t.Fatal("dynamic grant lacked its original live proof or exact native and wire counterparts")
	}
	for _, test := range []struct {
		name   string
		mutate func(*preparedGuardBatch, *nativeNAT64GrantOrigin, *testNAT64Readiness)
	}{
		{"missing origin", func(p *preparedGuardBatch, _ *nativeNAT64GrantOrigin, _ *testNAT64Readiness) {
			p.nat64GrantOrigins = nil
		}},
		{"nil origin", func(p *preparedGuardBatch, _ *nativeNAT64GrantOrigin, _ *testNAT64Readiness) {
			p.nat64GrantOrigins[0] = nil
		}},
		{"missing ledger", func(_ *preparedGuardBatch, o *nativeNAT64GrantOrigin, _ *testNAT64Readiness) { o.ledger = nil }},
		{"detached ledger", func(_ *preparedGuardBatch, o *nativeNAT64GrantOrigin, _ *testNAT64Readiness) {
			o.ledger = &policy.NAT64AllocationLedger{}
		}},
		{"missing readiness", func(_ *preparedGuardBatch, o *nativeNAT64GrantOrigin, _ *testNAT64Readiness) { o.readiness = nil }},
		{"translator stopped", func(_ *preparedGuardBatch, _ *nativeNAT64GrantOrigin, r *testNAT64Readiness) { r.ready = false }},
		{"translator mappings changed", func(_ *preparedGuardBatch, _ *nativeNAT64GrantOrigin, r *testNAT64Readiness) { r.entries = nil }},
		{"foreign transport", func(_ *preparedGuardBatch, o *nativeNAT64GrantOrigin, _ *testNAT64Readiness) {
			o.transport = newNAT64TokenPlanFixture(t, true, true).transport
		}},
		{"missing source", func(p *preparedGuardBatch, _ *nativeNAT64GrantOrigin, _ *testNAT64Readiness) {
			p.sourcePublication = nil
		}},
		{"duplicated origin", func(p *preparedGuardBatch, o *nativeNAT64GrantOrigin, _ *testNAT64Readiness) {
			p.nat64GrantOrigins = append(p.nat64GrantOrigins, o)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			modified, original, readiness := preparedDynamicNAT64GrantFixture(t)
			test.mutate(modified, original, readiness)
			if err := validatePreparedGuardBatch(t.Context(), modified); err == nil {
				t.Fatal("changed dynamic grant dependencies were accepted")
			}
		})
	}
	originalHash := origin.transport.baselineHash
	mappings, err := nativeNAT64GrantMappings(t.Context(), []*nativeNAT64Transport{origin.transport}, nil)
	if err != nil || len(mappings) != 1 || len(mappings[0]) != 0 {
		t.Fatal("compiler geometry alone produced a dynamic mapping", err)
	}
	if origin.transport.baselineHash != originalHash || len(origin.transport.mappings) != 0 {
		t.Fatal("grant projection changed immutable baseline geometry")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := nativeNAT64GrantMappings(cancelled, []*nativeNAT64Transport{origin.transport}, []*nativeNAT64GrantOrigin{origin}); err == nil {
		t.Fatal("cancelled grant dependency validation succeeded")
	}
}
