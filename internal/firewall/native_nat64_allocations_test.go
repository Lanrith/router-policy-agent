package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

type testNAT64Readiness struct {
	transport *nativeNAT64Transport
	entries   []policy.NAT64Allocation
	ready     bool
	calls     int
}

func (proof *testNAT64Readiness) verifyNAT64Readiness(ctx context.Context, transport *nativeNAT64Transport, entries []policy.NAT64Allocation) error {
	if proof == nil {
		return errors.New("test: translator readiness differs")
	}
	proof.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	if !proof.ready || proof.transport != transport || !reflect.DeepEqual(proof.entries, entries) {
		return errors.New("test: translator readiness differs")
	}
	return nil
}

func nat64AllocationFixture(t *testing.T) (*nativeNAT64Transport, *policy.NAT64AllocationLedger, []policy.NAT64Allocation) {
	t.Helper()
	b := nat64TransportFixture(t)
	b.NAT64[0].SourceMappings = []policy.NAT64SourceMapping{
		{Source: netip.MustParseAddr("fdca:1a2b::10"), Alias: netip.MustParseAddr("10.251.0.10")},
		{Source: netip.MustParseAddr("fdca:1a2b::11"), Alias: netip.MustParseAddr("10.251.0.11")},
	}
	transport, err := newNativeNAT64Transport(t.Context(), b, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := transport.geometry.Capture(t.Context(), transport.component, nil, b.NAT64[0].SourceMappings)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return transport, ledger, entries
}

func TestNAT64AllocationPublicationRequiresCurrentOriginalReadiness(t *testing.T) {
	t.Parallel()
	transport, ledger, entries := nat64AllocationFixture(t)
	proof := &testNAT64Readiness{transport: transport, entries: slices.Clone(entries), ready: true}
	prepared, err := prepareNativeNAT64Allocations(t.Context(), transport, ledger, proof)
	if err != nil {
		t.Fatal(err)
	}
	if proof.calls != 1 || prepared.timeout != 85 {
		t.Fatal("NAT64 allocation publication lost its live proof or bounded lifetime", proof.calls, prepared.timeout)
	}
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err != nil || proof.calls != 2 {
		t.Fatal("fresh NAT64 allocation publication failed validation", proof.calls, err)
	}
	var batch struct {
		Operations []map[string]json.RawMessage `json:"nftables"`
	}
	expectedOperations := 24 + len(transport.sourceScopes)
	for _, prefix := range transport.sourceScopes {
		if slices.ContainsFunc(entries, func(entry policy.NAT64Allocation) bool { return prefix.Contains(entry.Source) }) {
			expectedOperations++
		}
	}
	if err := json.Unmarshal(prepared.batch.data, &batch); err != nil || len(batch.Operations) != expectedOperations {
		t.Fatal("NAT64 allocation publication is not one complete replacement", err)
	}
	for index, operation := range batch.Operations {
		if index < 20+len(transport.sourceScopes) && operation["flush"] == nil || index >= 20+len(transport.sourceScopes) && operation["add"] == nil || len(operation) != 1 {
			t.Fatal("NAT64 allocation publication is not flush-before-add")
		}
	}
	for _, name := range (&nativeNAT64Tokens{transport: transport}).names() {
		if !bytes.Contains(prepared.batch.data, []byte(name)) {
			t.Fatal("allocation replacement did not atomically withdraw stale token evidence", name)
		}
	}
	for _, source := range []string{"fdca:1a2b::10", "fdca:1a2b::11"} {
		if !bytes.Contains(prepared.batch.data, []byte(source)) {
			t.Fatal("NAT64 allocation publication omitted an original source", source)
		}
	}
	proof.ready = false
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err == nil {
		t.Fatal("stopped translator retained allocation readiness")
	}
	proof.ready = true
	proof.entries[0].Alias = netip.MustParseAddr("10.251.0.12")
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err == nil {
		t.Fatal("changed translator mapping retained allocation readiness")
	}
	proof.entries = slices.Clone(entries)
	prepared.entries[0].Alias = netip.MustParseAddr("10.251.0.12")
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err == nil {
		t.Fatal("changed prepared allocation retained original ledger authority")
	}
	if _, err := json.Marshal(prepared); err == nil {
		t.Fatal("NAT64 allocation readiness became serializable")
	}
}

func TestNAT64AllocationScopesRetainOriginalSourceAndDeadline(t *testing.T) {
	t.Parallel()
	transport, ledger, entries := nat64AllocationFixture(t)
	proof := &testNAT64Readiness{transport: transport, entries: slices.Clone(entries), ready: true}
	prepared, err := prepareNativeNAT64Allocations(t.Context(), transport, ledger, proof)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := prepared.elements(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(transport.sourceScopes) == 0 {
		t.Fatal("fixture lacks an immutable IPv6 source scope")
	}
	for index, prefix := range transport.sourceScopes {
		wanted := map[string]bool{}
		for _, entry := range entries {
			if prefix.Contains(entry.Source) {
				wanted[entry.Alias.String()] = true
			}
		}
		values := rows[transport.sourceScopeName(index)]
		if len(values) != len(wanted) {
			t.Fatal("source scope does not match original allocation identities", prefix, values)
		}
		for _, raw := range values {
			var element struct {
				Value   string `json:"val"`
				Timeout int    `json:"timeout"`
			}
			if err := decodeNested(raw, "elem", &element, []string{"val", "timeout"}); err != nil ||
				!wanted[element.Value] || element.Timeout != prepared.timeout {
				t.Fatal("source scope borrowed another identity or extended its deadline", string(raw), err)
			}
			delete(wanted, element.Value)
		}
	}
	// An attacker-supplied digest cannot authorize a different source-scope
	// row. The privileged boundary rederives the membership from the original
	// ledger and live translator proof, independently of serialized bytes.
	var batch struct {
		Operations []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(prepared.batch.data, &batch); err != nil {
		t.Fatal(err)
	}
	changed := false
	for _, command := range batch.Operations {
		var add struct {
			Element struct {
				Name string `json:"name"`
			} `json:"element"`
		}
		if json.Unmarshal(command["add"], &add) != nil || add.Element.Name != transport.sourceScopeName(0) {
			continue
		}
		replacement := bytes.Replace(command["add"], []byte("10.251.0.10"), []byte("10.251.0.11"), 1)
		changed = !bytes.Equal(replacement, command["add"])
		command["add"] = replacement
	}
	if !changed {
		t.Fatal("fixture did not attempt a foreign source-scope membership")
	}
	prepared.batch.data, err = json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	prepared.digest = sha256.Sum256(prepared.batch.data)
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err == nil {
		t.Fatal("foreign scope membership escaped original-ledger validation")
	}
}

func TestNAT64AllocationPublicationRejectsDetachedExpiredAndCancelledInputs(t *testing.T) {
	t.Parallel()
	transport, ledger, entries := nat64AllocationFixture(t)
	proof := &testNAT64Readiness{transport: transport, entries: slices.Clone(entries), ready: true}
	if _, err := prepareNativeNAT64Allocations(nil, transport, ledger, proof); err == nil { //nolint:staticcheck // Deliberately invalid boundary input.
		t.Fatal("nil allocation publication context accepted")
	}
	for _, test := range []struct {
		name      string
		transport *nativeNAT64Transport
		ledger    *policy.NAT64AllocationLedger
		proof     nativeNAT64Readiness
	}{
		{"missing transport", nil, ledger, proof},
		{"missing ledger", transport, nil, proof},
		{"missing readiness", transport, ledger, nil},
		{"zero transport", &nativeNAT64Transport{}, ledger, proof},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := prepareNativeNAT64Allocations(t.Context(), test.transport, test.ledger, test.proof); err == nil {
				t.Fatal("detached NAT64 allocation dependency accepted")
			}
		})
	}
	other, _, _ := nat64AllocationFixture(t)
	if _, err := prepareNativeNAT64Allocations(t.Context(), other, ledger, proof); err == nil {
		t.Fatal("ledger from another original geometry accepted")
	}
	proof.ready = false
	if _, err := prepareNativeNAT64Allocations(t.Context(), transport, ledger, proof); err == nil {
		t.Fatal("unready translator minted an allocation publication")
	}
	proof.ready = true
	prepared, err := prepareNativeNAT64Allocations(t.Context(), transport, ledger, proof)
	if err != nil {
		t.Fatal(err)
	}
	prepared.batch.startedAt = prepared.batch.startedAt.Add(-preparationBudget)
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err == nil {
		t.Fatal("expired NAT64 allocation preparation accepted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := prepareNativeNAT64Allocations(cancelled, transport, ledger, proof); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled allocation preparation continued", err)
	}
	if _, err := prepareNativeNAT64AllocationClear(cancelled, transport); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled allocation revocation continued", err)
	}
}

func TestNAT64AllocationClearContainsNoPositiveState(t *testing.T) {
	t.Parallel()
	transport, _, _ := nat64AllocationFixture(t)
	prepared, err := prepareNativeNAT64AllocationClear(t.Context(), transport)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	data := prepared.batch.data
	var batch struct {
		Operations []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &batch); err != nil || len(batch.Operations) != 20+len(transport.sourceScopes) || bytes.Contains(data, []byte(`"add"`)) {
		t.Fatal("NAT64 allocation revocation retained positive state", err)
	}
	if _, err := prepareNativeNAT64AllocationClear(t.Context(), &nativeNAT64Transport{}); err == nil {
		t.Fatal("detached transport minted an allocation revocation")
	}
	prepared.entries = []policy.NAT64Allocation{}
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err == nil {
		t.Fatal("allocation revocation retained positive metadata")
	}
}

func TestNAT64AllocationPublicationDetectsByteMutation(t *testing.T) {
	t.Parallel()
	transport, ledger, entries := nat64AllocationFixture(t)
	proof := &testNAT64Readiness{transport: transport, entries: slices.Clone(entries), ready: true}
	prepared, err := prepareNativeNAT64Allocations(t.Context(), transport, ledger, proof)
	if err != nil {
		t.Fatal(err)
	}
	prepared.batch.data = bytes.Replace(prepared.batch.data, []byte("fdca:1a2b::10"), []byte("fdca:1a2b::12"), 1)
	if err := validateNAT64AllocationPreparation(t.Context(), prepared); err == nil {
		t.Fatal("mutated allocation publication retained its digest")
	}
}
