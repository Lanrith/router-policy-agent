package firewall

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func aggregateNAT64BackendFixture(t *testing.T) *guardedBackend {
	t.Helper()
	b := nat64TransportFixture(t)
	secondPool := netip.MustParsePrefix("10.252.0.0/24")
	b.NAT64 = append(b.NAT64, policy.NAT64{
		ID: "nat64-private", Prefix: netip.MustParsePrefix("fdca:1a2b:e065::/96"), Scope: "private", SourcePool: &secondPool,
	})
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(profileEnvelope{
		SchemaVersion: 1, Baseline: raw, ReviewedRuleset: json.RawMessage(reviewedArtifactFixture),
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := decodePinnedProfile(t.Context(), data, routerProfileDigest(data))
	if err != nil {
		t.Fatal(err)
	}
	options := backendOptionsFixture(t)
	options.profile = profile
	options.expected.FloorHash = profile.ruleset.digest
	backend, err := newGuardedBackend(options)
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func TestNAT64BackendActivationRequiresExactSelectedComponentSet(t *testing.T) {
	t.Parallel()
	backend := aggregateNAT64BackendFixture(t)
	if err := backend.activateNAT64(t.Context(), &policy.NAT64AllocationLedger{}, &testNAT64Readiness{}, policy.OwnerConfiguration{}); err == nil {
		t.Fatal("singular activation selected one component from an aggregate profile")
	}
	if err := backend.activateNAT64Components(t.Context(), nil, policy.OwnerConfiguration{}); err == nil {
		t.Fatal("empty activation set selected an aggregate profile")
	}
	transports := backend.options.profile.layout.native.selectedNAT64Transports()
	duplicate := []nativeNAT64Activation{
		{Component: transports[0].component, Ledger: &policy.NAT64AllocationLedger{}, Readiness: &testNAT64Readiness{}},
		{Component: transports[0].component, Ledger: &policy.NAT64AllocationLedger{}, Readiness: &testNAT64Readiness{}},
	}
	if err := backend.activateNAT64Components(t.Context(), duplicate, policy.OwnerConfiguration{}); err == nil {
		t.Fatal("duplicate activation substituted for a selected NAT64 component")
	}
	if backend.hasNAT64Origins() {
		t.Fatal("rejected activation retained runtime authority")
	}
}
