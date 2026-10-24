package firewall

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeAccessBaseline(t *testing.T) policy.Baseline {
	t.Helper()
	baseline := nativeScopeBaseline(t)
	baseline.NAT64, baseline.NAT46, baseline.NAT46Pools = []policy.NAT64{}, []policy.NAT46{}, []netip.Prefix{}
	baseline.Zones = []policy.Zone{baseline.Zones[0], baseline.Zones[3]}
	baseline.NetworkModel.Rules = append(baseline.NetworkModel.Rules,
		policy.NetworkRule{Action: "allow", Authorization: "directory", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan13"}}, To: []policy.NetworkSelector{{Interface: "lan10"}}},
		policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "any",
			From: []policy.NetworkSelector{{Interface: "lan13"}}, To: []policy.NetworkSelector{{Interface: "lan10"}}})
	return baseline
}

func TestNativeAccessOwnsIntentAndDoesNotActivateTheDefaultLayout(t *testing.T) {
	t.Parallel()
	baseline := nativeAccessBaseline(t)
	layout, err := newNativeAccessLayout(t.Context(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	before, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	baseline.NetworkModel.Rules[0].Ports[0] = 80
	baseline.NetworkModel.Rules[0].From[0].Addresses[0] = netip.MustParsePrefix("0.0.0.0/0")
	baseline.NetworkModel.ManagedNetworks[0] = policy.Trusted
	after, err := layout.program(t.Context())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("native access changed after mutating caller-owned intent", err)
	}
	defaultLayout, err := newGuardLayout(baseline)
	if err != nil || defaultLayout.native != nil {
		t.Fatal("component construction activated an unqualified default runtime", err)
	}
}

func TestNativeAccessRejectsUnqualifiedGeometryAndUnboundedExpansion(t *testing.T) {
	t.Parallel()
	if _, err := newNativeAccessLayout(nil, nativeAccessBaseline(t)); err == nil { //nolint:staticcheck // Deliberately test the missing-context boundary.
		t.Fatal("missing cancellation context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newNativeAccessLayout(ctx, nativeAccessBaseline(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled compilation proceeded", err)
	}
	if _, err := newNativeAccessLayout(t.Context(), nativeScopeBaseline(t)); err == nil {
		t.Fatal("native-only component silently admitted translator geometry")
	}
	baseline := nativeAccessBaseline(t)
	for range 768 {
		baseline.NetworkModel.Rules = append(baseline.NetworkModel.Rules, baseline.NetworkModel.Rules[0])
	}
	if _, err := newNativeAccessLayout(t.Context(), baseline); err == nil {
		t.Fatal("native rule/hook/link expansion exceeded its bounded capacity")
	}
}
