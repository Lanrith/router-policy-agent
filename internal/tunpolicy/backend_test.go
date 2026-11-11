package tunpolicy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

func fixture(t *testing.T) (policy.Baseline, policy.Input, *policy.Compiler) {
	t.Helper()
	prefix := netip.MustParsePrefix
	nat46Prefix := prefix("fd42:1234:5678:fd46::/96")
	b := policy.Baseline{SchemaVersion: 1, Generation: "tun-fixture", LeaseSeconds: 90, RefreshSeconds: 30,
		MaximumDevices: 4096, MaximumTuples: 16384,
		Zones: []policy.Zone{
			{Role: "devices", Interfaces: []string{"devices"}, Networks: []netip.Prefix{prefix("10.240.3.0/24"), prefix("fd42:1234:5678:10::/64")}},
			{Role: "servers", Interfaces: []string{"servers"}, Networks: []netip.Prefix{prefix("10.240.2.0/24"), prefix("fd42:1234:5678:20::/64")}},
		}, ProtectedNetworks: []policy.NetworkBlock{{ProtectionID: "P01", Networks: []netip.Prefix{prefix("10.241.0.0/25")}}, {ProtectionID: "P03", Networks: []netip.Prefix{prefix("10.241.0.128/25")}}}, ProtectedEndpoints: []policy.EndpointBlock{{ProtectionID: "P02", Networks: []netip.Prefix{prefix("10.241.0.1/32")}, Protocol: "tcp", Ports: []uint16{22}, DestinationOnly: true}}, RetainedBlocks: []policy.NetworkBlock{},
		NAT64:      []policy.NAT64{{ID: "nat64-internal", Prefix: prefix("fd42:1234:5678:fd65::/96"), Scope: "private"}},
		NAT46:      []policy.NAT46{{ID: "app", Alias: netip.MustParseAddr("10.251.0.2"), Target: netip.MustParseAddr("fd42:1234:5678:20::10"), Ready: true}},
		NAT46Pools: []netip.Prefix{prefix("10.251.0.0/24")},
		NetworkModel: &policy.NetworkModel{SchemaVersion: 1, ManagedNetworks: []policy.Role{"devices"}, UplinkInterface: "wan", NAT46Prefix: &nat46Prefix,
			Rules: []policy.NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{443},
				From: []policy.NetworkSelector{{}}, To: []policy.NetworkSelector{{}}}}},
	}
	now := time.Now().UTC()
	placement := `{"schema_version":1,"kind":"placement","vlan_role":"devices"}`
	access := `{"schema_version":1,"kind":"access","vlan_role":"devices","temporary":false,"rules":[{"id":"web","direction":"from_device","peer":{"addresses":["fd42:1234:5678:20::10/128","10.240.2.10/32"]},"protocol":"tcp","destination_ports":[443],"reason":"synthetic service"}]}`
	input := policy.Input{Now: now, Directory: policy.DirectorySnapshot{ObservedAt: now, Complete: true,
		Groups:  []policy.Group{{ID: "placement", Name: "Devices", Policy: &placement, IsNetwork: true}, {ID: "access", Name: "Web", Policy: &access, IsNetwork: true}},
		Devices: []policy.Device{{ID: "device", MAC: "02:00:00:00:00:02", Active: true, GroupIDs: []string{"placement", "access"}}}},
		Bindings: binding.Snapshot{SchemaVersion: 1, Generation: "binding-v1", ObservedAt: now, Complete: true,
			Records: []binding.Record{{MAC: "02:00:00:00:00:02", NAS: "switch", Interface: "devices", AssociatedAt: now, AssociationID: "association-1",
				Addresses: []binding.Address{
					{IP: netip.MustParseAddr("10.240.3.2"), Source: "kea_dhcp4", OwnershipID: "lease-1", ObservedAt: now, ValidUntil: now.Add(time.Minute)},
					{IP: netip.MustParseAddr("fd42:1234:5678:10::2"), Source: "qualified_ipv6", OwnershipID: "lease-2", ObservedAt: now, ValidUntil: now.Add(time.Minute)},
				}}},
		},
	}
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, input, compiler
}

func TestRenderingDelayCannotExtendEvidence(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"ownership", "grants"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, input, compiler, events, now := setup(t)
				authorization := authorize(t, input, compiler)
				owned, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, policy.CaptureAge())
				if err != nil {
					t.Fatal(err)
				}
				b.options.Clock = func() time.Time {
					time.Sleep(CommitBudget + time.Millisecond)
					return *now
				}
				before := len(*events)
				if mode == "ownership" {
					err = b.RefreshOwnership(t.Context(), owned)
				} else {
					err = b.Apply(t.Context(), authorization, state.EmptyClassification())
				}
				if !errors.Is(err, context.DeadlineExceeded) || len(*events) != before {
					t.Fatalf("slow rendering published state: %v, %v", err, (*events)[before:])
				}
			})
		})
	}
}

func setup(t *testing.T) (*Backend, policy.Input, *policy.Compiler, *[]string, *time.Time) {
	t.Helper()
	baseline, input, compiler := fixture(t)
	events := []string{}
	now := input.Now
	b, err := New(baseline, Options{Clock: func() time.Time { return now },
		Commit: func(_ context.Context, batch Batch) error { events = append(events, batch.Program()); return nil },
		Invalidate: func(_ context.Context, _ CleanupScope) error {
			events = append(events, "INVALIDATE")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.CompileOwnerConfiguration(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshConfiguration(t.Context(), configuration); err != nil {
		t.Fatal(err)
	}
	publish(t, b, input, compiler)
	return b, input, compiler, &events, &now
}
func publish(t *testing.T, b *Backend, input policy.Input, compiler *policy.Compiler) {
	t.Helper()
	owned, err := compiler.CompileOwnership(t.Context(), input.Bindings, input.Now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshOwnership(t.Context(), owned); err != nil {
		t.Fatal(err)
	}
}
func authorize(t *testing.T, input policy.Input, compiler *policy.Compiler) policy.Authorization {
	t.Helper()
	authorization, err := compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.Snapshot(t.Context())
	if err != nil || len(snapshot.Grants) == 0 {
		t.Fatalf("fixture needs actual grants: %+v %v", snapshot, err)
	}
	return authorization
}

func TestGrantProjectionAndDataOnlyWrites(t *testing.T) {
	t.Parallel()
	b, input, compiler, events, _ := setup(t)
	if err := b.Apply(t.Context(), authorize(t, input, compiler), state.EmptyClassification()); err != nil {
		t.Fatal(err)
	}
	text := (*events)[len(*events)-1]
	for _, expected := range []string{
		"10.240.3.2 . 10.251.0.2 . tcp . 443",
		"fd42:1234:5678:10::2 . fd42:1234:5678:fd65::af0:20a . tcp . 443",
		"fd42:1234:5678:10::2 . fd42:1234:5678:20::10 . tcp . 443",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing %s in %s", expected, text)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if !strings.HasPrefix(line, "flush set inet lanrith tp_") && !strings.HasPrefix(line, "add element inet lanrith tp_") && !strings.HasPrefix(line, "add element netdev lanrith_identity tp_") {
			t.Fatalf("non-data operation %s", line)
		}
	}
	if strings.Contains(text, "timeout 90") || strings.Contains(text, " . 80 ") {
		t.Fatal("scope or deadline widened", text)
	}
}

func TestBindingEpisodeChangeInvalidatesBeforePublicationAndRejectsOldGrants(t *testing.T) {
	t.Parallel()
	b, input, compiler, events, _ := setup(t)
	authorization := authorize(t, input, compiler)
	before := len(*events)
	input.Bindings.Records[0].AssociationID = "association-2"
	publish(t, b, input, compiler)
	added := (*events)[before:]
	if len(added) != 3 || !strings.Contains(added[0], "flush set inet lanrith tp_bound4") || added[1] != "INVALIDATE" || !strings.Contains(added[2], "add element inet lanrith tp_bound4") {
		t.Fatal("unsafe reassignment order", added)
	}
	if err := b.Apply(t.Context(), authorization, state.EmptyClassification()); err == nil {
		t.Fatal("old episode grant survived")
	}
}

func TestDirectorySealRetainsOwnershipAndHistory(t *testing.T) {
	t.Parallel()
	b, _, _, events, _ := setup(t)
	history := state.Classification{MACs: []string{"02:00:00:00:00:02"}, IPv4: []string{"10.240.3.2"}, IPv6: []string{}}
	for _, input := range []state.Classification{history, state.EmptyClassification()} {
		if err := b.Seal(t.Context(), input); err != nil {
			t.Fatal(err)
		}
		text := (*events)[len(*events)-1]
		if !strings.Contains(text, "add element inet lanrith tp_history4 { 10.240.3.2 }") || strings.Contains(text, "flush set inet lanrith tp_history") || strings.Contains(text, "flush set inet lanrith tp_bound") {
			t.Fatal("seal retired history or owner connectivity", text)
		}
	}
}

func TestInvalidationFailureLeavesNoCurrentBindingAndRetries(t *testing.T) {
	t.Parallel()
	b, input, compiler, events, _ := setup(t)
	failed := true
	b.options.Invalidate = func(_ context.Context, _ CleanupScope) error {
		if failed {
			return errors.New("test invalidation failure")
		}
		return nil
	}
	if err := b.ClearOwnership(t.Context()); err == nil {
		t.Fatal("invalidation failure hidden")
	}
	if len(b.bindings) != 0 || !b.cleanupPending || !strings.Contains((*events)[len(*events)-1], "flush set inet lanrith tp_grants4") {
		t.Fatal("failed withdrawal remained positive or forgot retry")
	}
	if err := b.Apply(t.Context(), authorize(t, input, compiler), state.EmptyClassification()); err == nil {
		t.Fatal("grant published without bindings")
	}
	failed = false
	if err := b.ClearOwnership(t.Context()); err != nil || b.cleanupPending {
		t.Fatal("withdrawal retry failed", err)
	}
}

func TestOwnershipWithdrawalIncludesBothNAT46Families(t *testing.T) {
	t.Parallel()
	b, _, _, events, _ := setup(t)
	publication := (*events)[len(*events)-1]
	for _, address := range []string{"10.240.3.2", "fd42:1234:5678:fd46::af0:302"} {
		if !strings.Contains(publication, address) {
			t.Errorf("cleanup cohort missed %s", address)
		}
	}
	called := false
	b.options.Invalidate = func(_ context.Context, scope CleanupScope) error {
		called = scope == IdentityConnections
		return nil
	}
	if err := b.ClearOwnership(t.Context()); err != nil || !called {
		t.Fatal("identity cleanup was not requested", err)
	}
	if strings.Contains((*events)[len(*events)-1], "flush set inet lanrith tp_cleanup") {
		t.Fatal("withdrawal discarded negative cleanup selectors")
	}
}

func TestExpiredEvidenceAndCanceledCallsCannotPublish(t *testing.T) {
	t.Parallel()
	b, input, compiler, events, now := setup(t)
	authorization := authorize(t, input, compiler)
	*now = input.Now.Add(2 * time.Minute)
	before := len(*events)
	if err := b.Apply(t.Context(), authorization, state.EmptyClassification()); err == nil || len(*events) != before {
		t.Fatal("expired grant wrote positive state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for range 10 {
		if err := b.Seal(ctx, state.EmptyClassification()); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if err := b.Seal(t.Context(), state.EmptyClassification()); err != nil {
		t.Fatal("cancellation leaked the writer lock", err)
	}
}
