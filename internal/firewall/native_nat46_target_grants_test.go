package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nat46TargetGrantFixture(t *testing.T, targetPresent bool) (*nativeNAT46Model, *nativeSourcePublication, time.Time, policy.Baseline) {
	t.Helper()
	b := nativeAccessBaseline(t)
	prefix := netip.MustParsePrefix("fdca:1a2b:e046::/96")
	b.NetworkModel.NAT46Prefix = &prefix
	b.NAT46Pools = sourceClassPrefixes("10.250.0.0/24")
	b.NAT46 = []policy.NAT46{{ID: "mapped", Alias: netip.MustParseAddr("10.250.0.20"), Target: netip.MustParseAddr("fdca:1a2b:3::10"), Ready: true}}
	model, err := newNativeNAT46Model(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	addresses := []binding.Address{{IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic4", ObservedAt: now, ValidUntil: now.Add(80 * time.Second)}}
	if targetPresent {
		addresses = append(addresses, binding.Address{IP: b.NAT46[0].Target, Source: "qualified_ipv6", OwnershipID: "synthetic6", ObservedAt: now, ValidUntil: now.Add(70 * time.Second)})
	}
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "synthetic-mixed-n46", ObservedAt: now, Complete: true, Records: []binding.Record{{MAC: "02:00:00:00:00:13", NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: "synthetic-session", Addresses: addresses}}}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := renderer.compiler.CompileOwnership(t.Context(), snapshot, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.InEpoch(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeOwnership(t.Context(), proof, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := nativeSourceReceipt(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	return model, receipt, now, b
}

func TestNAT46TargetGrantsKeepBothTypedRepresentationsAndOriginalDeadline(t *testing.T) {
	t.Parallel()
	model, receipt, utc, _ := nat46TargetGrantFixture(t, true)
	logical := idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.250.0.20", 43)
	commands, err := model.projectTargetGrants(t.Context(), logical, receipt, utc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[objectReference][]json.RawMessage{}
	for _, command := range commands {
		if command.Add == nil {
			continue
		}
		item := command.Add.Element
		ref := objectReference{Family: item.Family, Table: item.Table, Name: item.Name}
		if _, duplicate := seen[ref]; duplicate || len(item.Values) != 1 {
			t.Fatal("target projection changed endpoint cardinality")
		}
		seen[ref] = item.Values
		fields, timeout := nativeSourceTimedTest(t, item.Values[0])
		if len(fields) != 4 || timeout != 43 {
			t.Fatal("target projection broadened scope or renewed a deadline")
		}
		var epoch, alias, peer string
		var port uint16
		if json.Unmarshal(fields[0], &epoch) != nil || json.Unmarshal(fields[1], &alias) != nil || json.Unmarshal(fields[2], &peer) != nil || json.Unmarshal(fields[3], &port) != nil {
			t.Fatal("invalid typed target key")
		}
		expectedPeer := "10.240.0.10"
		if item.Name == "native_n46_to6_tcp" || item.Name == "native_n46_to6_udp" {
			expectedPeer = "fdca:1a2b:e046::af0:a"
		}
		if epoch != "0:1c00" || alias != "10.250.0.20" || peer != expectedPeer || port != 6053 {
			t.Fatal("mixed grant lost original source epoch, mapping, peer or listener")
		}
	}
	if len(seen) != 8 {
		t.Fatal("target projection omitted a family, direction or protocol", len(seen))
	}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		values := seen[ref]
		mirror := seen[objectReference{Family: "netdev", Table: ref.Table, Name: ref.Name}]
		if len(values) != 1 || len(mirror) != 1 || string(values[0]) != string(mirror[0]) {
			t.Fatal("target grant mirrors differ", ref)
		}
	}
	aged := *receipt
	aged.startedAt = aged.startedAt.Add(-50 * time.Second)
	anchor := time.Now()
	commands, err = model.projectTargetGrants(t.Context(), logical, &aged, utc, anchor)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := aged.remaining(t.Context(), 1, anchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.Add != nil {
			_, timeout := nativeSourceTimedTest(t, command.Add.Element.Values[0])
			if timeout < 1 || time.Duration(timeout)*time.Second+preparationBudget+commandBudget > remaining {
				t.Fatal("mixed projection restarted the individual source publication")
			}
		}
	}
	aged.startedAt = aged.startedAt.Add(-90 * time.Second)
	commands, err = model.projectTargetGrants(t.Context(), logical, &aged, utc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.Add != nil {
			t.Fatal("expired target publication produced a grant")
		}
	}
	// The generic APIs cannot execute the future component's collections.
	data, err := json.Marshal(guardChanges{Commands: commands})
	if err != nil {
		t.Fatal(err)
	}
	if validateGuardBatch(t.Context(), data) == nil || validateBatch(data) == nil {
		t.Fatal("generic mutation admitted mixed target collections")
	}
}

func TestNAT46TargetGrantsCannotBorrowAnotherTargetIdentityOrReceipt(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, iface, mac, alias string }{{"wrong interface", "lan10", "02:00:00:00:00:13", "10.250.0.20"}, {"wrong mac", "lan13", "02:00:00:00:00:14", "10.250.0.20"}, {"unmapped alias", "lan13", "02:00:00:00:00:13", "10.250.0.21"}} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			model, receipt, utc, _ := nat46TargetGrantFixture(t, true)
			commands, err := model.projectTargetGrants(t.Context(), idGrantInput(t, test.iface, test.mac, test.alias, 43), receipt, utc, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, command := range commands {
				if command.Add != nil {
					t.Fatal("mixed grant borrowed a target identity")
				}
			}
		})
	}
	model, receipt, utc, _ := nat46TargetGrantFixture(t, false)
	logical := idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.250.0.20", 43)
	commands, err := model.projectTargetGrants(t.Context(), logical, receipt, utc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.Add != nil {
			t.Fatal("IPv4 ownership substituted for mapped IPv6 ownership")
		}
	}
	if _, err := model.projectTargetGrants(t.Context(), logical, nil, utc, time.Now()); err == nil {
		t.Fatal("missing original receipt supplied positive grants")
	}
	model.baselineHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := model.projectTargetGrants(t.Context(), logical, receipt, utc, time.Now()); err == nil {
		t.Fatal("receipt crossed root baseline")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := model.projectTargetGrants(ctx, logical, receipt, utc, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}
