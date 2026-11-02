package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

type callbackGrantFixture struct {
	model     *nativeNAT64CallbackModel
	origin    *nativeNAT64GrantOrigin
	readiness *testNAT64Readiness
	receipt   *nativeSourcePublication
	utc       time.Time
}

func newCallbackGrantFixture(t *testing.T, targetPresent bool) callbackGrantFixture {
	t.Helper()
	baseline, callback, model := callbackPolicyFixture(t)
	now := time.Now().UTC()
	addresses := []binding.Address{{IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "callback-target4", ObservedAt: now, ValidUntil: now.Add(80 * time.Second)}}
	if targetPresent {
		addresses = append(addresses, binding.Address{IP: netip.MustParseAddr("fdca:1a2b:3::10"), Source: "qualified_ipv6", OwnershipID: "callback-target6", ObservedAt: now, ValidUntil: now.Add(70 * time.Second)})
	}
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "callback-recipients", ObservedAt: now, Complete: true, Records: []binding.Record{{MAC: "02:00:00:00:00:13", NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: "callback-target-session", Addresses: addresses}}}
	renderer, err := newRenderer(baseline)
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
	transport := callback.native
	ledger, err := transport.geometry.Capture(t.Context(), transport.component, nil, transport.mappings)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	readiness := &testNAT64Readiness{transport: transport, entries: entries, ready: true}
	return callbackGrantFixture{model: model, receipt: receipt, utc: now, readiness: readiness,
		origin: &nativeNAT64GrantOrigin{transport: transport, ledger: ledger, readiness: readiness}}
}

func TestNAT64CallbackTargetGrantsKeepOriginalReceiptListenerAndDeadline(t *testing.T) {
	t.Parallel()
	f := newCallbackGrantFixture(t, true)
	logical := idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.251.0.20", 43)
	commands, err := f.model.projectTargetGrants(t.Context(), logical, f.receipt, f.utc, time.Now(), f.origin)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[objectReference][]json.RawMessage{}
	for _, command := range commands {
		if command.Add == nil {
			continue
		}
		item := command.Add.Element
		if len(item.Values) != 1 || !strings.HasPrefix(item.Name, "native_n64_0_callback_to") {
			t.Fatal("callback grant changed cardinality or borrowed another component", item.Name)
		}
		fields, timeout := nativeSourceTimedTest(t, item.Values[0])
		var epoch, alias, peer string
		var port uint16
		if len(fields) != 4 || timeout != 43 || json.Unmarshal(fields[0], &epoch) != nil || json.Unmarshal(fields[1], &alias) != nil || json.Unmarshal(fields[2], &peer) != nil || json.Unmarshal(fields[3], &port) != nil {
			t.Fatal("callback grant lost typed original scope or renewed its deadline")
		}
		expectedPeer := "10.240.0.10"
		if strings.Contains(item.Name, "_to6_") {
			expectedPeer = "fdca:1a2b:e064::af0:a"
		}
		if epoch != "0:1c00" || alias != "10.251.0.20" || peer != expectedPeer || port != 6053 {
			t.Fatal("callback grant lost recipient epoch, allocation, caller or listener")
		}
		ref := objectReference{Family: item.Family, Table: item.Table, Name: item.Name}
		seen[ref] = item.Values
	}
	if len(seen) != 8 || f.readiness.calls == 0 {
		t.Fatal("callback omitted a typed representation or original live proof", len(seen))
	}
	for _, ref := range nativeMappedTargetGrantRefs(f.model.mapped.policyNamespace()) {
		mirror := objectReference{Family: "netdev", Table: ref.Table, Name: ref.Name}
		if len(seen[ref]) != 1 || len(seen[mirror]) != 1 || string(seen[ref][0]) != string(seen[mirror][0]) {
			t.Fatal("callback grant mirrors differ", ref)
		}
	}
	aged := *f.receipt
	aged.startedAt = aged.startedAt.Add(-50 * time.Second)
	anchor := time.Now()
	commands, err = f.model.projectTargetGrants(t.Context(), logical, &aged, f.utc, anchor, f.origin)
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
			if time.Duration(timeout)*time.Second+preparationBudget+commandBudget > remaining {
				t.Fatal("callback renewed original recipient ownership")
			}
		}
	}
}

func TestNAT64CallbackTargetGrantsRejectDifferentRecipientsAndCallerClasses(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, iface, mac, alias, peer string }{
		{"wrong recipient interface", "lan10", "02:00:00:00:00:13", "10.251.0.20", "10.240.0.10"},
		{"wrong recipient mac", "lan13", "02:00:00:00:00:14", "10.251.0.20", "10.240.0.10"},
		{"unmapped alias", "lan13", "02:00:00:00:00:13", "10.251.0.21", "10.240.0.10"},
		{"public caller on private component", "lan13", "02:00:00:00:00:13", "10.251.0.20", "8.8.8.8"},
		{"source pool caller", "lan13", "02:00:00:00:00:13", "10.251.0.20", "10.251.0.21"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newCallbackGrantFixture(t, true)
			logical := idGrantInput(t, test.iface, test.mac, test.alias, 43)
			for index := range logical.Commands {
				values := logical.Commands[index].Add.Element.Values
				for index := range values {
					values[index] = json.RawMessage(strings.ReplaceAll(string(values[index]), "10.240.0.10", test.peer))
				}
			}
			commands, err := f.model.projectTargetGrants(t.Context(), logical, f.receipt, f.utc, time.Now(), f.origin)
			if err != nil {
				t.Fatal(err)
			}
			for _, command := range commands {
				if command.Add != nil {
					t.Fatal("callback borrowed a recipient, allocation or caller class")
				}
			}
		})
	}
	f := newCallbackGrantFixture(t, false)
	commands, err := f.model.projectTargetGrants(t.Context(), idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.251.0.20", 43), f.receipt, f.utc, time.Now(), f.origin)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.Add != nil {
			t.Fatal("IPv4 receipt substituted for the mapped IPv6 recipient")
		}
	}
}

func TestNAT64CallbackTargetGrantsRequireLiveOriginalDependenciesButCleanupDoesNot(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*callbackGrantFixture)
	}{
		{"missing origin", func(f *callbackGrantFixture) { f.origin = nil }},
		{"missing ledger", func(f *callbackGrantFixture) { f.origin.ledger = nil }},
		{"detached ledger", func(f *callbackGrantFixture) { f.origin.ledger = &policy.NAT64AllocationLedger{} }},
		{"missing readiness", func(f *callbackGrantFixture) { f.origin.readiness = nil }},
		{"stopped translator", func(f *callbackGrantFixture) { f.readiness.ready = false }},
		{"changed live mappings", func(f *callbackGrantFixture) { f.readiness.entries = nil }},
		{"missing recipient receipt", func(f *callbackGrantFixture) { f.receipt = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCallbackGrantFixture(t, true)
			test.change(&f)
			if _, err := f.model.projectTargetGrants(t.Context(), idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.251.0.20", 43), f.receipt, f.utc, time.Now(), f.origin); err == nil {
				t.Fatal("callback accepted changed original dependencies")
			}
			clears, err := f.model.targetGrantClears()
			if err != nil || len(clears) != 8 {
				t.Fatal("callback cleanup needs positive proof or lost a collection")
			}
			for _, command := range clears {
				if command.Flush == nil || command.Add != nil {
					t.Fatal("callback cleanup acquired positive permission")
				}
			}
			data, err := json.Marshal(guardChanges{Commands: clears})
			if err != nil || validateGuardBatch(t.Context(), data) == nil || validateBatch(data) == nil {
				t.Fatal("generic writer admitted callback grant collections", err)
			}
		})
	}
	f := newCallbackGrantFixture(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.model.projectTargetGrants(ctx, guardChanges{}, f.receipt, f.utc, time.Now(), f.origin); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled callback grant projection continued", err)
	}
}

func TestNAT64CallbackTargetGrantsRejectDetachedComponentNamespaces(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*nativeNAT46Model)
	}{
		{"NAT46 namespace", func(m *nativeNAT46Model) { m.namespace = "native_n46" }},
		{"other callback namespace", func(m *nativeNAT46Model) { m.namespace = "native_n64_1_callback" }},
		{"other translator", func(m *nativeNAT46Model) { m.component = "nat46" }},
		{"other prefix", func(m *nativeNAT46Model) { m.prefix = netip.MustParsePrefix("fdca:1a2b:e046::/96") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCallbackGrantFixture(t, true)
			test.change(f.model.mapped)
			if _, err := f.model.projectTargetGrants(t.Context(), idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.251.0.20", 43), f.receipt, f.utc, time.Now(), f.origin); err == nil {
				t.Fatal("callback grant crossed its original namespace")
			}
		})
	}
}
