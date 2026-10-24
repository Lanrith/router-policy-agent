package firewall

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeIDPublicationFixture(t *testing.T) (*nativeSourcePublication, string, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	b := nativeAccessBaseline(t)
	compiler, err := policy.New(b)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := binding.Snapshot{SchemaVersion: 1, Generation: "synthetic-id-publication", ObservedAt: now, Complete: true}
	for index, mac := range []string{"02:00:00:00:00:13", "02:00:00:00:00:14"} {
		record := binding.Record{MAC: mac, NAS: "synthetic-nas", Interface: "lan13", VLAN: 13, AssociatedAt: now, AssociationID: mac}
		addresses := []string{"10.240.3.10", "10.240.3.12"}
		if index == 1 {
			addresses = []string{"10.240.3.11"}
		}
		for _, address := range addresses {
			record.Addresses = append(record.Addresses, binding.Address{IP: netip.MustParseAddr(address), Source: "kea_dhcp4", OwnershipID: address, ObservedAt: now, ValidUntil: now.Add(80 * time.Second)})
		}
		snapshot.Records = append(snapshot.Records, record)
	}
	evidence, err := compiler.CompileOwnership(t.Context(), snapshot, now, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = evidence.InEpoch(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := newRenderer(b)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := nativeSourceReceipt(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, compiler.BaselineHash(), now
}

func idGrantInput(t *testing.T, iface, mac, address string, timeout int) guardChanges {
	t.Helper()
	logical := guardChanges{}
	for _, name := range grantSets {
		device, peer := address, "10.240.0.10"
		if !ipv4Set(name) {
			device, peer = "fdca:1a2b:3::10", "fdca:1a2b::10"
		}
		value, err := json.Marshal(map[string]any{"elem": map[string]any{"timeout": timeout, "val": map[string]any{"concat": []any{iface, mac, device, peer, 6053}}}})
		if err != nil {
			t.Fatal(err)
		}
		logical.Commands = append(logical.Commands, guardAdd("inet", name, []json.RawMessage{value}))
	}
	return logical
}

func TestNativeIDGrantsUseExactPerAddressInventoryAndOriginalEpoch(t *testing.T) {
	t.Parallel()
	receipt, hash, utc := nativeIDPublicationFixture(t)
	cases := []struct {
		name, mac, address string
		id                 uint32
	}{{"first address", "02:00:00:00:00:13", "10.240.3.10", 1}, {"same MAC second address", "02:00:00:00:00:13", "10.240.3.12", 2}, {"other MAC", "02:00:00:00:00:14", "10.240.3.11", 3}}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			commands, err := projectNativeIPv4GrantIDs(t.Context(), idGrantInput(t, "lan13", test.mac, test.address, 43), receipt, hash, utc, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			projected := map[objectReference][]json.RawMessage{}
			for _, command := range commands {
				if command.Add == nil {
					continue
				}
				element := command.Add.Element
				ref := objectReference{Family: element.Family, Table: element.Table, Name: element.Name}
				if _, duplicate := projected[ref]; duplicate || len(element.Values) != 1 {
					t.Fatal("ID projection duplicated a set or broadened its source inventory")
				}
				projected[ref] = element.Values
				fields, timeout := nativeSourceTimedTest(t, command.Add.Element.Values[0])
				if len(fields) != 4 || timeout != 43 {
					t.Fatal("ID projection broadened scope or renewed its logical grant")
				}
				var epoch string
				var high uint32
				var peer string
				var port uint16
				if json.Unmarshal(fields[0], &epoch) != nil || json.Unmarshal(fields[1], &high) != nil || json.Unmarshal(fields[2], &peer) != nil || json.Unmarshal(fields[3], &port) != nil {
					t.Fatal("invalid ID grant tuple")
				}
				if epoch != epochClassID(7<<policy.OwnershipRuleBits|test.id) || high != 0 || peer != "10.240.0.10" || port != 6053 {
					t.Fatal("ID grant borrowed another source episode or endpoint")
				}
			}
			if len(projected) != 8 {
				t.Fatal("ID projection omitted an inet/netdev direction/protocol or admitted the IPv6 identity domain", len(projected))
			}
			for _, ref := range nativeIDLeaseRefs() {
				values := projected[ref]
				mirror := projected[objectReference{Family: "netdev", Table: ref.Table, Name: ref.Name}]
				if len(values) != 1 || len(mirror) != 1 || string(values[0]) != string(mirror[0]) {
					t.Fatal("inet and physical grants diverged in identity, scope or original deadline", ref)
				}
			}
		})
	}
}

func TestNativeIDGrantsRejectUnpublishedSourcesAndConsumeThePublishedLifetime(t *testing.T) {
	t.Parallel()
	receipt, hash, utc := nativeIDPublicationFixture(t)
	for _, test := range []struct{ name, iface, mac, address string }{{"wrong attachment", "lan12", "02:00:00:00:00:13", "10.240.3.10"}, {"wrong MAC", "lan13", "02:00:00:00:00:14", "10.240.3.10"}, {"unowned address", "lan13", "02:00:00:00:00:13", "10.240.3.99"}} {
		t.Run(test.name, func(t *testing.T) {
			commands, err := projectNativeIPv4GrantIDs(t.Context(), idGrantInput(t, test.iface, test.mac, test.address, 43), receipt, hash, utc, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, command := range commands {
				if command.Add != nil {
					t.Fatal("unpublished source gained an ID grant")
				}
			}
		})
	}
	logical := idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.240.3.10", 80)
	aged := *receipt
	aged.startedAt = aged.startedAt.Add(-50 * time.Second)
	anchor := time.Now()
	commands, err := projectNativeIPv4GrantIDs(t.Context(), logical, &aged, hash, utc, anchor)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := aged.remaining(t.Context(), 0, anchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.Add == nil {
			continue
		}
		_, timeout := nativeSourceTimedTest(t, command.Add.Element.Values[0])
		if timeout < 1 || time.Duration(timeout)*time.Second+preparationBudget+commandBudget > remaining {
			t.Fatal("ID grant restarted the original published source lifetime")
		}
	}
	aged.startedAt = aged.startedAt.Add(-90 * time.Second)
	commands, err = projectNativeIPv4GrantIDs(t.Context(), logical, &aged, hash, utc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.Add != nil {
			t.Fatal("expired publication gained a new ID grant")
		}
	}
	if _, err := projectNativeIPv4GrantIDs(t.Context(), logical, receipt, "different-baseline", utc, time.Now()); err == nil {
		t.Fatal("another baseline supplied source IDs")
	}
	if _, err := projectNativeIPv4GrantIDs(t.Context(), logical, nil, hash, utc, time.Now()); err == nil {
		t.Fatal("missing source publication supplied source IDs")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := projectNativeIPv4GrantIDs(ctx, logical, receipt, hash, utc, time.Now()); err == nil {
		t.Fatal("canceled ID projection succeeded")
	}
}
