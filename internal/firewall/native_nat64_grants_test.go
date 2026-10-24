package firewall

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/state"
)

func nat64GrantInput(t *testing.T, protocol string, timeout int) guardChanges {
	t.Helper()
	logical := guardChanges{}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	value, err := json.Marshal(map[string]any{"elem": map[string]any{"timeout": timeout, "val": map[string]any{"concat": []any{
		"lan10", "02:00:00:00:00:10", "fdca:1a2b::10", "fdca:1a2b:e064::af0:30a", 6061,
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	logical.Commands = append(logical.Commands, guardAdd("inet", "lease_from6_"+protocol, []json.RawMessage{value}))
	return logical
}

func preparedNAT64GrantFixture(t *testing.T) *preparedGuardBatch {
	t.Helper()
	fixture := newNAT64TokenPlanFixture(t, true)
	data, err := json.Marshal(nat64GrantInput(t, "tcp", 43))
	if err != nil {
		t.Fatal(err)
	}
	utc, started := time.Now().UTC(), time.Now()
	mapped, err := prepareMappedGuards(t.Context(), &preparedBatch{data: data, preparedAt: utc, startedAt: started, startBefore: utc.Add(preparationBudget)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT64Guards(t.Context(), mapped, fixture.sources, fixture.transport, utc)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestNAT64GrantPreparationRequiresOriginalSourceAndModel(t *testing.T) {
	t.Parallel()
	prepared := preparedNAT64GrantFixture(t)
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal("typed NAT64 grant control rejected", err)
	}
	for _, expected := range [][]byte{[]byte(`"native_n64_from4_tcp"`), []byte(`"native_n64_from6_tcp"`), []byte(`"0:2401"`), []byte(`"10.240.3.10"`), []byte(`"fdca:1a2b:e064::af0:30a"`)} {
		if !bytes.Contains(prepared.batch.data, expected) {
			t.Fatal("NAT64 grant projection omitted an exact identity", string(expected))
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*preparedGuardBatch)
	}{
		{"missing transport", func(p *preparedGuardBatch) { p.nat64Transport = nil }},
		{"missing receipt", func(p *preparedGuardBatch) { p.sourcePublication = nil }},
		{"changed prefix", func(p *preparedGuardBatch) {
			p.nat64Transport.prefix = netip.MustParsePrefix("fdca:1a2b:e065::/96")
		}},
		{"changed peer", func(p *preparedGuardBatch) {
			p.batch.data = bytes.ReplaceAll(p.batch.data, []byte("10.240.3.10"), []byte("10.240.3.11"))
		}},
		{"changed deadline", func(p *preparedGuardBatch) {
			offset := bytes.Index(p.batch.data, []byte(`"name":"native_n64_from4_tcp"`))
			if offset >= 0 {
				tail := bytes.Replace(p.batch.data[offset:], []byte(`"timeout":43`), []byte(`"timeout":44`), 1)
				p.batch.data = append(bytes.Clone(p.batch.data[:offset]), tail...)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			modified := preparedNAT64GrantFixture(t)
			test.mutate(modified)
			if err := validatePreparedGuardBatch(t.Context(), modified); err == nil {
				t.Fatal("altered NAT64 grant preparation was accepted")
			}
		})
	}
	for _, validate := range []func([]byte) error{validateBatch, func(data []byte) error { return validateGuardBatch(t.Context(), data) }} {
		if validate(prepared.batch.data) == nil {
			t.Fatal("generic mutation admitted NAT64 grant mirrors")
		}
	}
}

func TestNAT64GrantSealContainsOnlyFixedRevocations(t *testing.T) {
	t.Parallel()
	fixture := newNAT64TokenPlanFixture(t, false)
	data, err := json.Marshal(nat64GrantInput(t, "udp", 43))
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := prepareMappedGuards(t.Context(), &preparedBatch{data: data}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT64Guards(t.Context(), mapped, nil, fixture.transport, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	for _, ref := range nativeNAT64GrantRefs() {
		needle := []byte(`"flush":{"set":{"family":"` + ref.Family + `","table":"` + ownedTable + `","name":"` + ref.Name + `"}}`)
		if !bytes.Contains(prepared.batch.data, needle) {
			t.Fatal("NAT64 seal omitted fixed revocation", ref)
		}
	}
	if bytes.Contains(prepared.batch.data, []byte(`"name":"native_n64_from4_udp","elem"`)) {
		t.Fatal("NAT64 seal retained a delegated permission")
	}
}

func TestNAT64LayoutGuardPreparationSelectsItsTypedGrantInventory(t *testing.T) {
	t.Parallel()
	baseline := nat64TransportFixture(t)
	layout, err := newNativeNAT64AccessLayout(t.Context(), baseline, "nat64-internal")
	if err != nil {
		t.Fatal(err)
	}
	logical := guardChanges{}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	data, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	history := state.EmptyClassification()
	prepared, err := prepareLayoutGuards(t.Context(), &preparedBatch{data: data}, &history, layout)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.nat64Transport != layout.native.nat64Transport || prepared.sourcePublication != nil {
		t.Fatal("NAT64 layout preparation lost its selected model or invented a source receipt")
	}
	for _, ref := range nativeNAT64GrantRefs() {
		needle := []byte(`"flush":{"set":{"family":"` + ref.Family + `","table":"` + ownedTable + `","name":"` + ref.Name + `"}}`)
		if !bytes.Contains(prepared.batch.data, needle) {
			t.Fatal("NAT64 layout preparation omitted a fixed grant revocation", ref)
		}
	}
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
}
