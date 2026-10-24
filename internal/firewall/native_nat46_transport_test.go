package firewall

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNAT46SharedValidationKeepsEveryLegsOwnTupleMapsAndRecords(t *testing.T) {
	t.Parallel()
	sources, err := newNativeNAT46StaticSources(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	original, err := newNativeNAT46SourceTransport(t.Context(), sources)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := newNativeNAT46SharedTransport(t.Context(), sources)
	if err != nil {
		t.Fatal(err)
	}
	if original.shareValidation || !shared.shareValidation || !reflect.DeepEqual(original.definitions(), shared.definitions()) || !reflect.DeepEqual(original.schema().sets, shared.schema().sets) || !reflect.DeepEqual(original.schema().maps, shared.schema().maps) {
		t.Fatal("sharing changed the default mode or a leg's correlation collections")
	}
	before, after := original.chains(), shared.chains()
	validators := map[string]bool{}
	for _, leg := range shared.legs {
		for _, imported := range []bool{false, true} {
			suffix := "_export"
			if imported {
				suffix = "_import"
			}
			name := leg.name + suffix
			if !reflect.DeepEqual(before[name], after[name]) || !reflect.DeepEqual(before[name+"_checked"], after[name+"_checked"]) {
				t.Fatal("sharing changed selected geometry, tuple import or original connection facts")
			}
			if !imported && !reflect.DeepEqual(before[name+"_checked_current_source_record"], after[name+"_checked_current_source_record"]) {
				t.Fatal("sharing joined different legs' positive tuple publication")
			}
			validators[leg.sharedCurrentName(imported)] = true
		}
	}
	if len(validators) != 8 {
		t.Fatal("shared validators merged a direction, address representation or echo namespace")
	}
	oldCount, newCount := 0, 0
	for _, rules := range before {
		oldCount += len(rules)
	}
	for name, rules := range after {
		newCount += len(rules)
		if validators[name] && len(rules) == 0 {
			t.Fatal("missing shared current source validator")
		}
		if strings.HasPrefix(name, "native_n46_current_") {
			for _, rule := range rules {
				if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "update @") || strings.Contains(rule.text, "delete @") || strings.Contains(rule.text, "ct mark set") {
					t.Fatal("pure shared validation acquired forwarding or publication authority")
				}
			}
		}
	}
	if newCount >= oldCount {
		t.Fatal("shared validators did not remove duplicate rules")
	}
}

func TestNAT46TupleTransportOwnsGeometryAndNeverGrantsAccess(t *testing.T) {
	t.Parallel()
	model, err := newNativeNAT46Model(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newNativeNAT46Transport(t.Context(), model)
	if err != nil {
		t.Fatal(err)
	}
	before := transport.chains()
	if len(transport.legs) != 6*len(model.mappings) || len(transport.definitions()) != 24*len(model.mappings) {
		t.Fatal("missing protocol or direction")
	}
	for name, rules := range before {
		for _, rule := range rules {
			if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") {
				t.Fatal("tuple transport acquired packet authority", name)
			}
		}
	}
	for _, leg := range transport.legs {
		for _, imported := range []bool{false, true} {
			geometry := leg.geometry(imported).text
			if !strings.Contains(geometry, "nat46") || leg.protocol != "icmp" && !strings.Contains(geometry, leg.protocol) {
				t.Fatal("unbounded tuple attachment")
			}
			if leg.reply != imported && (!strings.Contains(geometry, leg.prefix.String()) || !strings.Contains(geometry, leg.mapping.targetInterface) || !strings.Contains(geometry, leg.mapping.target.String())) {
				t.Fatal("translated tuple lost its mapping or attachment")
			}
			_, key := leg.tuple(imported, true)
			object, ok := key.(map[string]any)
			if !ok {
				t.Fatal("tuple key was not a typed concatenation")
			}
			fields, ok := object["concat"].([]any)
			want := 6
			if leg.protocol == "icmp" {
				want = 5
			}
			if !ok || len(fields) != want {
				t.Fatal("tuple correlation lost epoch, context or channel")
			}
		}
	}
	model.prefix = netip.MustParsePrefix("fdca:1a2b:e047::/96")
	model.mappings[0].alias = netip.MustParseAddr("10.250.0.99")
	if !reflect.DeepEqual(before, transport.chains()) {
		t.Fatal("caller mutation changed tuple transport")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newNativeNAT46Transport(ctx, model); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled tuple program continued", err)
	}
	model.mappings = make([]nativeNAT46Mapping, nativeRuleCapacity/160+1)
	if _, err := newNativeNAT46Transport(t.Context(), model); err == nil {
		t.Fatal("tuple product was not bounded before allocation")
	}
	if _, err := newNativeNAT46Transport(t.Context(), nil); err == nil {
		t.Fatal("missing root geometry accepted")
	}
}

func TestNAT46StaticTransportRequiresOriginalGeometryAndSeparateNamespace(t *testing.T) {
	t.Parallel()
	sources, err := newNativeNAT46StaticSources(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := newNativeNAT46Transport(t.Context(), sources.model)
	if err != nil {
		t.Fatal(err)
	}
	static, err := newNativeNAT46StaticTransport(t.Context(), sources)
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []*nativeNAT46Transport{ordinary, static} {
		for name, rules := range transport.chains() {
			for _, rule := range rules {
				if strings.Contains(rule.text, "accept") || strings.Contains(rule.text, "hook ") ||
					transport == ordinary && strings.Contains(rule.text, nativeNAT46StaticBits4) {
					t.Fatal("transport acquired a verdict or borrowed static evidence", name)
				}
			}
		}
	}
	for _, leg := range static.legs {
		for _, direction := range []string{"export", "import"} {
			name := leg.name + "_" + direction + "_checked_current_source_static"
			text := strings.Join(nativeRulesText(static.chains()[name]), "\n")
			if !strings.Contains(text, "@"+nativeNAT46StaticBits4) || !strings.HasSuffix(text, "drop") {
				t.Fatal("static identity can use the zero-ID or NAS fallback", name)
			}
		}
	}
	missing := *sources
	missing.evidence = policy.NAT46StaticGeometry{}
	if _, err := newNativeNAT46StaticTransport(t.Context(), &missing); err == nil {
		t.Fatal("a model or diagnostic snapshot supplied static authority")
	}
	if _, err := newNativeNAT46StaticTransport(t.Context(), nil); err == nil {
		t.Fatal("missing static geometry accepted")
	}
	sources.model.prefix = netip.MustParsePrefix("fdca:1a2b:e047::/96")
	if _, err := newNativeNAT46StaticTransport(t.Context(), sources); err == nil {
		t.Fatal("different geometry supplied static identity")
	}
}

func TestNAT46StaticTransportBoundsCompletePacketProgram(t *testing.T) {
	t.Parallel()
	sources, err := newNativeNAT46StaticSources(t.Context(), nativeNAT46ModelFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// Mapping values do not change the rule product. Populate the boundary
	// using a compiler-owned fixture mapping without enumerating owner inputs.
	mapping := sources.model.mappings[0]
	sources.model.mappings = make([]nativeNAT46Mapping, (nativeRuleCapacity-45)/232)
	for index := range sources.model.mappings {
		sources.model.mappings[index] = mapping
	}
	transport, err := newNativeNAT46StaticTransport(t.Context(), sources)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rules := range transport.chains() {
		count += len(rules)
	}
	if count > nativeRuleCapacity {
		t.Fatal("static tuple product escaped the fixed packet-rule limit", count)
	}
	sources.model.mappings = append(sources.model.mappings, mapping)
	if _, err := newNativeNAT46StaticTransport(t.Context(), sources); err == nil {
		t.Fatal("static tuple product was not bounded before allocation")
	}
}
