package firewall

import (
	"encoding/json"
	"maps"
	"testing"
)

func BenchmarkFixedGuardFieldComparison(b *testing.B) {
	expected := map[string]any{"family": "inet", "table": ownedTable, "chain": "fixed_benchmark", "expr": []any{
		guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff0003ff)), uint64(0xd5000001)),
		guardMatch(guardPayload("ip6", "daddr"), map[string]any{"prefix": map[string]any{"addr": "fdca:1a2b:3::", "len": 64}}),
		guardMatch(guardPayload("tcp", "dport"), map[string]any{"set": []uint16{80, 443}}),
		map[string]any{"return": nil},
	}}
	schema := &guardTableSchema{encoded: map[string]*guardCompiledFields{}}
	if err := schema.freezeFields(b.Context(), "rule/fixed_benchmark/0", expected); err != nil {
		b.Fatal(err)
	}
	raw := []byte(`{"rule":{"family":"inet","table":"router_policy_agent","chain":"fixed_benchmark","handle":1,"expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},4278191103]},"right":3573547009}},{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":{"prefix":{"addr":"fdca:1a2b:3::","len":64}}}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[443,80]}}},{"return":null}]}}`)
	_, fields, err := guardObject(raw)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := checkGuardObjectWithFields(maps.Clone(fields), expected, false, schema.encoded["rule/fixed_benchmark/0"]); err != nil {
			b.Fatal(err)
		}
	}
	_ = json.Valid(raw)
}
