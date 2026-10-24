package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"
)

func TestFrozenGuardFieldsMatchTheCompleteComparator(t *testing.T) {
	t.Parallel()
	expected := map[string]any{"family": "inet", "table": ownedTable, "chain": "synthetic_guard", "expr": []any{
		guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff0003ff)), uint64(0xd5000001)),
		map[string]any{"return": nil},
	}}
	schema := &guardTableSchema{encoded: map[string]*guardCompiledFields{}}
	if err := schema.freezeFields(t.Context(), "rule/synthetic_guard/0", expected); err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	for name, value := range expected {
		fields[name] = value
	}
	fields["handle"] = 1
	positive, err := json.Marshal(map[string]any{"rule": fields})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		before, after string
		valid         bool
	}{
		{"", "", true},
		{`"synthetic_guard"`, `"synthetic_\u0067uard"`, true},
		{`"op":"=="`, `"right":3573547009,"op":"=="`, false},
		{`"mark"`, `"priority"`, false},
		{`3573547009`, `3573547010`, false},
		{`"return":null`, `"accept":null`, false},
		{`"handle":1`, `"handle":0`, false},
		{`"expr":`, `"unreviewed":1,"expr":`, false},
		{`"table":"router_policy_agent"`, `"table":null`, false},
		{`"chain":`, `"CHAIN":`, false},
	} {
		data := positive
		if test.before != "" {
			data = bytes.ReplaceAll(data, []byte(test.before), []byte(test.after))
			if bytes.Equal(data, positive) {
				t.Fatal("cache comparison mutation missed its target", test.before)
			}
		}
		compare := func(compiled *guardCompiledFields) (uint64, error) {
			_, actual, err := guardObject(data)
			if err != nil {
				return 0, err
			}
			return checkGuardObjectWithFields(actual, expected, false, compiled)
		}
		oldHandle, oldErr := compare(nil)
		newHandle, newErr := compare(schema.encoded["rule/synthetic_guard/0"])
		if (newErr == nil) != (oldErr == nil) || (newErr == nil) != test.valid || newErr == nil && newHandle != oldHandle {
			t.Fatal("frozen expectation changed exact object acceptance")
		}
	}
}

func TestFrozenInspectionComesOnlyFromCompletedCodeOwnedLayout(t *testing.T) {
	t.Parallel()
	layout, _ := nat46PublicationLayoutFixture(t)
	if layout.inspectionSchemas == nil {
		t.Fatal("selected publication layout did not freeze original expectations")
	}
	if err := layout.freezeInspectionSchemas(t.Context()); err == nil {
		t.Fatal("frozen layout was replaced in place")
	}
	layout.inspectionSchemas = nil
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := layout.freezeInspectionSchemas(ctx); !errors.Is(err, context.Canceled) || layout.inspectionSchemas != nil {
		t.Fatal("cancelled construction exposed partial expectations", err)
	}
}

func TestFrozenGuardValuesRemainIndependent(t *testing.T) {
	t.Parallel()
	verdict := map[string]any{"accept": nil}
	expected := map[string]any{"family": "inet", "table": ownedTable, "chain": "immutable_guard", "expr": []any{verdict}}
	schema := &guardTableSchema{encoded: map[string]*guardCompiledFields{}}
	if err := schema.freezeFields(t.Context(), "immutable", expected); err != nil {
		t.Fatal(err)
	}
	delete(verdict, "accept")
	verdict["drop"] = nil
	for _, test := range []struct {
		verdict string
		valid   bool
	}{{"accept", true}, {"drop", false}} {
		data := []byte(`{"rule":{"family":"inet","table":"router_policy_agent","chain":"immutable_guard","handle":1,"expr":[{"` + test.verdict + `":null}]}}`)
		_, fields, err := guardObject(data)
		if err != nil {
			t.Fatal(err)
		}
		_, err = checkGuardObjectWithFields(fields, expected, false, schema.encoded["immutable"])
		if (err == nil) != test.valid {
			t.Fatal("cached values followed a mutable header", err)
		}
	}
}

func TestFixedGuardValuesMatchCanonicalComparison(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		left, right string
	}{
		{`18446744073709551615`, `18446744073709551614`},
		{`340282366920938463463374607431768211455`, `340282366920938463463374607431768211454`},
		{`1`, `1.0`}, {`10`, `1e1`}, {`0`, `-0`},
		{`{"a":"b","c":null}`, `{"c":null,"a":"\u0062"}`},
		{`{"set":[{"concat":["a",1]},{"concat":["b",2]}]}`, `{"set":[{"concat":["b",2]},{"concat":["a",1]}]}`},
		{`{"set":[{"concat":["a",1]},{"concat":["b",2]}]}`, `{"set":[{"concat":["b",1]},{"concat":["a",2]}]}`},
		{`{"set":[1,1]}`, `{"set":[1]}`},
		{`{"concat":[1,2]}`, `{"concat":[2,1]}`},
		{`{"range":[1,2]}`, `{"range":[2,1]}`},
		{`[{"accept":null},{"drop":null}]`, `[{"drop":null},{"accept":null}]`},
		{`[]`, `null`}, {`{}`, `null`}, {`false`, `0`}, {`"1"`, `1`},
	} {
		left, err := fixedGuardValue([]byte(test.left))
		if err != nil {
			t.Fatal(err)
		}
		right, err := fixedGuardValue([]byte(test.right))
		if err != nil {
			t.Fatal(err)
		}
		first, err := canonicalFixedGuardJSON([]byte(test.left))
		if err != nil {
			t.Fatal(err)
		}
		second, err := canonicalFixedGuardJSON([]byte(test.right))
		if err != nil {
			t.Fatal(err)
		}
		if equalFixedGuardValues(left, right) != bytes.Equal(first, second) {
			t.Fatal("decoded comparison changed canonical equality", test)
		}
	}
}

func FuzzFrozenGuardValuesEquivalent(f *testing.F) {
	expressions := []any{
		guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff0003ff)), uint64(0xd5000001)),
		guardMatch(guardPayload("ip6", "daddr"), map[string]any{"set": []any{
			map[string]any{"concat": []any{"lan10", "fdca:1a2b:1::10"}},
			map[string]any{"concat": []any{"lan13", "fdca:1a2b:3::10"}},
		}}),
		map[string]any{"return": nil},
	}
	expected := map[string]any{"family": "inet", "table": ownedTable, "chain": "fuzz_guard", "expr": expressions}
	schema := &guardTableSchema{encoded: map[string]*guardCompiledFields{}}
	if err := schema.freezeFields(f.Context(), "fuzz", expected); err != nil {
		f.Fatal(err)
	}
	compiled := schema.encoded["fuzz"]
	legacy := *compiled
	legacy.values = nil
	encoded, err := json.Marshal(expressions)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[{"return":null}]`))
	f.Add([]byte(`[{"match":{"left":18446744073709551615,"op":"==","right":18446744073709551614}}]`))
	f.Fuzz(func(t *testing.T, expressions []byte) {
		if len(expressions) > 65536 || !json.Valid(expressions) {
			return
		}
		fields := maps.Clone(expected)
		fields["handle"], fields["expr"] = 1, json.RawMessage(expressions)
		data, err := json.Marshal(map[string]any{"rule": fields})
		if err != nil {
			return
		}
		_, actual, err := guardObject(data)
		if err != nil {
			return
		}
		oldHandle, oldError := checkGuardObjectWithFields(maps.Clone(actual), expected, false, &legacy)
		newHandle, newError := checkGuardObjectWithFields(maps.Clone(actual), expected, false, compiled)
		if (oldError == nil) != (newError == nil) || oldError == nil && oldHandle != newHandle {
			t.Fatal("decoded cache changed original encoded-field acceptance")
		}
	})
}
