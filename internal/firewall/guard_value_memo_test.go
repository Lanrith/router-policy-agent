package firewall

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

func memoGuardFixture(t *testing.T) (map[string]any, *guardCompiledFields) {
	t.Helper()
	expected := map[string]any{
		"family": "inet", "table": ownedTable, "chain": "memo_guard",
		"expr": []any{guardMatch(guardMeta("mark"), uint64(7)), map[string]any{"return": nil}},
	}
	schema := &guardTableSchema{encoded: map[string]*guardCompiledFields{}}
	if err := schema.freezeFields(t.Context(), "rule/memo_guard/0", expected); err != nil {
		t.Fatal(err)
	}
	return expected, schema.encoded["rule/memo_guard/0"]
}

func memoGuardFields(t *testing.T, compiled *guardCompiledFields, handle uint64) map[string]json.RawMessage {
	t.Helper()
	fields := map[string]json.RawMessage{}
	for name, data := range compiled.encoded {
		fields[name] = bytes.Clone(data)
	}
	encoded, err := json.Marshal(handle)
	if err != nil {
		t.Fatal(err)
	}
	fields["handle"] = encoded
	// nft's spelling need not match the compiler's canonical object key order
	// or whitespace. The first observation still needs the complete comparator.
	fields["expr"] = bytes.ReplaceAll(fields["expr"], []byte(":"), []byte(": "))
	return fields
}

func TestGuardEncodingMemoOwnsOnlyValidatedFixedBytes(t *testing.T) {
	t.Parallel()
	expected, compiled := memoGuardFixture(t)
	fields := memoGuardFields(t, compiled, 1)
	if _, err := checkGuardObjectWithFields(fields, expected, false, compiled); err != nil {
		t.Fatal(err)
	}
	memo := compiled.verified["expr"].Load()
	if memo == nil {
		t.Fatal("equivalent fixed expression was not memoized")
	}
	saved := bytes.Clone(memo.data)
	for index := range fields["expr"] {
		fields["expr"][index] = ' '
	}
	if !bytes.Equal(memo.data, saved) {
		t.Fatal("memo retained caller-owned listing storage")
	}
	for _, change := range []func(map[string]json.RawMessage){
		func(fields map[string]json.RawMessage) {
			fields["expr"] = bytes.ReplaceAll(fields["expr"], []byte("7"), []byte("8"))
		},
		func(fields map[string]json.RawMessage) { fields["handle"] = []byte("0") },
		func(fields map[string]json.RawMessage) { fields["elem"] = []byte("[]") },
		func(fields map[string]json.RawMessage) { fields["unreviewed"] = []byte("1") },
	} {
		fields := memoGuardFields(t, compiled, 1)
		change(fields)
		if _, err := checkGuardObjectWithFields(fields, expected, false, compiled); err == nil {
			t.Fatal("memo allowed changed authority, handle or schema")
		}
		if !bytes.Equal(compiled.verified["expr"].Load().data, saved) {
			t.Fatal("rejected observation replaced the verified encoding")
		}
	}
}

func TestGuardEncodingMemoBoundsRetainedEquivalentInput(t *testing.T) {
	t.Parallel()
	expected, compiled := memoGuardFixture(t)
	fields := memoGuardFields(t, compiled, 1)
	fields["expr"] = bytes.Replace(fields["expr"], []byte("["), append([]byte("["), bytes.Repeat([]byte(" "), 4096)...), 1)
	if _, err := checkGuardObjectWithFields(fields, expected, false, compiled); err != nil {
		t.Fatal("valid whitespace changed comparison", err)
	}
	if compiled.verified["expr"].Load() != nil {
		t.Fatal("oversized equivalent spelling grew retained memory")
	}
}

func TestGuardEncodingMemoKeepsConcurrentComparisonsIndependent(t *testing.T) {
	t.Parallel()
	expected, compiled := memoGuardFixture(t)
	var workers sync.WaitGroup
	for worker := range uint64(12) {
		workers.Go(func() {
			for iteration := range 30 {
				fields := memoGuardFields(t, compiled, worker+1)
				valid := iteration%3 != 0
				if !valid {
					fields["expr"] = bytes.ReplaceAll(fields["expr"], []byte("return"), []byte("accept"))
				}
				_, err := checkGuardObjectWithFields(fields, expected, false, compiled)
				if (err == nil) != valid {
					t.Error("concurrent memo changed exact comparison", err)
					return
				}
			}
		})
	}
	workers.Wait()
}
