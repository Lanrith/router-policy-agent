package firewall

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

func TestBatchArrayRetainsStrictNestedAuthority(t *testing.T) {
	t.Parallel()
	valid := leasedBatch(t)
	for _, test := range []struct{ before, after string }{
		{`"nftables":`, `"NFTables":`},
		{`"nftables":`, `"nftables":[],"nft\u0061bles":`},
		{`"flush":`, `"flush":null,"flush":`},
		{`"flush":`, `"Flush":`},
		{`"family":"inet"`, `"family":"inet","fam\u0069ly":"inet"`},
		{`"family":"inet"`, `"family":"inet","Family":"inet"`},
		{`"timeout":2`, `"timeout":2,"timeo\u0075t":2`},
		{`"concat":`, `"concat":null,"concat":`},
	} {
		changed := bytes.ReplaceAll(valid, []byte(test.before), []byte(test.after))
		if bytes.Equal(changed, valid) || validateBatch(changed) == nil {
			t.Fatal("ambiguous or unknown batch operation escaped the strict boundary")
		}
	}
	for _, raw := range []string{`{"nftables":null}`, `{"nftables":{}}`, `{"nftables":[]}`, `{"nftables":[],"other":1}`} {
		if validateBatch([]byte(raw)) == nil {
			t.Fatal("invalid fixed batch envelope accepted")
		}
	}
}

type nestedJSONFixture struct {
	Value struct {
		Fields []string `json:"concat"`
	} `json:"val"`
	Timeout int `json:"timeout"`
}

// Preserve the original four-pass boundary as an independent differential
// oracle. Production performs the same exact field and typed checks after one
// strict validation of the complete value.
func referenceDecodeNested(raw json.RawMessage, target any) error {
	if err := strictjson.Object(raw, []string{"elem"}, nil, maximumBatch); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := strictjson.Decode(raw, &object, maximumBatch); err != nil {
		return err
	}
	if err := strictjson.Object(object["elem"], []string{"val", "timeout"}, nil, maximumBatch); err != nil {
		return err
	}
	return strictjson.Decode(object["elem"], target, maximumBatch)
}

func compareNestedJSON(t *testing.T, data []byte) {
	t.Helper()
	var actual, expected nestedJSONFixture
	got := decodeNested(data, "elem", &actual, []string{"val", "timeout"})
	want := referenceDecodeNested(data, &expected)
	if (got == nil) != (want == nil) || got == nil && !reflect.DeepEqual(actual, expected) {
		t.Fatal("nested decoder differs from the original strict schema")
	}
}

func TestNestedJSONRetainsTheOriginalStrictBoundary(t *testing.T) {
	t.Parallel()
	for _, data := range []string{
		`{"elem":{"val":{"concat":["a","b"]},"timeout":20}}`,
		`{"elem":{"val":{},"timeout":20}}`,
		`{"el\u0065m":{"v\u0061l":{"concat":[]},"timeout":20}}`,
		`{"elem":{"val":{"concat":["a"]},"timeout":20,"timeout":20}}`,
		`{"elem":{"val":{"concat":[]},"timeout":20,"timeo\u0075t":20}}`,
		`{"elem":{"val":{"concat":[],"concat":[]},"timeout":20}}`,
		`{"elem":{"val":{"concat":[],"unknown":1},"timeout":20}}`,
		`{"elem":{"val":{"concat":[]},"timeout":null}}`,
		`{"elem":{"val":null,"timeout":20}}`,
		`{"elem":{"val":{"concat":[]},"timeout":20,"extra":1}}`,
		`{"elem":{"Val":{"concat":[]},"timeout":20}}`,
		`{"elem":{"val":{"concat":[]},"Timeout":20}}`,
		`{"elem":{"val":{"concat":[]},"timeout":20},"extra":1}`,
		`{"elem":{"val":{"concat":[]},"timeout":20}} {}`,
		`{"elem":{"val":{"concat":[]},"timeout":1e1000}}`,
		`{"elem":{"val":{"concat":[]},"timeout":20.0}}`,
		`{"elem":{"val":{"concat":[null]},"timeout":20}}`,
		"{\"elem\":{\"val\":{\"concat\":[\"\xff\"]},\"timeout\":20}}",
		`null`, `[]`, `{}`, `{"elem":null}`, `{"elem":[]}`, `{"elem":{}}`,
		strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33),
	} {
		compareNestedJSON(t, []byte(data))
	}
}

func FuzzNestedJSONMatchesTheOriginalStrictBoundary(f *testing.F) {
	f.Add([]byte(`{"elem":{"val":{"concat":["a"]},"timeout":20}}`))
	f.Add([]byte(`{"elem":{"val":{"concat":[]},"timeout":20,"timeo\u0075t":20}}`))
	f.Add([]byte(`{"elem":{"val":{"concat":[],"unreviewed":1},"timeout":20}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) <= 16384 {
			compareNestedJSON(t, data)
		}
	})
}
