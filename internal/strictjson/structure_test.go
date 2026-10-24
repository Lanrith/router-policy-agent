package strictjson_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

func compareStrictStructure(t testing.TB, data []byte) {
	t.Helper()
	const limit = 65536
	var oldRaw, newRaw json.RawMessage
	oldError, newError := legacyStrictDecode(data, &oldRaw, limit), strictjson.Decode(data, &newRaw, limit)
	if (oldError == nil) != (newError == nil) || oldError == nil && !bytes.Equal(oldRaw, newRaw) {
		t.Fatalf("raw structural acceptance differs: original=%v current=%v input=%q", oldError, newError, data)
	}
	var oldMap, newMap map[string]json.RawMessage
	oldError, newError = legacyStrictDecode(data, &oldMap, limit), strictjson.Decode(data, &newMap, limit)
	if (oldError == nil) != (newError == nil) || oldError == nil && !reflect.DeepEqual(oldMap, newMap) {
		t.Fatalf("object acceptance differs: original=%v current=%v input=%q", oldError, newError, data)
	}
	var oldValue, newValue struct {
		Value int `json:"value"`
	}
	oldError, newError = legacyStrictDecode(data, &oldValue, limit), strictjson.Decode(data, &newValue, limit)
	if (oldError == nil) != (newError == nil) || oldError == nil && oldValue != newValue {
		t.Fatalf("typed acceptance differs: original=%v current=%v input=%q", oldError, newError, data)
	}
	var oldAny, newAny any
	oldError, newError = legacyStrictDecode(data, &oldAny, limit), strictjson.Decode(data, &newAny, limit)
	if (oldError == nil) != (newError == nil) || oldError == nil && !reflect.DeepEqual(oldAny, newAny) {
		t.Fatalf("value acceptance differs: original=%v current=%v input=%q", oldError, newError, data)
	}
}

func strictStructureSeeds() [][]byte {
	seeds := []string{
		`null`, `true`, `false`, `0`, `-0`, `1.0`, `1e9999`, `"a\\b\"c"`, `[]`, `{}`,
		`{"value":1}`, `{"Value":1}`, `{"value":1,"value":2}`, `{"value":1,"v\u0061lue":2}`,
		`{"a":{"a":1},"b":[{"a":2}]}`, `{"a":[{"b":1,"b":2}]}`,
		`{"":0,"":1}`, `{"a/b":0,"a\/b":1}`, `{"\u0000":0,"\u0000":1}`,
		`{"\ud800":0,"\ufffd":1}`, `{"\udfff":0,"�":1}`, `{"\ud800\udc00":0,"𐀀":1}`,
		`{"a\"b":0,"a\u0022b":1}`, `{"a\\b":0,"a\u005cb":1}`,
		`{"value":1} {}`, `{"value":1,}`, `[0,]`, `{"a" 0}`, `"\uZZZZ"`, `01`, `NaN`,
	}
	for depth := 30; depth <= 34; depth++ {
		seeds = append(seeds, strings.Repeat("[", depth)+"0"+strings.Repeat("]", depth))
		seeds = append(seeds, strings.Repeat("[", depth)+strings.Repeat("]", depth))
		seeds = append(seeds, strings.Repeat(`{"a":`, depth)+`0`+strings.Repeat("}", depth))
	}
	var fields []string
	for index := range 20 {
		fields = append(fields, fmt.Sprintf(`"k%d":%d`, index, index))
	}
	seeds = append(seeds, "{"+strings.Join(fields, ",")+"}")
	seeds = append(seeds, "{"+strings.Join(fields, ",")+`,"k0":99}`)
	seeds = append(seeds, "{"+strings.Join(fields, ",")+`,"\u006b0":99}`)
	result := make([][]byte, 0, len(seeds)+1)
	for _, seed := range seeds {
		result = append(result, []byte(seed))
	}
	return append(result, []byte("{\"value\":\"\xff\"}"))
}

func TestStrictStructureMatchesOriginalDecoder(t *testing.T) {
	t.Parallel()
	for _, seed := range strictStructureSeeds() {
		compareStrictStructure(t, seed)
	}
}

func FuzzStrictStructureEquivalent(f *testing.F) {
	for _, seed := range strictStructureSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		compareStrictStructure(t, data)
	})
}
