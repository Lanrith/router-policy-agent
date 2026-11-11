package strictjson_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

func keySpanBoundarySeeds() [][]byte {
	result := [][]byte{}
	for _, count := range []int{1, 7, 8, 9, 17} {
		for _, escapedFirst := range []bool{false, true} {
			fields := []string{}
			for index := range count {
				literal := fmt.Sprintf(`"k%d"`, index)
				if (index%2 == 0) == escapedFirst {
					literal = fmt.Sprintf(`"\u006b%d"`, index)
				}
				fields = append(fields, fmt.Sprintf("%s:%d", literal, index))
			}
			result = append(result, []byte("{"+strings.Join(fields, ",")+"}"))
			// Repeat the first key using the opposite spelling, including just
			// before and after promotion from the small inventory to a map.
			duplicate := `"k0":99`
			if !escapedFirst {
				duplicate = `"\u006b0":99`
			}
			result = append(result, []byte("{"+strings.Join(fields, ",")+","+duplicate+"}"))
		}
	}
	return result
}

func TestKeySpanPromotionMatchesDecodedKeysWithoutChangingInput(t *testing.T) {
	t.Parallel()
	for index, input := range keySpanBoundarySeeds() {
		original := bytes.Clone(input)
		var decoded json.RawMessage
		err := strictjson.Decode(input, &decoded, 65536)
		if (err == nil) != (index%2 == 0) {
			t.Fatal("key inventory changed promotion-boundary acceptance", index, err)
		}
		compareStrictStructure(t, input)
		if !bytes.Equal(input, original) {
			t.Fatal("key validation changed its input")
		}
		if err == nil {
			for offset := range input {
				input[offset] = 'x'
			}
			if !bytes.Equal(decoded, original) {
				t.Fatal("decoded value retained temporary input spans")
			}
		}
	}
}

func TestKeySpansRetainUnicodeCaseAndExactLength(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input string
		valid bool
	}{
		{`{"value":1,"Value":2}`, true},
		{`{"a":1,"aa":2,"a ":3}`, true},
		{`{"a":1,"\u0061":2}`, false},
		{`{"\u0061":1,"a":2}`, false},
		{`{"":1,"":2}`, false},
		{`{"é":1,"e\u0301":2}`, true},
		{`{"é":1,"\u00e9":2}`, false},
		{`{"𐀀":1,"\ud800\udc00":2}`, false},
		{`{"\ud800":1,"�":2}`, false},
		{`{"a/b":1,"a\/b":2}`, false},
		{`{"a\\b":1,"a\u005cb":2}`, false},
		{`{"\u0000":1,"\u0000":2}`, false},
		{`{"\u0000":1,"":2}`, true},
		{"{\"\xff\":1}", false},
	} {
		input := []byte(test.input)
		original := bytes.Clone(input)
		var decoded json.RawMessage
		if err := strictjson.Decode(input, &decoded, 65536); (err == nil) != test.valid {
			t.Fatal("key spans changed exact decoded-key semantics", test.input, err)
		}
		compareStrictStructure(t, input)
		if !bytes.Equal(input, original) {
			t.Fatal("key validation changed its input")
		}
	}
}
