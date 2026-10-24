package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Both representations come from the completed compiler-owned header. Values
// are independently decoded copies, not references to mutable header maps or
// observed rules. Keeping their trees avoids re-encoding every observed field
// solely to compare object-key order. No lease or observation is cached here.
type guardCompiledFields struct {
	encoded map[string][]byte
	values  map[string]any
}

func fixedGuardValue(data []byte) (any, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("firewall: fixed expression normalization failed")
	}
	if err := normalizeGuardLiteralSets(value); err != nil {
		return nil, err
	}
	return value, nil
}

// The inputs are JSON trees decoded with UseNumber. Number spelling therefore
// has the same exact comparison as canonicalFixedGuardJSON, without float
// rounding. Only literal sets were sorted; all other arrays remain ordered.
func equalFixedGuardValues(left, right any) bool {
	switch want := left.(type) {
	case nil:
		return right == nil
	case bool:
		actual, ok := right.(bool)
		return ok && want == actual
	case string:
		actual, ok := right.(string)
		return ok && want == actual
	case json.Number:
		actual, ok := right.(json.Number)
		return ok && want == actual
	case []any:
		actual, ok := right.([]any)
		if !ok || (want == nil) != (actual == nil) || len(want) != len(actual) {
			return false
		}
		for index, value := range want {
			if !equalFixedGuardValues(value, actual[index]) {
				return false
			}
		}
		return true
	case map[string]any:
		actual, ok := right.(map[string]any)
		if !ok || (want == nil) != (actual == nil) || len(want) != len(actual) {
			return false
		}
		for key, value := range want {
			other, exists := actual[key]
			if !exists || !equalFixedGuardValues(value, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
