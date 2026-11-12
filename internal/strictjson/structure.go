package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
)

// The standard library validates the complete JSON grammar first. This walk
// adds only the depth and decoded-key uniqueness checks that json.Valid lacks.
// Scalar values are skipped without allocating Decoder.Token values. Escaped
// object keys still use encoding/json's exact Unicode and surrogate handling.
func validateStructure(data []byte) error {
	if !json.Valid(data) {
		return errors.New("invalid JSON value")
	}
	end, err := structureValue(data, 0, 0)
	if err != nil {
		return err
	}
	if structureSpace(data, end) != len(data) {
		return errors.New("trailing input")
	}
	return nil
}

func structureValue(data []byte, position, depth int) (int, error) {
	if depth > maximumDepth {
		return 0, errors.New("nesting limit exceeded")
	}
	position = structureSpace(data, position)
	if position >= len(data) {
		return 0, errors.New("missing value")
	}
	switch data[position] {
	case '{':
		position = structureSpace(data, position+1)
		keys := structureKeys{}
		for position < len(data) && data[position] != '}' {
			start := position
			end, escaped, err := structureString(data, position)
			if err != nil {
				return 0, err
			}
			key := structureKey{raw: data[start+1 : end-1]}
			if escaped {
				var decoded string
				if err := json.Unmarshal(data[start:end], &decoded); err != nil {
					return 0, errors.New("invalid object key")
				}
				key = structureKey{decoded: decoded}
			}
			if !keys.add(key) {
				return 0, errors.New("duplicate or invalid object key")
			}
			position = structureSpace(data, end)
			if position >= len(data) || data[position] != ':' {
				return 0, errors.New("missing object separator")
			}
			position, err = structureValue(data, position+1, depth+1)
			if err != nil {
				return 0, err
			}
			position = structureSpace(data, position)
			if position < len(data) && data[position] == ',' {
				position = structureSpace(data, position+1)
			}
		}
		if position >= len(data) || data[position] != '}' {
			return 0, errors.New("missing object end")
		}
		return position + 1, nil
	case '[':
		position = structureSpace(data, position+1)
		for position < len(data) && data[position] != ']' {
			var err error
			position, err = structureValue(data, position, depth+1)
			if err != nil {
				return 0, err
			}
			position = structureSpace(data, position)
			if position < len(data) && data[position] == ',' {
				position = structureSpace(data, position+1)
			}
		}
		if position >= len(data) || data[position] != ']' {
			return 0, errors.New("missing array end")
		}
		return position + 1, nil
	case '"':
		end, _, err := structureString(data, position)
		return end, err
	default:
		// json.Valid already checked scalar spelling and number syntax.
		for position < len(data) {
			switch data[position] {
			case ' ', '\t', '\r', '\n', ',', ']', '}':
				return position, nil
			default:
				position++
			}
		}
		return position, nil
	}
}

func structureString(data []byte, position int) (int, bool, error) {
	if position >= len(data) || data[position] != '"' {
		return 0, false, errors.New("invalid string start")
	}
	escaped := false
	for position++; position < len(data); position++ {
		switch data[position] {
		case '\\':
			escaped = true
			position++ // Its spelling was checked by json.Valid.
		case '"':
			return position + 1, escaped, nil
		}
	}
	return 0, false, errors.New("missing string end")
}

func structureSpace(data []byte, position int) int {
	for position < len(data) {
		switch data[position] {
		case ' ', '\t', '\r', '\n':
			position++
		default:
			return position
		}
	}
	return position
}

// Unescaped key spans live only during this synchronous structure walk. They
// avoid allocating an owned string for each repeated key in large listings.
// Escapes still use encoding/json's complete decoded Unicode representation.
// No span is cached or retained in a decoded value; promoted maps own strings.
type structureKey struct {
	raw     []byte
	decoded string
}

func (key structureKey) equal(other structureKey) bool {
	switch {
	case key.raw != nil && other.raw != nil:
		return bytes.Equal(key.raw, other.raw)
	case key.raw != nil:
		return string(key.raw) == other.decoded
	case other.raw != nil:
		return key.decoded == string(other.raw)
	default:
		return key.decoded == other.decoded
	}
}

func (key structureKey) owned() string {
	if key.raw != nil {
		return string(key.raw)
	}
	return key.decoded
}

// Most objects have one to four fields. Keep their key inventory on the stack;
// larger objects retain an ordinary map with the same exact comparison.
type structureKeys struct {
	small [8]structureKey
	count int
	large map[string]struct{}
}

func (keys *structureKeys) add(key structureKey) bool {
	if keys.large != nil {
		owned := key.owned()
		if _, exists := keys.large[owned]; exists {
			return false
		}
		keys.large[owned] = struct{}{}
		return true
	}
	for _, previous := range keys.small[:keys.count] {
		if previous.equal(key) {
			return false
		}
	}
	if keys.count < len(keys.small) {
		keys.small[keys.count] = key
		keys.count++
		return true
	}
	keys.large = make(map[string]struct{}, 2*len(keys.small))
	for _, previous := range keys.small {
		keys.large[previous.owned()] = struct{}{}
	}
	keys.large[key.owned()] = struct{}{}
	return true
}
