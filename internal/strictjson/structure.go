package strictjson

import (
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
			key := ""
			if escaped {
				if err := json.Unmarshal(data[start:end], &key); err != nil {
					return 0, errors.New("invalid object key")
				}
			} else {
				key = string(data[start+1 : end-1])
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

// Most NFT objects have one to four fields. Keep their key inventory on the
// stack; larger objects retain an ordinary map with the same exact comparison.
type structureKeys struct {
	small [8]string
	count int
	large map[string]struct{}
}

func (keys *structureKeys) add(key string) bool {
	if keys.large != nil {
		if _, exists := keys.large[key]; exists {
			return false
		}
		keys.large[key] = struct{}{}
		return true
	}
	for _, previous := range keys.small[:keys.count] {
		if previous == key {
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
		keys.large[previous] = struct{}{}
	}
	keys.large[key] = struct{}{}
	return true
}
