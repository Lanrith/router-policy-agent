// Package strictjson rejects ambiguous JSON at policy trust boundaries.
package strictjson_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const legacyMaximumDepth = 32

// Decode accepts one bounded JSON value, without duplicate keys, invalid UTF-8,
// unknown struct fields, excessive nesting, or trailing input.
func legacyStrictDecode(data []byte, target any, limit int) error {
	if len(data) == 0 || len(data) > limit || limit <= 0 {
		return errors.New("strictjson: invalid input size")
	}
	if !utf8.Valid(data) {
		return errors.New("strictjson: invalid utf-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := legacyStructureScan(decoder, 0); err != nil {
		return fmt.Errorf("strictjson: invalid structure: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("strictjson: trailing input")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		// Do not reproduce attacker-controlled keys or values in diagnostics.
		return errors.New("strictjson: value does not match schema")
	}
	return nil
}

func legacyStructureScan(decoder *json.Decoder, depth int) error {
	if depth > legacyMaximumDepth {
		return errors.New("nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("invalid token")
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errors.New("invalid object key")
			}
			key, isString := keyToken.(string)
			if !isString || seen[key] {
				return errors.New("duplicate or invalid object key")
			}
			seen[key] = true
			if err := legacyStructureScan(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := legacyStructureScan(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return errors.New("invalid closing delimiter")
	}
	isObjectEnd := delimiter == '{' && closing == json.Delim('}')
	isArrayEnd := delimiter == '[' && closing == json.Delim(']')
	if !isObjectEnd && !isArrayEnd {
		return errors.New("unmatched delimiter")
	}
	return nil
}
