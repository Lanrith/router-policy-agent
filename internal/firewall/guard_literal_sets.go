package firewall

import (
	"cmp"
	"encoding/json"
	"errors"
	"slices"
)

// Fixed packet expressions contain anonymous literal sets. nft lists their
// members in kernel order, which need not match source order. Only a literal
// "set" array is unordered; expression sequences, concat fields, ranges and
// command arrays retain their exact order. Complete rows and multiplicity are
// preserved, so sorting cannot unpair an identity, attachment or destination.
// Runtime grant/batch normalization deliberately does not use this function.
func canonicalFixedGuardJSON(data []byte) ([]byte, error) {
	value, err := fixedGuardValue(data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func normalizeGuardLiteralSets(value any) error {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			if err := normalizeGuardLiteralSets(child); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, child := range node {
			if err := normalizeGuardLiteralSets(child); err != nil {
				return err
			}
			rows, literal := child.([]any)
			if key != "set" || !literal {
				continue
			}
			type entry struct {
				key   string
				value any
			}
			entries := make([]entry, len(rows))
			for index, row := range rows {
				encoded, err := json.Marshal(row)
				if err != nil {
					return errors.New("firewall: fixed literal set member encoding failed")
				}
				entries[index] = entry{string(encoded), row}
			}
			slices.SortFunc(entries, func(left, right entry) int { return cmp.Compare(left.key, right.key) })
			for index, item := range entries {
				rows[index] = item.value
			}
		}
	}
	return nil
}
