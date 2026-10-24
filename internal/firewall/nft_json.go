package firewall

import (
	"encoding/json"
	"errors"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// One complete strict validation covers every nested key and value. Callers
// still independently enforce their exact operation/object schema and quotas.
func decodeNftablesArray(data []byte, limit int) ([]json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if err := strictjson.Decode(data, &envelope, limit); err != nil {
		return nil, err
	}
	var objects []json.RawMessage
	if len(envelope) != 1 || envelope["nftables"] == nil || json.Unmarshal(envelope["nftables"], &objects) != nil || objects == nil {
		return nil, errors.New("firewall: exact non-null nftables array required")
	}
	return objects, nil
}

// Used only for child values of an already strictly validated NFT envelope.
// The standalone decodeNested path performs its own complete strict check.
func decodeValidatedNested(raw json.RawMessage, key string, target any, keys []string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return errors.New("firewall: nested object required")
	}
	return decodeNestedFields(object, key, target, keys)
}
