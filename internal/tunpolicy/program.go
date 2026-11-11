package tunpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

var mutableSets = map[string]bool{
	"tp_started": true, "tp_history_mac": true, "tp_history4": true, "tp_history6": true,
	"tp_bound4": true, "tp_bound6": true, "tp_dest4": true, "tp_dest6": true,
	"tp_cleanup4": true, "tp_cleanup6": true,
	"tp_grants4": true, "tp_grants6": true, "tp_echo4": true, "tp_echo6": true,
}

// ProgramDigest fingerprints the installed nft program and static data. Only
// runtime handles, counter values and the fixed publisher's set elements are
// excluded. Rule order, hooks, schemas and static selectors remain significant.
// The expected digest must be produced during build qualification, never learned
// from the running router or reconstructed from its current data.
func ProgramDigest(data []byte) (string, error) {
	if len(data) == 0 || len(data) > 16<<20 {
		return "", errors.New("tunpolicy: invalid program listing size")
	}
	// Validate all input, but retain values as raw JSON until mutable element
	// arrays are removed. Expiring bindings can contain tens of thousands of
	// rows; constructing and discarding their object trees adds no integrity.
	var listing struct {
		NFTables []map[string]map[string]json.RawMessage `json:"nftables"`
	}
	if err := strictjson.Decode(data, &listing, 16<<20); err != nil {
		return "", err
	}
	objects := make([]map[string]map[string]any, 0, len(listing.NFTables))
	for _, rawObject := range listing.NFTables {
		object := make(map[string]map[string]any, 1)
		if len(rawObject) != 1 {
			return "", errors.New("tunpolicy: invalid program object")
		}
		if _, metadata := rawObject["metainfo"]; metadata {
			continue
		}
		for kind, raw := range rawObject {
			switch kind {
			case "table", "chain", "rule", "set", "map", "counter":
			default:
				return "", errors.New("tunpolicy: unsupported program object")
			}
			delete(raw, "handle")
			if kind == "set" {
				var identity struct{ Family, Table, Name string }
				for field, target := range map[string]*string{"family": &identity.Family, "table": &identity.Table, "name": &identity.Name} {
					if err := json.Unmarshal(raw[field], target); err != nil {
						return "", err
					}
				}
				owned := identity.Family == "inet" && identity.Table == "lanrith" || identity.Family == "netdev" && identity.Table == "lanrith_identity"
				if owned && mutableSets[identity.Name] {
					delete(raw, "elem")
				}
			}
			encoded, err := json.Marshal(raw)
			if err != nil {
				return "", err
			}
			var value map[string]any
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				return "", err
			}
			object[kind] = value
			if kind == "rule" {
				if expressions, ok := value["expr"].([]any); ok {
					for _, expression := range expressions {
						if item, ok := expression.(map[string]any); ok {
							if counter, ok := item["counter"].(map[string]any); ok {
								delete(counter, "packets")
								delete(counter, "bytes")
							}
						}
					}
				}
			}
			if kind == "counter" {
				delete(value, "packets")
				delete(value, "bytes")
			}
		}
		objects = append(objects, object)
	}
	if len(objects) == 0 {
		return "", errors.New("tunpolicy: empty program listing")
	}
	canonical, err := json.Marshal(objects)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// Positive identifies a publication that requires the pinned program and
// current writer generation. Negative sealing remains available on drift.
func (batch Batch) Positive() bool { return batch.positive }
