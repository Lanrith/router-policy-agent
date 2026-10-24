package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
)

// Freeze only independently compiled code-owned expectations, before exposing
// an immutable layout to concurrent readers. No kernel listing, observed lease
// or runtime receipt supplies any cached field. Layout construction must finish
// before this call; selecting another mode requires a fresh construction.
func (layout *guardLayout) freezeInspectionSchemas(ctx context.Context) error {
	if ctx == nil || layout == nil || layout.inspectionSchemas != nil {
		return errors.New("firewall: missing or already frozen inspection layout")
	}
	compiled := map[string]*guardTableSchema{}
	for _, family := range []string{"inet", "netdev"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		schema, err := layout.schema(family)
		if err != nil {
			return err
		}
		schema.encoded = map[string]*guardCompiledFields{}
		for _, item := range []struct {
			kind    string
			headers map[string]map[string]any
		}{{"set", schema.sets}, {"map", schema.maps}, {"chain", schema.chains}} {
			for name, header := range item.headers {
				if err := schema.freezeFields(ctx, item.kind+"/"+name, header); err != nil {
					return err
				}
			}
		}
		for chain, rules := range schema.rules {
			for index, expressions := range rules {
				header := map[string]any{"family": family, "table": ownedTable, "chain": chain, "expr": expressions}
				if err := schema.freezeFields(ctx, "rule/"+chain+"/"+strconv.Itoa(index), header); err != nil {
					return err
				}
			}
		}
		compiled[family] = schema
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	layout.inspectionSchemas = compiled
	return nil
}

func (schema *guardTableSchema) freezeFields(ctx context.Context, key string, header map[string]any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fields := &guardCompiledFields{encoded: map[string][]byte{}, values: map[string]any{}}
	for name, value := range header {
		encoded, err := json.Marshal(value)
		if err != nil {
			return errors.New("firewall: invalid compiled inspection field")
		}
		value, err = fixedGuardValue(encoded)
		if err != nil {
			return err
		}
		encoded, err = json.Marshal(value)
		if err != nil {
			return errors.New("firewall: invalid normalized inspection field")
		}
		fields.encoded[name], fields.values[name] = encoded, value
	}
	schema.encoded[key] = fields
	return nil
}
