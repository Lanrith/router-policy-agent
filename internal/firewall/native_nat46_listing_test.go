package firewall

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"
)

func TestNAT46WholeInspectionRetainsStrictJSONAndExactNativeObjects(t *testing.T) {
	t.Parallel()
	layout, data := nat46PublicationListingFixture(t)
	contract := reviewedRulesetFixture(t)
	if _, err := contract.inspect(t.Context(), layout, data); err != nil {
		t.Fatal("complete native positive fixture failed inspection", err)
	}
	for _, test := range []struct {
		name, before, after string
	}{
		{"root case", `"nftables":`, `"NFTables":`},
		{"root duplicate", `{"nftables":`, `{"nftables":[],"nftables":`},
		{"escaped root duplicate", `{"nftables":`, `{"nft\u0061bles":[],"nftables":`},
		{"extra root field", `{"nftables":`, `{"unreviewed":true,"nftables":`},
		{"expression duplicate", `"op":"=="`, `"op":"==","op":"=="`},
		{"expression escaped duplicate", `"op":"=="`, `"op":"==","o\u0070":"=="`},
		{"duplicate verdict", `"return":null`, `"return":null,"return":null`},
		{"extra null rule field", `"expr":`, `"unreviewed":null,"expr":`},
		{"invalid UTF-8", `"router_policy_agent"`, "\"router_policy_\xffagent\""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			changed := bytes.ReplaceAll(data, []byte(test.before), []byte(test.after))
			if bytes.Equal(changed, data) {
				t.Fatal("mutation missed its intended field")
			}
			if _, err := contract.inspect(t.Context(), layout, changed); err == nil {
				t.Fatal("invalid complete native listing was accepted")
			}
		})
	}
	if _, err := contract.inspect(t.Context(), layout, append(bytes.Clone(data), []byte(` {}`)...)); err == nil {
		t.Fatal("trailing input was accepted")
	}
}

func nat46PublicationListingFixture(t *testing.T) (*guardLayout, []byte) {
	t.Helper()
	layout, _ := nat46PublicationLayoutFixture(t)
	objects := []map[string]any{{"metainfo": map[string]any{"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}}}
	objects = append(objects, reviewedNativeObjects(t)...)
	for _, family := range []string{"inet", "netdev"} {
		schema, err := layout.schema(family)
		if err != nil {
			t.Fatal(err)
		}
		_, permanent, err := layout.nat46Sources().staticInventory(t.Context(), family)
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, map[string]any{"table": map[string]any{"family": family, "name": ownedTable, "handle": 1}})
		handle := 2
		for _, item := range []struct {
			kind    string
			headers map[string]map[string]any
		}{{"chain", schema.chains}, {"set", schema.sets}, {"map", schema.maps}} {
			for name, original := range item.headers {
				header := maps.Clone(original)
				header["handle"] = handle
				handle++
				if len(permanent[name]) != 0 {
					header["elem"] = permanent[name]
				}
				objects = append(objects, map[string]any{item.kind: header})
			}
		}
		for name, rules := range schema.rules {
			for _, expressions := range rules {
				objects = append(objects, map[string]any{"rule": map[string]any{"family": family, "table": ownedTable, "chain": name, "handle": handle, "expr": expressions}})
				handle++
			}
		}
	}
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	return layout, data
}
