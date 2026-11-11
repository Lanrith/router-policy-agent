package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// guardInventory is a verified observation of our fixed objects, not fresh
// authorization, boot restoration, or a fence against another privileged writer.
type guardInventory struct {
	native            bool
	sourceEpoch       uint32
	cohort            []string
	addresses4        []netip.Addr
	addresses6        []netip.Addr
	managedInterfaces []string
	translationPaths  []deviceTranslationPath
	nat46Model        *nativeNAT46Model
	leases            int
}

type guardListings struct {
	inet   []byte
	netdev []byte
}

type guardTableObservation struct {
	sets map[string]listedSet
}

func (layout *guardLayout) inspect(ctx context.Context, listings guardListings) (*guardInventory, error) {
	if ctx == nil || layout == nil || len(layout.managedInterfaces) == 0 {
		return nil, errors.New("firewall: missing guarded inspection dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inet, err := layout.inspectTable(ctx, "inet", listings.inet)
	if err != nil {
		return nil, err
	}
	netdev, err := layout.inspectTable(ctx, "netdev", listings.netdev)
	if err != nil {
		return nil, err
	}
	return layout.inspectObservations(ctx, inet, netdev)
}

// Whole-profile inspection already validated the enclosing JSON. Reusing its
// immutable object slices avoids encoding and rescanning both helper tables.
// Exact objects, rule order, handles and all dynamic relations are still
// checked below by the same fixed schema and independent inventory inspector.
func (layout *guardLayout) inspectObjectTables(ctx context.Context, tables map[string][]json.RawMessage) (*guardInventory, error) {
	inet, err := layout.inspectTableObjects(ctx, "inet", tables["inet"])
	if err != nil {
		return nil, err
	}
	netdev, err := layout.inspectTableObjects(ctx, "netdev", tables["netdev"])
	if err != nil {
		return nil, err
	}
	return layout.inspectObservations(ctx, inet, netdev)
}

func (layout *guardLayout) inspectObservations(ctx context.Context, inet, netdev *guardTableObservation) (*guardInventory, error) {
	cohort, err := listedGuardMACs(inet.sets[cohortSet].Elements)
	if err != nil {
		return nil, err
	}
	other, err := listedGuardMACs(netdev.sets[cohortSet].Elements)
	if err != nil || !slices.Equal(cohort, other) {
		return nil, errors.New("firewall: permanent guard cohorts differ")
	}
	addresses4, err := listedGuardAddresses(ctx, inet.sets[classified4Set].Elements, true)
	if err != nil {
		return nil, err
	}
	addresses6, err := listedGuardAddresses(ctx, inet.sets[classified6Set].Elements, false)
	if err != nil {
		return nil, err
	}
	inventory := &guardInventory{
		native: layout.native != nil, cohort: cohort, addresses4: addresses4, addresses6: addresses6,
		managedInterfaces: slices.Clone(layout.managedInterfaces),
		translationPaths:  slices.Clone(layout.translationPaths),
	}
	if sources := layout.nat46Sources(); sources != nil {
		inventory.nat46Model = sources.model
	}
	if err := layout.inspectOwnership(ctx, inet, netdev); err != nil {
		return nil, err
	}
	if layout.native != nil {
		for _, item := range []struct {
			name      string
			addresses []netip.Addr
			ipv4      bool
		}{{classified4Set, addresses4, true}, {classified6Set, addresses6, false}} {
			physical, err := listedGuardAddresses(ctx, netdev.sets[item.name].Elements, item.ipv4)
			if err != nil || !slices.Equal(physical, item.addresses) {
				return nil, errors.New("firewall: native physical classification differs from its original history")
			}
		}
		if err := layout.inspectNativeSources(ctx, inet, netdev); err != nil {
			return nil, err
		}
	}
	if layout.ownership {
		if err := inspectConfigurationEpoch(ctx, inet); err != nil {
			return nil, err
		}
		for _, configuration := range []bool{false, true} {
			if err := inspectEpochChannel(ctx, configuration, inet, netdev); err != nil {
				return nil, err
			}
		}
	}
	if layout.ownership {
		epochs, err := listedGuardLeases(ctx, inet.sets[ownershipEpochSet].Elements)
		if err != nil {
			return nil, err
		}
		if len(epochs) == 1 {
			var epoch struct {
				Value   uint32 `json:"val"`
				Timeout int    `json:"timeout"`
			}
			if err := decodeNested(epochs[0], "elem", &epoch, []string{"val", "timeout"}); err != nil {
				return nil, err
			}
			inventory.sourceEpoch = epoch.Value >> policy.OwnershipRuleBits
		}
	}
	if err := layout.inspectNAT46Publications(ctx, inet, netdev); err != nil {
		return nil, err
	}
	if err := inventory.checkMirrors(ctx, inet, netdev); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return inventory, nil
}

func (layout *guardLayout) inspectTable(
	ctx context.Context,
	family string,
	data []byte,
) (*guardTableObservation, error) {
	objects, err := decodeRulesetListing(ctx, data)
	if err != nil {
		return nil, err
	}
	return layout.inspectTableObjects(ctx, family, objects)
}

func (layout *guardLayout) inspectTableObjects(ctx context.Context, family string, objects []json.RawMessage) (*guardTableObservation, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing fixed table inspection context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema, err := layout.schema(family)
	if err != nil {
		return nil, err
	}
	count := 2 + len(schema.sets) + len(schema.maps) + len(schema.chains)
	for _, rules := range schema.rules {
		count += len(rules)
	}
	if len(objects) != count {
		return nil, errors.New("firewall: guarded object inventory differs")
	}
	if err := verifyOwnedListingHeader(objects[:2], family); err != nil {
		return nil, err
	}
	observed := &guardTableObservation{sets: map[string]listedSet{}}
	handles, chains, rules := map[uint64]bool{}, map[string]bool{}, map[string]int{}
	for _, raw := range objects[2:] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kind, fields, err := guardObjectFromListing(raw)
		if err != nil {
			return nil, err
		}
		var expected map[string]any
		name, key := "", "name"
		if kind == "rule" {
			key = "chain"
		}
		if err := json.Unmarshal(fields[key], &name); err != nil {
			return nil, errors.New("firewall: invalid guarded object identity")
		}
		switch kind {
		case "set":
			expected = schema.sets[name]
			if _, exists := observed.sets[name]; exists {
				return nil, errors.New("firewall: duplicate guarded set")
			}
		case "map":
			expected = schema.maps[name]
			if _, exists := observed.sets[name]; exists {
				return nil, errors.New("firewall: duplicate guarded map")
			}
		case "chain":
			expected = schema.chains[name]
			if chains[name] {
				return nil, errors.New("firewall: duplicate guarded chain")
			}
			chains[name] = true
		case "rule":
			if rules[name] >= len(schema.rules[name]) {
				return nil, errors.New("firewall: unexpected guarded rule")
			}
			expected = map[string]any{"family": family, "table": ownedTable,
				"chain": name, "expr": schema.rules[name][rules[name]]}
			rules[name]++
		default:
			return nil, errors.New("firewall: unexpected guarded object")
		}
		compiledKey := kind + "/" + name
		if kind == "rule" {
			compiledKey += "/" + strconv.Itoa(rules[name]-1)
		}
		handle, err := checkGuardObjectWithFields(fields, expected, kind == "set" || kind == "map", schema.encoded[compiledKey])
		if err != nil {
			return nil, err
		}
		if handles[handle] {
			return nil, errors.New("firewall: duplicate guarded object handle")
		}
		handles[handle] = true
		if kind == "set" || kind == "map" {
			var set listedSet
			target := any(&struct {
				Set *listedSet `json:"set"`
			}{Set: &set})
			if kind == "map" {
				target = &struct {
					Map *listedSet `json:"map"`
				}{Map: &set}
			}
			if err := json.Unmarshal(raw, target); err != nil {
				return nil, errors.New("firewall: guarded set decoding failed")
			}
			if uint64(len(set.Elements)) > set.Size {
				return nil, errors.New("firewall: guarded set capacity exceeded")
			}
			observed.sets[name] = set
		}
	}
	for name := range schema.chains {
		if !chains[name] || rules[name] != len(schema.rules[name]) {
			return nil, errors.New("firewall: guarded chain or rules missing")
		}
	}
	if len(observed.sets) != len(schema.sets)+len(schema.maps) {
		return nil, errors.New("firewall: guarded sets missing")
	}
	return observed, nil
}

func guardObject(raw json.RawMessage) (string, map[string]json.RawMessage, error) {
	if err := strictjson.Object(raw, nil, []string{"set", "map", "chain", "rule"}, maximumOutput); err != nil {
		return "", nil, err
	}
	return guardObjectFromListing(raw)
}

// Only callers whose complete envelope already passed strictjson may use this
// path. It retains exact kinds and fields without walking the same expression
// subtree for duplicate keys again. Standalone inspection uses guardObject.
func guardObjectFromListing(raw json.RawMessage) (string, map[string]json.RawMessage, error) {
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &object); err != nil || len(object) != 1 {
		return "", nil, errors.New("firewall: exact guarded object required")
	}
	for kind, value := range object {
		switch kind {
		case "set", "map", "chain", "rule":
		default:
			return "", nil, errors.New("firewall: unexpected guarded object kind")
		}
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(value, &fields); err != nil || fields == nil {
			return "", nil, errors.New("firewall: guarded object fields required")
		}
		return kind, fields, nil
	}
	return "", nil, errors.New("firewall: guarded object missing")
}

func checkGuardObject(fields map[string]json.RawMessage, expected map[string]any, hasElements bool) (uint64, error) {
	if expected == nil {
		return 0, errors.New("firewall: guarded object outside fixed schema")
	}
	required := make([]string, 0, len(expected)+1)
	for key := range expected {
		required = append(required, key)
	}
	required = append(required, "handle")
	optional := []string{}
	if hasElements {
		optional = append(optional, "elem")
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return 0, errors.New("firewall: guarded header encoding failed")
	}
	if err := strictjson.Object(data, required, optional, maximumOutput); err != nil {
		return 0, err
	}
	return checkGuardObjectFromListing(fields, expected, hasElements)
}

// The enclosing listing supplied strict syntax and duplicate-key validation.
// This still requires every exact code-owned header key, rejects null or extra
// fields, checks a unique positive handle, and compares complete expressions.
func checkGuardObjectFromListing(fields map[string]json.RawMessage, expected map[string]any, hasElements bool) (uint64, error) {
	return checkGuardObjectWithFields(fields, expected, hasElements, nil)
}

func checkGuardObjectWithFields(fields map[string]json.RawMessage, expected map[string]any, hasElements bool, compiled *guardCompiledFields) (uint64, error) {
	if expected == nil {
		return 0, errors.New("firewall: guarded object outside fixed schema")
	}
	for key := range expected {
		if fields[key] == nil {
			return 0, errors.New("firewall: required guarded field missing")
		}
	}
	for key, value := range fields {
		_, codeOwned := expected[key]
		if !codeOwned && key != "handle" && (!hasElements || key != "elem") || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return 0, errors.New("firewall: unexpected or null guarded object field")
		}
	}
	var handle uint64
	if err := json.Unmarshal(fields["handle"], &handle); err != nil || handle == 0 {
		return 0, errors.New("firewall: invalid guarded object handle")
	}
	delete(fields, "handle")
	delete(fields, "elem")
	if compiled != nil {
		if len(compiled.encoded) != len(expected) || compiled.values != nil && len(compiled.values) != len(expected) {
			return 0, errors.New("firewall: compiled inspection field inventory differs")
		}
		for name := range expected {
			wanted, exists := compiled.encoded[name]
			if !exists {
				return 0, errors.New("firewall: compiled inspection field missing")
			}
			var value any
			if compiled.values != nil {
				value, exists = compiled.values[name]
				if !exists {
					return 0, errors.New("firewall: compiled inspection value missing")
				}
			}
			actual := bytes.TrimSpace(fields[name])
			if bytes.Equal(actual, wanted) {
				continue
			}
			if compiled.values != nil {
				observed, err := fixedGuardValue(actual)
				if err != nil || !equalFixedGuardValues(value, observed) {
					return 0, errors.New("firewall: fixed guard field differs from compiled expectation")
				}
				continue
			}
			canonical, err := canonicalFixedGuardJSON(actual)
			if err != nil || !bytes.Equal(canonical, wanted) {
				return 0, errors.New("firewall: fixed guard field differs from compiled expectation")
			}
		}
		return handle, nil
	}
	actual, err := json.Marshal(fields)
	if err != nil {
		return 0, errors.New("firewall: guarded header normalization failed")
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return 0, errors.New("firewall: fixed guard schema encoding failed")
	}
	actual, err = canonicalFixedGuardJSON(actual)
	if err != nil {
		return 0, err
	}
	want, err = canonicalFixedGuardJSON(want)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(actual, want) {
		return 0, errors.New("firewall: fixed guard schema or rule order differs")
	}
	return handle, nil
}

func listedGuardMACs(elements []json.RawMessage) ([]string, error) {
	if err := validateMACs(elements); err != nil {
		return nil, err
	}
	macs := make([]string, 0, len(elements))
	for _, raw := range elements {
		var mac string
		if err := json.Unmarshal(raw, &mac); err != nil {
			return nil, errors.New("firewall: invalid guarded mac")
		}
		macs = append(macs, mac)
	}
	slices.Sort(macs)
	return macs, nil
}

func listedGuardAddresses(ctx context.Context, elements []json.RawMessage, ipv4 bool) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(elements))
	seen := map[netip.Addr]bool{}
	for _, raw := range elements {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, errors.New("firewall: canonical classified address required")
		}
		prefix := "/128"
		if ipv4 {
			prefix = "/32"
		}
		address, err := policy.ParseHost(value + prefix)
		if err != nil || address.Is4() != ipv4 || address.String() != value || seen[address] {
			return nil, errors.New("firewall: invalid or duplicate classified address")
		}
		seen[address] = true
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}
