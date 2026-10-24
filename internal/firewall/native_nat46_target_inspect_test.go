package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// The listing fixture comes from the actual typed ownership and grant
// producers. Listing it does not manufacture a new opaque source receipt.
func nat46TargetListingFixture(t *testing.T) (*nativeNAT46Model, guardChanges, *guardTableObservation, *guardTableObservation) {
	t.Helper()
	model, publication, utc, baseline := nat46TargetGrantFixture(t, true)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	ownership, err := renderer.prepareNativeOwnership(t.Context(), publication.evidence, utc)
	if err != nil {
		t.Fatal(err)
	}
	var source guardChanges
	if err := json.Unmarshal(ownership.batch.data, &source); err != nil {
		t.Fatal(err)
	}
	logical := idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.250.0.20", 43)
	projected, err := model.projectTargetGrants(t.Context(), logical, publication, utc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inet := &guardTableObservation{sets: map[string]listedSet{}}
	netdev := &guardTableObservation{sets: map[string]listedSet{}}
	for _, command := range append(source.Commands, projected...) {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		observation := inet
		if element.Family == "netdev" {
			observation = netdev
		}
		if element.Name != ownershipEpochSet && element.Name != ownership6Set && !bytes.HasPrefix([]byte(element.Name), []byte("native_n46_to")) {
			continue
		}
		values := make([]json.RawMessage, 0, len(element.Values))
		for _, raw := range element.Values {
			var lease struct {
				Value   json.RawMessage `json:"val"`
				Timeout int             `json:"timeout"`
			}
			if err := decodeNested(raw, "elem", &lease, []string{"val", "timeout"}); err != nil {
				t.Fatal(err)
			}
			listed, err := json.Marshal(map[string]any{"elem": map[string]any{"val": lease.Value, "timeout": lease.Timeout, "expires": lease.Timeout - 1}})
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, listed)
		}
		observation.sets[element.Name] = listedSet{Elements: values}
	}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		observation := inet
		if ref.Family == "netdev" {
			observation = netdev
		}
		if len(observation.sets[ref.Name].Elements) != 1 {
			t.Fatal("positive fixture lost a typed target grant", ref)
		}
	}
	return model, logical, inet, netdev
}

func replaceNAT46ListedValue(t *testing.T, observation *guardTableObservation, name, before, after string) {
	t.Helper()
	set := observation.sets[name]
	changed := false
	for index, raw := range set.Elements {
		next := bytes.ReplaceAll(raw, []byte(before), []byte(after))
		changed = changed || !bytes.Equal(next, raw)
		set.Elements[index] = next
	}
	if !changed {
		t.Fatal("fixture mutation missed its intended value", name, before)
	}
	observation.sets[name] = set
}

func TestNAT46TargetInspectionRequiresCurrentTargetAndCompleteLogicalGrant(t *testing.T) {
	t.Parallel()
	model, logical, inet, netdev := nat46TargetListingFixture(t)
	if count, err := model.inspectTargetGrants(t.Context(), logical, inet, netdev); err != nil || count != 4 {
		t.Fatal("typed target publication failed independent observation", count, err)
	}
	// A recorded remaining expiry never resets the original timeout or grants.
	for _, ref := range nativeNAT46TargetGrantRefs() {
		observation := inet
		if ref.Family == "netdev" {
			observation = netdev
		}
		var row map[string]map[string]any
		if err := json.Unmarshal(observation.sets[ref.Name].Elements[0], &row); err != nil {
			t.Fatal(err)
		}
		row["elem"]["expires"] = 1
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		observation.sets[ref.Name] = listedSet{Elements: []json.RawMessage{raw}}
	}
	if count, err := model.inspectTargetGrants(t.Context(), logical, inet, netdev); err != nil || count != 4 {
		t.Fatal("remaining counters changed fixed grant identity", count, err)
	}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		inet.sets[ref.Name], netdev.sets[ref.Name] = listedSet{}, listedSet{}
	}
	inet.sets[ownershipEpochSet], inet.sets[ownership6Set] = listedSet{}, listedSet{}
	if count, err := model.inspectTargetGrants(t.Context(), guardChanges{}, inet, netdev); err != nil || count != 0 {
		t.Fatal("fixed empty revocation failed inspection", count, err)
	}
}

func TestNAT46TargetInspectionRejectsChangedScopeIdentityEpochAndLifetime(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"inet", "netdev"} {
		for _, test := range []string{
			"epoch", "alias", "raw peer", "wire peer", "port", "timeout", "duplicate", "missing mirror", "missing collection",
			"missing target", "other target", "other target MAC", "other target interface", "short target lifetime", "ambiguous target",
			"missing epoch", "short epoch lifetime", "unaligned epoch", "duplicate epoch", "missing logical grant", "wrong protocol", "from-device only", "different model",
		} {
			t.Run(family+"/"+test, func(t *testing.T) {
				t.Parallel()
				model, logical, inet, netdev := nat46TargetListingFixture(t)
				observation := inet
				if family == "netdev" {
					observation = netdev
				}
				switch test {
				case "epoch":
					replaceNAT46ListedValue(t, observation, "native_n46_to4_tcp", `"0:1c00"`, `"0:2000"`)
				case "alias":
					replaceNAT46ListedValue(t, observation, "native_n46_to4_tcp", `"10.250.0.20"`, `"10.250.0.21"`)
				case "raw peer":
					replaceNAT46ListedValue(t, observation, "native_n46_to4_tcp", `"10.240.0.10"`, `"10.240.0.11"`)
				case "wire peer":
					replaceNAT46ListedValue(t, observation, "native_n46_to6_tcp", `"fdca:1a2b:e046::af0:a"`, `"fdca:1a2b:e046::af0:b"`)
				case "port":
					replaceNAT46ListedValue(t, observation, "native_n46_to4_tcp", `6053`, `6054`)
				case "timeout":
					replaceNAT46ListedValue(t, observation, "native_n46_to4_tcp", `"timeout":43`, `"timeout":44`)
				case "duplicate":
					set := observation.sets["native_n46_to4_tcp"]
					set.Elements = append(set.Elements, set.Elements[0])
					observation.sets["native_n46_to4_tcp"] = set
				case "missing mirror":
					observation.sets["native_n46_to4_tcp"] = listedSet{}
				case "missing collection":
					delete(observation.sets, "native_n46_to4_tcp")
				case "missing target":
					inet.sets[ownership6Set] = listedSet{}
				case "other target":
					replaceNAT46ListedValue(t, inet, ownership6Set, `"fdca:1a2b:3::10"`, `"fdca:1a2b:3::11"`)
				case "other target MAC":
					replaceNAT46ListedValue(t, inet, ownership6Set, `"02:00:00:00:00:13"`, `"02:00:00:00:00:14"`)
				case "other target interface":
					replaceNAT46ListedValue(t, inet, ownership6Set, `"lan13"`, `"lan10"`)
				case "short target lifetime":
					inet.sets[ownership6Set] = listedSet{Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":["lan13","02:00:00:00:00:13","fdca:1a2b:3::10"]},"timeout":20,"expires":19}}`)}}
				case "ambiguous target":
					set := inet.sets[ownership6Set]
					set.Elements = append(set.Elements, bytes.ReplaceAll(set.Elements[0], []byte(`"02:00:00:00:00:13"`), []byte(`"02:00:00:00:00:14"`)))
					inet.sets[ownership6Set] = set
				case "missing epoch":
					inet.sets[ownershipEpochSet] = listedSet{}
				case "short epoch lifetime":
					inet.sets[ownershipEpochSet] = listedSet{Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":7168,"timeout":20,"expires":19}}`)}}
				case "unaligned epoch":
					replaceNAT46ListedValue(t, inet, ownershipEpochSet, `7168`, `7169`)
				case "duplicate epoch":
					set := inet.sets[ownershipEpochSet]
					set.Elements = append(set.Elements, set.Elements[0])
					inet.sets[ownershipEpochSet] = set
				case "missing logical grant":
					logical.Commands = nil
				case "wrong protocol":
					for index := range logical.Commands {
						if logical.Commands[index].Add.Element.Name == "lease_to4_tcp" {
							logical.Commands[index].Add.Element.Name = "lease_to4_udp"
						}
					}
				case "from-device only":
					for index := range logical.Commands {
						if logical.Commands[index].Add.Element.Name == "lease_to4_tcp" {
							logical.Commands[index].Add.Element.Name = "lease_from4_tcp"
						}
					}
				case "different model":
					model.mappings[0].target = model.mappings[0].target.Next()
				}
				if _, err := model.inspectTargetGrants(t.Context(), logical, inet, netdev); err == nil {
					t.Fatal("modified target projection was accepted")
				}
			})
		}
	}
}

func TestNAT46TargetInspectionRejectsMissingDependenciesAndCancellation(t *testing.T) {
	t.Parallel()
	model, logical, inet, netdev := nat46TargetListingFixture(t)
	if _, err := model.inspectTargetGrants(nil, logical, inet, netdev); err == nil { //nolint:staticcheck // Deliberately test the missing-context boundary.
		t.Fatal("missing context accepted")
	}
	if _, err := (*nativeNAT46Model)(nil).inspectTargetGrants(t.Context(), logical, inet, netdev); err == nil {
		t.Fatal("missing model accepted")
	}
	if _, err := model.inspectTargetGrants(t.Context(), logical, nil, netdev); err == nil {
		t.Fatal("missing observation accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := model.inspectTargetGrants(ctx, logical, inet, netdev); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}
