package firewall

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func callbackTargetListingFixture(t *testing.T) (*nativeNAT64CallbackModel, guardChanges, *guardTableObservation, *guardTableObservation) {
	t.Helper()
	prepared, f := preparedCallbackGrantFixture(t)
	baseline, _, _ := callbackPolicyFixture(t)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	source, err := renderer.prepareNativeOwnership(t.Context(), f.receipt.evidence, prepared.batch.preparedAt)
	if err != nil {
		t.Fatal(err)
	}
	var ownership guardChanges
	if err := json.Unmarshal(source.batch.data, &ownership); err != nil {
		t.Fatal(err)
	}
	grants, err := decodePreparedGuardChanges(prepared)
	if err != nil {
		t.Fatal(err)
	}
	inet := &guardTableObservation{sets: map[string]listedSet{}}
	netdev := &guardTableObservation{sets: map[string]listedSet{}}
	for _, ref := range nativeNAT64CallbackGrantRefs(prepared.nat64Callbacks) {
		observation := inet
		if ref.Family == "netdev" {
			observation = netdev
		}
		observation.sets[ref.Name] = listedSet{}
	}
	for _, command := range append(ownership.Commands, grants.Commands...) {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Name != ownershipEpochSet && element.Name != ownership6Set && !bytes.HasPrefix([]byte(element.Name), []byte("native_n64_0_callback_to")) {
			continue
		}
		observation := inet
		if element.Family == "netdev" {
			observation = netdev
		}
		values := []json.RawMessage{}
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
	return f.model, idGrantInput(t, "lan13", "02:00:00:00:00:13", "10.251.0.20", 43), inet, netdev
}

func TestNAT64CallbackInspectionRequiresRecipientScopeEpochAndMirrors(t *testing.T) {
	t.Parallel()
	model, logical, inet, netdev := callbackTargetListingFixture(t)
	if count, err := model.inspectTargetGrants(t.Context(), logical, inet, netdev); err != nil || count != 4 {
		t.Fatal("original callback grants failed independent observation", count, err)
	}
	for _, family := range []string{"inet", "netdev"} {
		for _, name := range []string{"alias", "wire peer", "listener", "epoch", "timeout", "missing mirror", "foreign collection", "missing target", "wrong target MAC", "wrong target interface", "missing logical", "chained caller", "wrong caller class", "replaced original"} {
			t.Run(family+"/"+name, func(t *testing.T) {
				model, logical, inet, netdev := callbackTargetListingFixture(t)
				observation := inet
				if family == "netdev" {
					observation = netdev
				}
				switch name {
				case "alias":
					replaceNAT46ListedValue(t, observation, "native_n64_0_callback_to4_tcp", `"10.251.0.20"`, `"10.251.0.21"`)
				case "wire peer":
					replaceNAT46ListedValue(t, observation, "native_n64_0_callback_to6_tcp", `"fdca:1a2b:e064::af0:a"`, `"fdca:1a2b:e064::af0:b"`)
				case "listener":
					replaceNAT46ListedValue(t, observation, "native_n64_0_callback_to4_tcp", `6053`, `6054`)
				case "epoch":
					replaceNAT46ListedValue(t, observation, "native_n64_0_callback_to4_tcp", `"0:1c00"`, `"0:2000"`)
				case "timeout":
					replaceNAT46ListedValue(t, observation, "native_n64_0_callback_to4_tcp", `"timeout":43`, `"timeout":44`)
				case "missing mirror":
					observation.sets["native_n64_0_callback_to4_tcp"] = listedSet{}
				case "foreign collection":
					observation.sets["native_n46_to4_tcp"] = observation.sets["native_n64_0_callback_to4_tcp"]
					delete(observation.sets, "native_n64_0_callback_to4_tcp")
				case "missing target":
					inet.sets[ownership6Set] = listedSet{}
				case "wrong target MAC":
					replaceNAT46ListedValue(t, inet, ownership6Set, `"02:00:00:00:00:13"`, `"02:00:00:00:00:14"`)
				case "wrong target interface":
					replaceNAT46ListedValue(t, inet, ownership6Set, `"lan13"`, `"lan10"`)
				case "missing logical":
					logical.Commands = nil
				case "chained caller", "wrong caller class":
					peer := "10.251.0.21"
					if name == "wrong caller class" {
						peer = "8.8.8.8"
					}
					for index := range logical.Commands {
						for row, raw := range logical.Commands[index].Add.Element.Values {
							logical.Commands[index].Add.Element.Values[row] = bytes.ReplaceAll(raw, []byte("10.240.0.10"), []byte(peer))
						}
					}
				case "replaced original":
					changed := *model
					model.callback.grants = &changed
				}
				if _, err := model.inspectTargetGrants(t.Context(), logical, inet, netdev); err == nil {
					t.Fatal("changed callback observation accepted")
				}
			})
		}
	}
}

func TestNAT64CallbackSourceTransitionsRevokeGrantsWithoutPositiveReadiness(t *testing.T) {
	t.Parallel()
	prepared, f := preparedCallbackGrantFixture(t)
	f.readiness.ready = false
	revocation, err := prepareNativeNAT64OwnershipClear(t.Context(), f.model.callback.native)
	if err != nil {
		t.Fatal(err)
	}
	baseline, _, _ := callbackPolicyFixture(t)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	source, err := renderer.prepareNativeOwnership(t.Context(), f.receipt.evidence, prepared.batch.preparedAt)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := prepareNativeNAT64SourceRefresh(t.Context(), source, nil, 0, f.model.callback.native)
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []*preparedOwnership{revocation, refresh} {
		if err := validateOwnershipPreparation(t.Context(), transition, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		var changes guardChanges
		if err := json.Unmarshal(transition.batch.data, &changes); err != nil {
			t.Fatal(err)
		}
		for _, ref := range nativeNAT64CallbackGrantRefs(prepared.nat64Callbacks) {
			count := 0
			for _, command := range changes.Commands {
				if command.Flush != nil && command.Flush.Set == ref {
					count++
				}
				if command.Add != nil && command.Add.Element.Name == ref.Name {
					t.Fatal("source transition renewed callback grants")
				}
			}
			if count != 1 {
				t.Fatal("source transition omitted exact callback revocation", ref, count)
			}
		}
		changed := *transition
		changed.nat64Callbacks = nil
		if err := validateOwnershipPreparation(t.Context(), &changed, time.Now().UTC()); err == nil {
			t.Fatal("callback source transition lost original model")
		}
	}
}
