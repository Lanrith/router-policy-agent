package firewall

import (
	"encoding/json"
	"testing"
)

func TestNativeGrantProjectionsPreserveEveryDirectionFamilyAndProtocol(t *testing.T) {
	t.Parallel()
	var logical guardChanges
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	for _, name := range grantSets {
		device, peer := "fdca:1a2b:3::10", "fdca:1a2b::10"
		if ipv4Set(name) {
			device, peer = "10.240.3.10", "10.240.0.10"
		}
		raw, err := json.Marshal(map[string]any{"elem": map[string]any{"timeout": 43, "val": map[string]any{"concat": []any{"lan13", "02:00:00:00:00:01", device, peer, 6053}}}})
		if err != nil {
			t.Fatal(err)
		}
		logical.Commands = append(logical.Commands, guardAdd("inet", name, []json.RawMessage{raw}))
	}
	source, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	base, err := prepareMappedGuards(t.Context(), &preparedBatch{data: source}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	native, err := prepareNativeGuards(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedGuardBatch(t.Context(), native); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeGuardChanges(native.batch.data)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, command := range decoded.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family != "netdev" {
			continue
		}
		nativeSet := false
		for _, ref := range nativeLeaseRefs() {
			if ref.Name == element.Name {
				nativeSet = true
			}
		}
		if !nativeSet {
			continue
		}
		count++
		fields, timeout := nativeSourceTimedTest(t, element.Values[0])
		if len(fields) != 3 || timeout != 43 {
			t.Fatal("projection changed tuple scope or original timeout")
		}
	}
	if count != len(grantSets) {
		t.Fatal("grant direction, family or protocol lost")
	}
	if validateGuardSeal(t.Context(), native) == nil {
		t.Fatal("positive projected grants admitted as a seal")
	}
	for _, name := range []string{"timeout", "peer", "missing flush", "extra lease", "generic flag"} {
		t.Run(name, func(t *testing.T) {
			owned := *native
			owned.batch.data = append([]byte(nil), native.batch.data...)
			changed, err := decodeGuardChanges(owned.batch.data)
			if err != nil {
				t.Fatal(err)
			}
			index := -1
			for i, command := range changed.Commands {
				if command.Add != nil && command.Add.Element.Name == nativeLeaseSet(grantSets[0]) {
					index = i
				}
			}
			if index < 0 {
				t.Fatal("missing native grant")
			}
			switch name {
			case "timeout", "peer":
				var lease map[string]any
				if err := json.Unmarshal(changed.Commands[index].Add.Element.Values[0], &lease); err != nil {
					t.Fatal(err)
				}
				value, ok := lease["elem"].(map[string]any)
				if !ok {
					t.Fatal("missing lease")
				}
				if name == "timeout" {
					value["timeout"] = 44
				} else {
					value["val"] = map[string]any{"concat": []any{"10.240.3.10", "10.240.0.11", 6053}}
				}
				raw, err := json.Marshal(lease)
				if err != nil {
					t.Fatal(err)
				}
				changed.Commands[index].Add.Element.Values[0] = raw
			case "missing flush":
				changed.Commands = append(changed.Commands[:index-1], changed.Commands[index:]...)
			case "extra lease":
				changed.Commands = append(changed.Commands, changed.Commands[index])
			case "generic flag":
				owned.native = false
			}
			owned.batch.data, err = json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if validatePreparedGuardBatch(t.Context(), &owned) == nil {
				t.Fatal("tampered physical grant accepted")
			}
		})
	}
}
