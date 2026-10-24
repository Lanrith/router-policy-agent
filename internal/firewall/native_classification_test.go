package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestNativeClassifierMirrorsKeepHistoryAndPreparationFence(t *testing.T) {
	t.Parallel()
	renderer, input, _, _ := renderFixture(t)
	logical, err := renderer.prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	base, err := prepareClassifiedGuards(t.Context(), logical, guardClassificationFixture())
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(base.batch.data)
	native, err := prepareNativeGuards(t.Context(), base)
	if err != nil || validatePreparedGuardBatch(t.Context(), native) != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, base.batch.data) || native.batch.startedAt != base.batch.startedAt || native.batch.preparedAt != base.batch.preparedAt || native.batch.startBefore != base.batch.startBefore {
		t.Fatal("physical classification changed the original grant age or caller-owned batch")
	}
	if validateMappedGuardBatch(t.Context(), native.batch.data, native.classification, nil) == nil || validateBatch(native.batch.data) == nil {
		t.Fatal("generic mutation admitted native physical classification")
	}
	seal, err := prepareGuardSeal(t.Context(), guardClassificationFixture())
	if err != nil {
		t.Fatal(err)
	}
	native, err = prepareNativeGuards(t.Context(), seal)
	if err != nil || validateGuardSeal(t.Context(), native) != nil {
		t.Fatal(err)
	}
	commands, err := decodeGuardChanges(native.batch.data)
	if err != nil {
		t.Fatal(err)
	}
	mirrors := 0
	for _, command := range commands.Commands {
		if command.Add != nil && command.Add.Element.Family == "netdev" && (command.Add.Element.Name == classified4Set || command.Add.Element.Name == classified6Set) {
			mirrors++
		}
	}
	if mirrors != 2 {
		t.Fatal("missing fixed physical address mirrors")
	}
	if err := (&guardInventory{native: false}).checkPreparedReplacement(t.Context(), native); err == nil {
		t.Fatal("native publication admitted to legacy geometry")
	}
}

func TestNativeClassifierMirrorsRejectTamperingAndCancellation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing", "wrong address", "wrong family", "permanent flush", "duplicate", "native flag"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base, err := prepareGuardSeal(t.Context(), guardClassificationFixture())
			if err != nil {
				t.Fatal(err)
			}
			native, err := prepareNativeGuards(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeGuardChanges(native.batch.data)
			if err != nil {
				t.Fatal(err)
			}
			last := -1
			for index, command := range decoded.Commands {
				if command.Add != nil && command.Add.Element.Family == "netdev" && command.Add.Element.Name == classified6Set {
					last = index
				}
			}
			if last < 0 {
				t.Fatal("missing native classifier")
			}
			switch name {
			case "missing":
				decoded.Commands = append(decoded.Commands[:last], decoded.Commands[last+1:]...)
			case "wrong address":
				decoded.Commands[last].Add.Element.Values[0] = json.RawMessage(`"fdca:1a2b:3::dead"`)
			case "wrong family":
				decoded.Commands[last].Add.Element.Family = "inet"
			case "permanent flush":
				decoded.Commands = append(decoded.Commands, change{Flush: &setChange{Set: objectReference{Family: "netdev", Table: ownedTable, Name: classified4Set}}})
			case "duplicate":
				decoded.Commands = append(decoded.Commands, decoded.Commands[last])
			case "native flag":
				native.native = false
			}
			native.batch.data, err = json.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := validatePreparedGuardBatch(t.Context(), native); err == nil {
				t.Fatal("tampered native classifier accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	base, err := prepareGuardSeal(t.Context(), guardClassificationFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeGuards(ctx, base); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
