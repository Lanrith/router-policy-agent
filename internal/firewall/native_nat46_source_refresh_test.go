package firewall

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func nat46ModeFlushes(t *testing.T, data []byte) (int, int) {
	t.Helper()
	var batch struct {
		Commands []struct {
			Flush map[string]objectReference `json:"flush"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	sources, grants := 0, 0
	for _, command := range batch.Commands {
		for _, ref := range command.Flush {
			if ref.Name == nativeNAT46StaticSourceChannel || ref.Name == nativeNAT46StaticSourceLive {
				sources++
			}
			for _, target := range nativeNAT46TargetGrantRefs() {
				if ref == target {
					grants++
				}
			}
		}
	}
	return sources, grants
}

func TestNAT46SourceTransitionsRevokeOnlyTheirDependentModeCollections(t *testing.T) {
	t.Parallel()
	model, previous, utc, baseline := nat46TargetGrantFixture(t, true)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	source, err := renderer.prepareNativeOwnership(t.Context(), previous.evidence, utc)
	if err != nil {
		t.Fatal(err)
	}
	startup, err := prepareNativeNAT46SourceRefresh(t.Context(), source, nil, 0, model)
	if err != nil {
		t.Fatal(err)
	}
	if sourceCount, grantCount := nat46ModeFlushes(t, startup.batch.data); sourceCount != 3 || grantCount != 8 {
		t.Fatal("startup omitted translated dependent revocations", sourceCount, grantCount)
	}
	if err := validateOwnershipPreparation(t.Context(), startup, utc); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeSourceReceipt(t.Context(), startup); err != nil {
		t.Fatal("mode transition lost its original ownership publication", err)
	}
	steady, err := prepareNativeNAT46SourceRefresh(t.Context(), source, previous, 7, model)
	if err != nil {
		t.Fatal(err)
	}
	if sourceCount, grantCount := nat46ModeFlushes(t, steady.batch.data); sourceCount != 0 || grantCount != 0 {
		t.Fatal("unchanged source needlessly revoked independently current projections")
	}
	shorter := *source
	shorter.timeouts = append([]int(nil), source.timeouts...)
	shorter.timeouts[len(shorter.timeouts)-1]--
	snapshot, err := shorter.evidence.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	shorter.batch.data, err = shorter.expectedData(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	shorter.digest = sha256.Sum256(shorter.batch.data)
	shrunk, err := prepareNativeNAT46SourceRefresh(t.Context(), &shorter, previous, 7, model)
	if err != nil {
		t.Fatal(err)
	}
	if sourceCount, grantCount := nat46ModeFlushes(t, shrunk.batch.data); sourceCount != 0 || grantCount != 8 || !shrunk.withdrawNativeIDs {
		t.Fatal("individual shrink failed to revoke grants or revoked unrelated source geometry")
	}
	if err := validateOwnershipPreparation(t.Context(), shrunk, utc); err != nil {
		t.Fatal(err)
	}
	epochWindow := *source
	epochWindow.epochTimeout--
	epochWindow.batch.data, err = epochWindow.expectedData(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	epochWindow.digest = sha256.Sum256(epochWindow.batch.data)
	for _, transition := range []struct {
		prepared *preparedOwnership
		observed uint32
	}{{&epochWindow, 7}, {source, 0}} {
		bounded, err := prepareNativeNAT46SourceRefresh(t.Context(), transition.prepared, previous, transition.observed, model)
		if err != nil {
			t.Fatal(err)
		}
		if sourceCount, grantCount := nat46ModeFlushes(t, bounded.batch.data); sourceCount != 3 || grantCount != 8 {
			t.Fatal("epoch shrink or a source gap retained dependent translated evidence")
		}
		if err := validateOwnershipPreparation(t.Context(), bounded, utc); err != nil {
			t.Fatal(err)
		}
	}
	if sourceCount, grantCount := nat46ModeFlushes(t, source.batch.data); sourceCount != 0 || grantCount != 0 || source.nat46SourceModel != nil {
		t.Fatal("translated preparation changed its caller's ordinary native inventory")
	}
	for _, validate := range []func([]byte) error{validateBatch, func(data []byte) error { return validateGuardBatch(t.Context(), data) }} {
		if validate(startup.batch.data) == nil {
			t.Fatal("generic mutation admitted translated source mode")
		}
	}
}

func TestNAT46SourceModeRequiresOriginalModelReceiptAndEpoch(t *testing.T) {
	t.Parallel()
	model, previous, utc, baseline := nat46TargetGrantFixture(t, true)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	source, err := renderer.prepareNativeOwnership(t.Context(), previous.evidence, utc)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeNAT46SourceRefresh(t.Context(), source, previous, 7, model)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing model", "foreign model", "missing receipt", "changed observed epoch", "legacy source", "foreign previous episode"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			changed := *prepared
			switch name {
			case "missing model":
				changed.nat46SourceModel = nil
			case "foreign model":
				ownedModel := *model
				ownedModel.baselineHash = strings.Repeat("a", 64)
				changed.nat46SourceModel = &ownedModel
			case "missing receipt":
				changed.nat46Previous = nil
			case "changed observed epoch":
				changed.nat46ObservedEpoch = 8
			case "legacy source":
				changed.nativeSources = false
			case "foreign previous episode":
				ownedPrevious := *previous
				evidence, changedErr := previous.evidence.InEpoch(t.Context(), 8)
				if changedErr != nil {
					t.Fatal(changedErr)
				}
				ownedPrevious.evidence = evidence
				changed.nat46Previous = &ownedPrevious
			}
			if err := validateOwnershipPreparation(t.Context(), &changed, utc); err == nil {
				t.Fatal("changed source transition proof accepted")
			}
		})
	}
	if _, err := prepareNativeNAT46SourceRefresh(t.Context(), prepared, previous, 7, model); err == nil {
		t.Fatal("source mode wrapped an already selected transition")
	}
}

func TestNAT46OwnershipRevocationKeepsOrdinaryNativeAndConfigurationObjectsSeparate(t *testing.T) {
	t.Parallel()
	model, _, _, _ := nat46TargetGrantFixture(t, true)
	ordinary, err := prepareNativeOwnershipClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	translated, err := prepareNativeNAT46OwnershipClear(t.Context(), model)
	if err != nil {
		t.Fatal(err)
	}
	var first, second struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(ordinary.batch.data, &first) != nil || json.Unmarshal(translated.batch.data, &second) != nil || len(first.Commands) != 33 || len(second.Commands) != 44 {
		t.Fatal("source revocation changed its fixed selected inventory", len(first.Commands), len(second.Commands))
	}
	if sourceCount, grantCount := nat46ModeFlushes(t, translated.batch.data); sourceCount != 3 || grantCount != 8 {
		t.Fatal("translated source revocation omitted dependent collections")
	}
	if !translated.batch.startedAt.IsZero() || !translated.batch.preparedAt.IsZero() || !translated.batch.startBefore.IsZero() || translated.nat46Previous != nil {
		t.Fatal("revocation invented a clock or positive source receipt")
	}
	for _, name := range []string{configurationEpochSet, configurationEpochMap, nativeNAT46StaticChannel} {
		if strings.Contains(string(translated.batch.data), name) {
			t.Fatal("source revocation changed independently owned configuration", name)
		}
	}
	if err := validateOwnershipPreparation(t.Context(), translated, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeSourceReceipt(t.Context(), translated); err == nil {
		t.Fatal("revocation minted a positive source receipt")
	}
	if _, err := translated.evidence.Snapshot(t.Context()); err == nil {
		t.Fatal("revocation contained original positive ownership evidence")
	}
}
