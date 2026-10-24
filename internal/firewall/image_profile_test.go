package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
)

func protectedRulesetListing(t testing.TB) []byte {
	t.Helper()
	objects := []any{map[string]any{"metainfo": map[string]any{
		"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1,
	}}}
	for _, object := range reviewedNativeObjects(t) {
		objects = append(objects, object)
	}
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBuildImageProfileProducesPinnedRuntimeArtifacts(t *testing.T) {
	t.Parallel()
	baseline, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := BuildImageProfile(t.Context(), baseline, protectedRulesetListing(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.Profile) == 0 || len(artifacts.Guards) == 0 || len(artifacts.Guards) > maximumBatch || len(artifacts.Metadata) == 0 {
		t.Fatal("image profile build emitted an empty artifact")
	}
	if bytes.Contains(artifacts.Profile, []byte(`"handle"`)) ||
		bytes.Contains(artifacts.Profile, []byte(`"packets"`)) ||
		bytes.Contains(artifacts.Profile, []byte(`"bytes"`)) {
		t.Fatal("runtime profile retained volatile listing state")
	}
	if bytes.Contains(artifacts.Profile, []byte("schema:")) || bytes.Contains(artifacts.Profile, []byte("yaml")) {
		t.Fatal("runtime profile retained a source configuration format")
	}
	var metadata imageProfileMetadata
	if err := json.Unmarshal(artifacts.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.SchemaVersion != 1 || metadata.ProfileSHA256 != sha256Hex(bytes.TrimSuffix(artifacts.Profile, []byte{'\n'})) ||
		metadata.GuardsSHA256 != sha256Hex(artifacts.Guards) || len(metadata.FloorSHA256) != 64 {
		t.Fatal("image profile metadata does not pin every runtime artifact")
	}
	profile, err := decodePinnedProfile(t.Context(), bytes.TrimSuffix(artifacts.Profile, []byte{'\n'}), metadata.ProfileSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ruleset.digest != metadata.FloorSHA256 {
		t.Fatal("metadata floor pin differs from decoded runtime profile")
	}
}

func TestBuildImageProfileIsDeterministicAcrossVolatileListingData(t *testing.T) {
	t.Parallel()
	baseline, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	firstListing := protectedRulesetListing(t)
	var listing struct {
		Objects []map[string]map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(firstListing, &listing); err != nil {
		t.Fatal(err)
	}
	// Declaration order, handles, and counter statistics are runtime details.
	listing.Objects[2], listing.Objects[3] = listing.Objects[3], listing.Objects[2]
	for index, outer := range listing.Objects[1:] {
		for kind, fields := range outer {
			fields["handle"] = 9000 + index
			if kind == "counter" {
				fields["packets"], fields["bytes"] = uint64(99), uint64(12345)
			}
			if kind == "rule" {
				expressions, ok := fields["expr"].([]any)
				if !ok {
					t.Fatal("rule expression changed type")
				}
				for _, statement := range expressions {
					if counter, ok := statement.(map[string]any)["counter"].(map[string]any); ok {
						counter["packets"], counter["bytes"] = uint64(77), uint64(888)
					}
				}
			}
		}
	}
	secondListing, err := json.Marshal(listing)
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildImageProfile(t.Context(), baseline, firstListing)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildImageProfile(t.Context(), baseline, secondListing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Profile, second.Profile) || !bytes.Equal(first.Guards, second.Guards) ||
		!bytes.Equal(first.Metadata, second.Metadata) {
		t.Fatal("volatile listing details changed immutable runtime artifacts")
	}
}

func TestBuildImageProfileRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()
	baseline, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	listing := protectedRulesetListing(t)
	tests := []struct {
		name      string
		cancelled bool
		baseline  []byte
		listing   []byte
	}{
		{name: "cancelled", cancelled: true, baseline: baseline, listing: listing},
		{name: "yaml baseline", baseline: []byte("schema_version: 1\n"), listing: listing},
		{name: "wrong nft version", baseline: baseline,
			listing: bytes.Replace(listing, []byte(`"version":"1.1.3"`), []byte(`"version":"1.1.4"`), 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if test.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := BuildImageProfile(ctx, test.baseline, test.listing); err == nil {
				t.Fatal("unsafe image profile input accepted")
			}
		})
	}
	var decoded struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &decoded); err != nil {
		t.Fatal(err)
	}
	owned := map[string]any{"table": map[string]any{
		"family": "inet", "name": ownedTable, "handle": 99999,
	}}
	raw, err := json.Marshal(owned)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Objects = append(decoded.Objects, raw)
	withHelper, err := json.Marshal(map[string]any{"nftables": decoded.Objects})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildImageProfile(t.Context(), baseline, withHelper); err == nil {
		t.Fatal("preinstalled helper table was accepted as reviewed image input")
	}
	if _, err := BuildImageProfile(nil, baseline, listing); err == nil { //nolint:staticcheck // Deliberately test the missing-context boundary.
		t.Fatal("nil context accepted")
	}
}
