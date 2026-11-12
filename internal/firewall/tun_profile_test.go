package firewall

import (
	"encoding/json"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestTUNProfileIsPinnedAndDoesNotContainRuntimeCompilerProgram(t *testing.T) {
	t.Parallel()
	// Reuse the existing named baseline fixture, with no deployment resources.
	baseline := nativeAccessBaseline(t)
	baseline.NetworkModel = &policy.NetworkModel{SchemaVersion: 1, ManagedNetworks: []policy.Role{}, UplinkInterface: "wan", Rules: []policy.NetworkRule{}}
	raw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	listing := []byte(`{"nftables":[{"table":{"family":"inet","name":"lanrith"}}]}`)
	artifacts, err := BuildTUNImageProfile(t.Context(), raw, listing)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Profile string `json:"profile_sha256"`
	}
	if err := json.Unmarshal(artifacts.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	profile, loaded, err := decodeTUNProfile(artifacts.Profile[:len(artifacts.Profile)-1], metadata.Profile)
	if err != nil || profile.Backend != "tun" || loaded.Generation != baseline.Generation {
		t.Fatal("profile roundtrip", err)
	}
	artifacts.Profile[0] = '['
	if _, _, err := decodeTUNProfile(artifacts.Profile[:len(artifacts.Profile)-1], metadata.Profile); err == nil {
		t.Fatal("changed profile accepted")
	}
}
