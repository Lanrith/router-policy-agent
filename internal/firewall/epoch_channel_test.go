package firewall

import (
	"encoding/json"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func channelListingFixture(configuration bool) (*guardTableObservation, *guardTableObservation) {
	inet := epochListingFixture()
	netdev := &guardTableObservation{sets: map[string]listedSet{}}
	mapping, set := epochChannelNames(configuration)
	if configuration {
		inet.sets[configurationEpochSet] = listedSet{Elements: []json.RawMessage{json.RawMessage(`7168`)}}
		inet.sets[mapping] = listedSet{Elements: []json.RawMessage{json.RawMessage(`[7168,"0:1c00"]`)}}
		netdev.sets[set] = listedSet{Elements: []json.RawMessage{json.RawMessage(`"0:1c00"`)}}
	} else {
		inet.sets[mapping] = listedSet{Elements: []json.RawMessage{json.RawMessage(`[{"elem":{"val":7168,"timeout":85,"expires":84}},"0:1c00"]`)}}
		netdev.sets[set] = listedSet{Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":"0:1c00","timeout":85,"expires":84}}`)}}
	}
	return inet, netdev
}

func TestEpochClassIdentifierIsCanonicalAndCannotOverlapRuleBits(t *testing.T) {
	t.Parallel()
	for _, epoch := range []uint32{1, 7, 17, policy.MaximumOwnershipEpoch} {
		base := epoch << policy.OwnershipRuleBits
		actual, err := parseEpochClassID(epochClassID(base))
		if err != nil || actual != base {
			t.Fatal("epoch conversion changed bits", epoch, actual, err)
		}
	}
	for _, value := range []string{"none", "0:0", "0:1", "0:01c00", "00:1c00", "0:1C00", "0x0:1c00", "0:1c01", "0:1c00:1", "ffff:ffff"} {
		if _, err := parseEpochClassID(value); err == nil {
			t.Fatal("noncanonical, unaligned or reserved epoch accepted", value)
		}
	}
}

func TestEpochChannelInspectionRejectsTransferredAndIncompleteGeneration(t *testing.T) {
	t.Parallel()
	for _, configuration := range []bool{false, true} {
		inet, netdev := channelListingFixture(configuration)
		if err := inspectEpochChannel(t.Context(), configuration, inet, netdev); err != nil {
			t.Fatal("consistent conversion channel rejected", err)
		}
		mapping, set := epochChannelNames(configuration)
		for _, test := range []struct{ name, value string }{
			{"different generation", "0:2000"}, {"changed rule bits", "0:1c01"},
			{"noncanonical", "00:1c00"}, {"reserved", "ffff:ffff"},
		} {
			t.Run(test.name+map[bool]string{false: "/source", true: "/configuration"}[configuration], func(t *testing.T) {
				t.Parallel()
				inet, netdev := channelListingFixture(configuration)
				value, err := json.Marshal(test.value)
				if err != nil {
					t.Fatal(err)
				}
				if configuration {
					netdev.sets[set].Elements[0] = value
				} else {
					netdev.sets[set].Elements[0] = json.RawMessage(`{"elem":{"val":` + string(value) + `,"timeout":85,"expires":84}}`)
				}
				if err := inspectEpochChannel(t.Context(), configuration, inet, netdev); err == nil {
					t.Fatal("physical epoch changed without its admitted origin")
				}
			})
		}
		delete(inet.sets, mapping)
		if err := inspectEpochChannel(t.Context(), configuration, inet, netdev); err == nil {
			t.Fatal("missing conversion map accepted")
		}
	}
}
