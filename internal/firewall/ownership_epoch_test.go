package firewall

import (
	"encoding/json"
	"testing"
)

func epochListingFixture() *guardTableObservation {
	return &guardTableObservation{sets: map[string]listedSet{
		ownershipEpochSet: {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":7168,"timeout":85,"expires":84}}`)}},
		ownershipEpochMap: {Elements: []json.RawMessage{
			json.RawMessage(`[{"elem":{"val":"ipv4","timeout":85,"expires":84}},7168]`),
			json.RawMessage(`[{"elem":{"val":"ipv6","timeout":85,"expires":84}},7168]`),
		}},
	}}
}

func TestOwnershipEpochInspectionRejectsForgedIncompleteAndExpiredMirrors(t *testing.T) {
	t.Parallel()
	if err := inspectOwnershipEpoch(t.Context(), epochListingFixture()); err != nil {
		t.Fatal("consistent kernel epoch listing rejected", err)
	}
	for _, test := range []struct {
		name, mapping string
	}{
		{"changed value", `[{"elem":{"val":"ipv6","timeout":85,"expires":84}},8192]`},
		{"reused family", `[{"elem":{"val":"ipv4","timeout":85,"expires":84}},7168]`},
		{"foreign family", `[{"elem":{"val":"arp","timeout":85,"expires":84}},7168]`},
		{"changed timeout", `[{"elem":{"val":"ipv6","timeout":86,"expires":84}},7168]`},
		{"impossible expiry", `[{"elem":{"val":"ipv6","timeout":85,"expires":86}},7168]`},
		{"unknown attribute", `[{"elem":{"val":"ipv6","timeout":85,"expires":84,"grant":true}},7168]`},
		{"null value", `[{"elem":{"val":"ipv6","timeout":85,"expires":84}},null]`},
		{"extra tuple", `[{"elem":{"val":"ipv6","timeout":85,"expires":84}},7168,7168]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			listing := epochListingFixture()
			listing.sets[ownershipEpochMap].Elements[1] = json.RawMessage(test.mapping)
			if err := inspectOwnershipEpoch(t.Context(), listing); err == nil {
				t.Fatal("forged epoch mirror accepted")
			}
		})
	}
	for _, name := range []string{ownershipEpochMap, ownershipEpochSet} {
		t.Run("missing "+name, func(t *testing.T) {
			t.Parallel()
			listing := epochListingFixture()
			delete(listing.sets, name)
			if err := inspectOwnershipEpoch(t.Context(), listing); err == nil {
				t.Fatal("incomplete epoch evidence accepted")
			}
		})
	}
}
