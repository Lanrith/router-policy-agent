package firewall

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
)

func listedIDGrant(t *testing.T, epoch, id uint32, peer string, port uint16, timeout int) json.RawMessage {
	t.Helper()
	key, err := nativeIDGrantKey(epoch, id, netip.MustParseAddr(peer), port)
	if err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(map[string]any{"elem": map[string]any{"val": key, "timeout": timeout, "expires": timeout - 1}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNativeIDObservationIsOnlyAnIntersectionOfCurrentSourceAndLogicalGrant(t *testing.T) {
	t.Parallel()
	inet, netdev := nativeSourceListingFixture()
	logical := idGrantInput(t, "lan13", "02:00:00:00:00:14", "10.240.3.11", 43)
	for _, ref := range nativeIDLeaseRefs() {
		observation := netdev
		if ref.Family == "inet" {
			observation = inet
		}
		observation.sets[ref.Name] = listedSet{Elements: []json.RawMessage{listedIDGrant(t, 7<<10, 2, "10.240.0.10", 6053, 20)}}
	}
	if count, err := inspectNativeIDGrants(t.Context(), logical, inet, netdev); err != nil || count != 4 {
		t.Fatal("valid source/grant intersection rejected", count, err)
	}
	// Missing projected permits are safe, including after source revocation.
	for _, ref := range nativeIDLeaseRefs() {
		inet.sets[ref.Name] = listedSet{}
		netdev.sets[ref.Name] = listedSet{}
	}
	inet.sets[ownershipEpochSet] = listedSet{}
	if count, err := inspectNativeIDGrants(t.Context(), logical, inet, netdev); err != nil || count != 0 {
		t.Fatal("empty revoked ID projection rejected", count, err)
	}
}

func TestNativeIDObservationRejectsEpochIdentityEndpointAndLifetimeTampering(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"inet", "netdev"} {
		for _, name := range []string{"other epoch", "other ID", "other peer", "other port", "longer than logical grant", "longer than individual source", "longer than epoch", "expired individual source", "missing source epoch", "duplicate", "missing logical grant", "other protocol"} {
			t.Run(family+"/"+name, func(t *testing.T) {
				t.Parallel()
				inet, netdev := nativeSourceListingFixture()
				logical := idGrantInput(t, "lan13", "02:00:00:00:00:14", "10.240.3.11", 43)
				observation := netdev
				if family == "inet" {
					observation = inet
				}
				epoch, id, peer, port, timeout := uint32(7<<10), uint32(2), "10.240.0.10", uint16(6053), 20
				target := "native_id_lease_from4_tcp"
				switch name {
				case "other epoch":
					epoch = 8 << 10
				case "other ID":
					id = 1
				case "other peer":
					peer = "10.240.0.11"
				case "other port":
					port = 6054
				case "longer than logical grant":
					timeout = 44
				case "longer than individual source":
					inet.sets[ownership4Set] = listedSet{Elements: []json.RawMessage{bytes.ReplaceAll(inet.sets[ownership4Set].Elements[0], []byte(`50`), []byte(`10`))}}
					inet.sets[ownership4Set].Elements[0] = bytes.ReplaceAll(inet.sets[ownership4Set].Elements[0], []byte(`49`), []byte(`9`))
				case "longer than epoch":
					inet.sets[ownershipEpochSet] = listedSet{Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":7168,"timeout":10,"expires":9}}`)}}
				case "expired individual source":
					inet.sets[ownership4Set] = listedSet{}
				case "missing source epoch":
					inet.sets[ownershipEpochSet] = listedSet{}
				case "missing logical grant":
					logical.Commands = nil
				case "other protocol":
					logical.Commands = logical.Commands[:1]
					target = "native_id_lease_from4_udp"
				}
				value := listedIDGrant(t, epoch, id, peer, port, timeout)
				observation.sets[target] = listedSet{Elements: []json.RawMessage{value}}
				if name == "duplicate" {
					observation.sets[target] = listedSet{Elements: []json.RawMessage{value, value}}
				}
				if _, err := inspectNativeIDGrants(t.Context(), logical, inet, netdev); err == nil {
					t.Fatal("modified ID projection was accepted")
				}
			})
		}
	}
}

func TestNativeIDKeyKeepsUpperSourceBitsAndExcludesTheReservedEpoch(t *testing.T) {
	t.Parallel()
	raw, err := nativeIDGrantKey(7<<10, 4096, netip.MustParseAddr("10.240.0.10"), 6053)
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Fields []json.RawMessage `json:"concat"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		t.Fatal(err)
	}
	var epoch string
	var high uint32
	if len(key.Fields) != 4 || json.Unmarshal(key.Fields[0], &epoch) != nil || json.Unmarshal(key.Fields[1], &high) != nil || epoch != "0:1c00" || high != 32768 {
		t.Fatal("ID upper bits or source epoch were truncated")
	}
	if _, err := nativeIDGrantKey(uint32(nativeCoreEpoch), 1, netip.MustParseAddr("10.240.0.10"), 6053); err == nil {
		t.Fatal("core connection kind became a source identity grant")
	}
}
