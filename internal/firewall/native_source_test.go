package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeSourceSnapshotFixture() policy.OwnershipSnapshot {
	return policy.OwnershipSnapshot{Epoch: 7, Addresses: []policy.OwnedAddress{
		{Interface: "lan13", MAC: "02:00:00:00:00:13", Address: netip.MustParseAddr("10.240.3.10")},
		{Interface: "lan13", MAC: "02:00:00:00:00:13", Address: netip.MustParseAddr("fdca:1a2b:3::10")},
		{Interface: "lan13", MAC: "02:00:00:00:00:14", Address: netip.MustParseAddr("10.240.3.11")},
	}}
}

func nativeSourceElements(t *testing.T, operations []any) map[string][]json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Commands []struct {
			Add *struct {
				Element struct {
					Name   string            `json:"name"`
					Values []json.RawMessage `json:"elem"`
				} `json:"element"`
			} `json:"add"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	result := map[string][]json.RawMessage{}
	for _, command := range decoded.Commands {
		if command.Add != nil {
			result[command.Add.Element.Name] = command.Add.Element.Values
		}
	}
	return result
}

func nativeSourceTimedTest(t *testing.T, raw json.RawMessage) ([]json.RawMessage, int) {
	t.Helper()
	var item struct {
		Element struct {
			Timeout int `json:"timeout"`
			Value   struct {
				Fields []json.RawMessage `json:"concat"`
			} `json:"val"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	return item.Element.Value.Fields, item.Element.Timeout
}

func nativeSourceBindingTest(t *testing.T, raw json.RawMessage) (uint32, string, string) {
	t.Helper()
	fields, _ := nativeSourceTimedTest(t, raw)
	if len(fields) != 3 {
		t.Fatal("three exact native source-binding fields required")
	}
	var high uint32
	var low, address string
	if err := json.Unmarshal(fields[0], &high); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fields[1], &low); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fields[2], &address); err != nil {
		t.Fatal(err)
	}
	return high, low, address
}

func TestNativeSourceInventoryDoesNotExtendIndividualAddressLifetimes(t *testing.T) {
	t.Parallel()
	operations, err := nativeSourceChanges(t.Context(), nativeSourceSnapshotFixture(), []int{4, 50, 71}, 71)
	if err != nil {
		t.Fatal(err)
	}
	values := nativeSourceElements(t, operations)
	if len(values[nativeSourceIDs]) != 2 || len(values[nativeSourceChannel]) != 2 ||
		len(values[nativeSource4]) != 2 || len(values[nativeSource6]) != 1 {
		t.Fatal("IDs must describe MACs, while exact IP proofs remain independent")
	}
	for _, inventory := range values[nativeSourceIDs] {
		var pair []json.RawMessage
		if err := json.Unmarshal(inventory, &pair); err != nil || len(pair) != 2 {
			t.Fatal("invalid inventory map pair", err)
		}
		_, timeout := nativeSourceTimedTest(t, pair[0])
		if timeout != 71 {
			t.Fatal("inventory lifetime did not retain the epoch deadline")
		}
	}
	for name, expected := range map[string][]int{nativeSource4: {4, 71}, nativeSource6: {50}} {
		for index, value := range values[name] {
			_, timeout := nativeSourceTimedTest(t, value)
			if timeout != expected[index] {
				t.Fatal("an address proof inherited a longer inventory lifetime")
			}
		}
	}
	high, low, address := nativeSourceBindingTest(t, values[nativeSource4][0])
	high6, low6, address6 := nativeSourceBindingTest(t, values[nativeSource6][0])
	if high != high6 || low != low6 || address == address6 {
		t.Fatal("the two families did not retain one identity with separate IP bindings")
	}

}

func TestNativeSourceMetadataRejectsAmbiguousOrUnboundedInputs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*policy.OwnershipSnapshot)
	}{
		{"missing epoch", func(s *policy.OwnershipSnapshot) { s.Epoch = 0 }},
		{"wrapped epoch", func(s *policy.OwnershipSnapshot) { s.Epoch = policy.MaximumOwnershipEpoch + 1 }},
		{"duplicate IP", func(s *policy.OwnershipSnapshot) { s.Addresses[2].Address = s.Addresses[0].Address }},
		{"two attachments", func(s *policy.OwnershipSnapshot) { s.Addresses[1].Interface = "lan10" }},
		{"unqualified source", func(s *policy.OwnershipSnapshot) { s.Addresses[0].Address = netip.MustParseAddr("fe80::1") }},
		{"invalid interface", func(s *policy.OwnershipSnapshot) { s.Addresses[0].Interface = "invalid iface" }},
		{"invalid MAC", func(s *policy.OwnershipSnapshot) { s.Addresses[0].MAC = "invalid" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := nativeSourceSnapshotFixture()
			snapshot.Addresses = slices.Clone(snapshot.Addresses)
			test.change(&snapshot)
			if _, err := nativeSourceChanges(t.Context(), snapshot, []int{4, 50, 71}, 71); err == nil {
				t.Fatal("ambiguous source metadata admitted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := nativeSourceChanges(ctx, nativeSourceSnapshotFixture(), []int{4, 50, 71}, 71); !errors.Is(err, context.Canceled) {
		t.Fatal("source metadata derivation ignored cancellation", err)
	}
	for _, timeouts := range [][]int{{1}, {0, 50, 71}, {88, 50, 71}} {
		if _, err := nativeSourceChanges(t.Context(), nativeSourceSnapshotFixture(), timeouts, 71); err == nil {
			t.Fatal("missing, expired or unbounded lifetime accepted")
		}
	}
}

func TestNativeSourceClearCanOnlyWithdrawItsFixedObjects(t *testing.T) {
	t.Parallel()
	operations, err := nativeSourceChanges(t.Context(), policy.OwnershipSnapshot{}, nil, 0)
	if err != nil || len(operations) != 17 {
		t.Fatal("native source withdrawal did not retain its fixed scope", err)
	}
	if len(nativeSourceElements(t, operations)) != 0 {
		t.Fatal("native source withdrawal added positive metadata")
	}
}

func TestNativeSourceRawBitsRetainNetworkOrderAndIndividualDeadlines(t *testing.T) {
	t.Parallel()
	operations, err := nativeSourceChanges(t.Context(), nativeSourceSnapshotFixture(), []int{4, 50, 71}, 71)
	if err != nil {
		t.Fatal(err)
	}
	rows := nativeSourceElements(t, operations)[nativeSourceBits4]
	if len(rows) != 2 {
		t.Fatal("raw source proof lost an ipv4 address or included ipv6")
	}
	for index, expected := range []struct {
		address uint32
		timeout int
	}{{0x0af0030a, 4}, {0x0af0030b, 71}} {
		fields, timeout := nativeSourceTimedTest(t, rows[index])
		var address uint32
		if len(fields) != 3 || json.Unmarshal(fields[2], &address) != nil ||
			address != expected.address || timeout != expected.timeout {
			t.Fatal("raw ipv4 proof changed bit order or renewed a deadline")
		}
	}
}

func TestNativeSourceIdentityBoundaryKeepsTheUpperIDBits(t *testing.T) {
	t.Parallel()
	snapshot := policy.OwnershipSnapshot{Epoch: 7, Addresses: []policy.OwnedAddress{}}
	timeouts := []int{}
	for index := 1; index <= maximumCohortSize; index++ {
		snapshot.Addresses = append(snapshot.Addresses, policy.OwnedAddress{Interface: "lan13", MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", index/256, index%256), Address: netip.MustParseAddr(fmt.Sprintf("10.241.%d.%d", index/256, index%256))})
		timeouts = append(timeouts, 71)
	}
	changes, err := nativeSourceChanges(t.Context(), snapshot, timeouts, 71)
	if err != nil {
		t.Fatal(err)
	}
	values := nativeSourceElements(t, changes)
	if len(values[nativeSourceIDs]) != 4096 || len(values[nativeSourceChannel]) != 1024 {
		t.Fatal("identity capacity truncated or duplicated the low-bit channel")
	}
	high, low, _ := nativeSourceBindingTest(t, values[nativeSource4][4095])
	if high != 0x8000 || low != "none" {
		t.Fatal("identity4096 lost its high bits or became an unmanaged sentinel", high, low)
	}

	snapshot.Addresses = append(snapshot.Addresses, policy.OwnedAddress{Interface: "lan13", MAC: "02:00:00:00:10:01", Address: netip.MustParseAddr("10.241.16.1")})
	timeouts = append(timeouts, 71)
	if _, err := nativeSourceChanges(t.Context(), snapshot, timeouts, 71); err == nil {
		t.Fatal("source identity capacity exceeded")
	}
}

func TestNativeSourcePreparationCannotSubstituteBytesForItsOwnershipProof(t *testing.T) {
	t.Parallel()
	baseline := nativeAccessBaseline(t)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	evidence, err := ownershipProofFixture(t, baseline, now, 70*time.Second).InEpoch(t.Context(), 9)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := renderer.prepareNativeOwnership(t.Context(), evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.nativeSources || prepared.batch.preparedAt != now ||
		prepared.batch.startBefore != now.Add(preparationBudget) {
		t.Fatal("native metadata changed the original ownership preparation fence")
	}
	if err := validateOwnershipPreparation(t.Context(), prepared, now); err != nil {
		t.Fatal(err)
	}
	prepared.nativeSources = false
	if err := validateOwnershipPreparation(t.Context(), prepared, now); err == nil {
		t.Fatal("a legacy preparation accepted native metadata without its mode")
	}
	prepared.nativeSources = true
	prepared.batch.data = bytes.Replace(prepared.batch.data, []byte(`"0:1"`), []byte(`"0:2"`), 1)
	prepared.digest = sha256.Sum256(prepared.batch.data)
	if err := validateOwnershipPreparation(t.Context(), prepared, now); err == nil {
		t.Fatal("a self-consistent byte digest replaced the original identity proof")
	}
	revocation, err := prepareNativeOwnershipClear(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnershipPreparation(t.Context(), revocation, now); err != nil {
		t.Fatal(err)
	}
	var commands struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(revocation.batch.data, &commands); err != nil || len(commands.Commands) != 33 {
		t.Fatal("native withdrawal omitted its ownership, epoch or identity objects", err)
	}
}

func TestNativeIPv4IdentityDistinguishesAddressesOnOneMAC(t *testing.T) {
	t.Parallel()
	snapshot := nativeSourceSnapshotFixture()
	other := snapshot.Addresses[0]
	other.Address = netip.MustParseAddr("10.240.3.12")
	snapshot.Addresses = append(snapshot.Addresses, other)
	operations, err := nativeSourceChanges(t.Context(), snapshot, []int{4, 50, 71, 27}, 71)
	if err != nil {
		t.Fatal(err)
	}
	values := nativeSourceElements(t, operations)
	inventory := map[string]string{}
	for _, raw := range values[nativeSourceIDs4] {
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil {
			t.Fatal(err)
		}
		fields, timeout := nativeSourceTimedTest(t, pair[0])
		if len(fields) != 4 || timeout != 71 {
			t.Fatal("IPv4 identity inventory lost its original epoch")
		}
		var address, id string
		if err := json.Unmarshal(fields[3], &address); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(pair[1], &id); err != nil {
			t.Fatal(err)
		}
		inventory[address] = id
	}
	if inventory["10.240.3.10"] != "0:1" || inventory["10.240.3.12"] != "0:2" || inventory["10.240.3.11"] != "0:3" {
		t.Fatal("one MAC's distinct IPv4 addresses share a physical source identity", inventory)
	}
	inverse := map[string]int{}
	for _, raw := range values[nativeSourceAddresses4] {
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil {
			t.Fatal(err)
		}
		fields, timeout := nativeSourceTimedTest(t, pair[0])
		if len(fields) != 2 {
			t.Fatal("invalid inverse identity key")
		}
		var address string
		if err := json.Unmarshal(pair[1], &address); err != nil {
			t.Fatal(err)
		}
		inverse[address] = timeout
	}
	if inverse["10.240.3.10"] != 4 || inverse["10.240.3.12"] != 27 || inverse["10.240.3.11"] != 71 {
		t.Fatal("IPv4 inverse map renewed or merged individual ownership deadlines")
	}
}

func TestNativeIPv6IdentityDistinguishesAddressesOnOneMAC(t *testing.T) {
	t.Parallel()
	snapshot := nativeSourceSnapshotFixture()
	snapshot.Addresses[0].Address = netip.MustParseAddr("fdca:1a2b:3::10")
	snapshot.Addresses[1].Address = netip.MustParseAddr("10.240.3.10")
	snapshot.Addresses[2].Address = netip.MustParseAddr("fdca:1a2b:3::11")
	other := snapshot.Addresses[0]
	other.Address = netip.MustParseAddr("fdca:1a2b:3::12")
	snapshot.Addresses = append(snapshot.Addresses, other)
	operations, err := nativeSourceChanges(t.Context(), snapshot, []int{4, 50, 71, 27}, 71)
	if err != nil {
		t.Fatal(err)
	}
	values := nativeSourceElements(t, operations)
	inventory := map[string]string{}
	for _, raw := range values[nativeSourceIDs6] {
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil {
			t.Fatal(err)
		}
		fields, timeout := nativeSourceTimedTest(t, pair[0])
		if len(fields) != 4 || timeout != 71 {
			t.Fatal("IPv6 identity inventory lost its original epoch")
		}
		var address, id string
		if err := json.Unmarshal(fields[3], &address); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(pair[1], &id); err != nil {
			t.Fatal(err)
		}
		inventory[address] = id
	}
	if inventory["fdca:1a2b:3::10"] != "0:1" || inventory["fdca:1a2b:3::12"] != "0:2" || inventory["fdca:1a2b:3::11"] != "0:3" {
		t.Fatal("one MAC's distinct IPv6 addresses share a physical source identity", inventory)
	}
	inverse := map[string]int{}
	for _, raw := range values[nativeSourceAddresses6] {
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil {
			t.Fatal(err)
		}
		fields, timeout := nativeSourceTimedTest(t, pair[0])
		if len(fields) != 2 {
			t.Fatal("invalid inverse identity key")
		}
		var address string
		if err := json.Unmarshal(pair[1], &address); err != nil {
			t.Fatal(err)
		}
		inverse[address] = timeout
	}
	if inverse["fdca:1a2b:3::10"] != 4 || inverse["fdca:1a2b:3::12"] != 27 || inverse["fdca:1a2b:3::11"] != 71 {
		t.Fatal("IPv6 inverse map renewed or merged individual ownership deadlines")
	}
}
