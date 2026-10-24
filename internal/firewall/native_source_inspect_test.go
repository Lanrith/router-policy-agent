package firewall

import (
	"bytes"
	"encoding/json"
	"testing"
)

func nativeSourceListingFixture() (*guardTableObservation, *guardTableObservation) {
	inet := &guardTableObservation{sets: map[string]listedSet{
		ownershipEpochSet: {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":7168,"timeout":71,"expires":70}}`)}},
		ownership4Set:     {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":["lan13","02:00:00:00:00:14","10.240.3.11"]},"timeout":50,"expires":49}}`)}},
		nativeSourceIDs: {Elements: []json.RawMessage{
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"lan13","02:00:00:00:00:13"]},"timeout":71,"expires":70}},"0:1"]`),
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"lan13","02:00:00:00:00:14"]},"timeout":71,"expires":70}},"0:2"]`),
		}},
		nativeSourceIDs4: {Elements: []json.RawMessage{
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"lan13","02:00:00:00:00:13","10.240.3.10"]},"timeout":71,"expires":70}},"0:1"]`),
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"lan13","02:00:00:00:00:14","10.240.3.11"]},"timeout":71,"expires":70}},"0:2"]`),
		}},
		ownership6Set: {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":["lan13","02:00:00:00:00:13","fdca:1a2b:3::12"]},"timeout":27,"expires":26}}`)}},
		nativeSourceIDs6: {Elements: []json.RawMessage{
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"lan13","02:00:00:00:00:13","fdca:1a2b:3::10"]},"timeout":71,"expires":70}},"0:1"]`),
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"lan13","02:00:00:00:00:13","fdca:1a2b:3::12"]},"timeout":71,"expires":70}},"0:2"]`),
		}},
		nativeSourceChannel: {Elements: []json.RawMessage{
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"0:1"]},"timeout":71,"expires":70}},"0:1c01"]`),
			json.RawMessage(`[{"elem":{"val":{"concat":[7168,"0:2"]},"timeout":71,"expires":70}},"0:1c02"]`),
		}},
	}}
	netdev := &guardTableObservation{sets: map[string]listedSet{
		nativeSourceEpoch6:     {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":["0:1c00","fdca:1a2b:3::12"]},"timeout":27,"expires":26}}`)}},
		nativeSourceAddresses6: {Elements: []json.RawMessage{json.RawMessage(`[{"elem":{"val":{"concat":[0,"0:2"]},"timeout":27,"expires":26}},"fdca:1a2b:3::12"]`)}},
		nativeSourceLive6:      {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":[0,"0:2"]},"timeout":27,"expires":26}}`)}},
		nativeSource6:          {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":[0,"0:2","fdca:1a2b:3::12"]},"timeout":27,"expires":26}}`)}},
		nativeSourceAddresses4: {Elements: []json.RawMessage{json.RawMessage(`[{"elem":{"val":{"concat":[0,"0:2"]},"timeout":50,"expires":49}},"10.240.3.11"]`)}},
		nativeSourceLive4:      {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":[0,"0:2"]},"timeout":50,"expires":49}}`)}},
		nativeSource4:          {Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":[0,"0:2","10.240.3.11"]},"timeout":50,"expires":49}}`)}},
	}}
	inet.sets[nativeSource4] = listedSet{Elements: append([]json.RawMessage(nil), netdev.sets[nativeSource4].Elements...)}
	inet.sets[nativeSource6] = listedSet{Elements: append([]json.RawMessage(nil), netdev.sets[nativeSource6].Elements...)}
	inet.sets[nativeSourceLive4] = listedSet{Elements: append([]json.RawMessage(nil), netdev.sets[nativeSourceLive4].Elements...)}
	inet.sets[nativeSourceLive6] = listedSet{Elements: append([]json.RawMessage(nil), netdev.sets[nativeSourceLive6].Elements...)}
	inet.sets[nativeSourceBits4] = listedSet{Elements: []json.RawMessage{json.RawMessage(`{"elem":{"val":{"concat":[0,"0:2",183501579]},"timeout":50,"expires":49}}`)}}
	netdev.sets[nativeSourceBits4] = listedSet{Elements: append([]json.RawMessage(nil), inet.sets[nativeSourceBits4].Elements...)}
	return inet, netdev
}

func TestNativeSourceInspectionKeepsIDsAfterAnotherMACsLastIPExpires(t *testing.T) {
	t.Parallel()
	layout, err := newNativeAccessLayout(t.Context(), nativeAccessBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	inet, netdev := nativeSourceListingFixture()
	if err := layout.inspectNativeSources(t.Context(), inet, netdev); err != nil {
		t.Fatal("expired individual IP changed the remaining identity's ID", err)
	}
	inet.sets[ownershipEpochSet] = listedSet{}
	if err := layout.inspectNativeSources(t.Context(), inet, netdev); err == nil {
		t.Fatal("native source metadata survived without its checked epoch")
	}
}

func TestNativeSourceInspectionRejectsIdentityGenerationAndLifetimeDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, object, before, after string
		physical                    bool
	}{
		{"ipv6 source epoch identity", nativeSourceEpoch6, `"0:1c00"`, `"0:2000"`, true},
		{"ipv6 source epoch address", nativeSourceEpoch6, `"fdca:1a2b:3::12"`, `"fdca:1a2b:3::13"`, true},
		{"ipv6 source epoch deadline", nativeSourceEpoch6, `"timeout":27`, `"timeout":71`, true},
		{"raw ipv4 bit order", nativeSourceBits4, `183501579`, `184501579`, false},
		{"raw ipv4 identity", nativeSourceBits4, `"0:2"`, `"0:1"`, false},
		{"raw ipv4 deadline", nativeSourceBits4, `"timeout":50`, `"timeout":71`, false},
		{"physical raw ipv4 bit order", nativeSourceBits4, `183501579`, `184501579`, true},
		{"physical raw ipv4 identity", nativeSourceBits4, `"0:2"`, `"0:1"`, true},
		{"physical raw ipv4 deadline", nativeSourceBits4, `"timeout":50`, `"timeout":71`, true},
		{"ipv6 inventory identity", nativeSourceIDs6, `"0:2"`, `"0:1"`, false},
		{"ipv6 inventory epoch", nativeSourceIDs6, `7168`, `8192`, false},
		{"ipv6 inventory address", nativeSourceIDs6, `"fdca:1a2b:3::12"`, `"fdca:1a2b:3::13"`, false},
		{"ipv6 inventory wrong family", nativeSourceIDs6, `"fdca:1a2b:3::12"`, `"10.240.3.12"`, false},
		{"inverse ipv6 identity", nativeSourceAddresses6, `"0:2"`, `"0:1"`, true},
		{"inverse ipv6 address", nativeSourceAddresses6, `"fdca:1a2b:3::12"`, `"fdca:1a2b:3::13"`, true},
		{"inverse ipv6 deadline", nativeSourceAddresses6, `"timeout":27`, `"timeout":71`, true},
		{"ipv6 live identity", nativeSourceLive6, `"0:2"`, `"0:1"`, true},
		{"ipv6 live deadline", nativeSourceLive6, `"timeout":27`, `"timeout":71`, true},
		{"ipv6 raw identity", nativeSource6, `"0:2"`, `"0:1"`, false},
		{"ipv6 raw deadline", nativeSource6, `"timeout":27`, `"timeout":71`, false},
		{"ipv6 physical identity", nativeSource6, `"0:2"`, `"0:1"`, true},
		{"ipv6 physical deadline", nativeSource6, `"timeout":27`, `"timeout":71`, true},
		{"IPv4 inventory identity", nativeSourceIDs4, `"0:2"`, `"0:1"`, false},
		{"IPv4 inventory epoch", nativeSourceIDs4, `7168`, `8192`, false},
		{"IPv4 inventory IP", nativeSourceIDs4, `"10.240.3.11"`, `"10.240.3.12"`, false},
		{"inverse IPv4 identity", nativeSourceAddresses4, `"0:2"`, `"0:1"`, true},
		{"inverse IPv4 address", nativeSourceAddresses4, `"10.240.3.11"`, `"10.240.3.12"`, true},
		{"inverse IPv4 deadline", nativeSourceAddresses4, `"timeout":50`, `"timeout":71`, true},
		{"duplicate ID", nativeSourceIDs, `"0:2"`, `"0:1"`, false},
		{"changed epoch", nativeSourceIDs, `7168`, `8192`, false},
		{"changed attachment", nativeSourceIDs, `"lan13"`, `"lan10"`, false},
		{"extended inventory", nativeSourceIDs, `"timeout":71`, `"timeout":72`, false},
		{"different channel epoch", nativeSourceChannel, `"0:1c02"`, `"0:2002"`, false},
		{"unmanaged ID", nativeSourceIDs, `"0:2"`, `"none"`, false},
		{"noncanonical ID", nativeSourceIDs, `"0:2"`, `"0:02"`, false},
		{"live ID", nativeSourceLive4, `"0:2"`, `"0:1"`, true},
		{"live ID deadline", nativeSourceLive4, `"timeout":50`, `"timeout":71`, true},
		{"other pre-NAT identity", nativeSource4, `"0:2"`, `"0:1"`, false},
		{"other physical identity", nativeSource4, `"0:2"`, `"0:1"`, true},
		{"other physical address", nativeSource4, `"10.240.3.11"`, `"10.240.3.12"`, true},
		{"extended IP deadline", nativeSource4, `"timeout":50`, `"timeout":71`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			layout, err := newNativeAccessLayout(t.Context(), nativeAccessBaseline(t))
			if err != nil {
				t.Fatal(err)
			}
			inet, netdev := nativeSourceListingFixture()
			observed := inet
			if test.physical {
				observed = netdev
			}
			object := observed.sets[test.object]
			for index, raw := range object.Elements {
				object.Elements[index] = bytes.ReplaceAll(raw, []byte(test.before), []byte(test.after))
			}
			observed.sets[test.object] = object
			if err := layout.inspectNativeSources(t.Context(), inet, netdev); err == nil {
				t.Fatal("modified source handoff observation was accepted")
			}
		})
	}
}
