package policy

import (
	"encoding/json"
	"testing"
)

func asymmetricBaseline(t *testing.T) Baseline {
	t.Helper()
	b := coreServiceBaseline(t)
	b.NetworkModel.CoreServices = nil
	b.NetworkModel.AsymmetricReplies = []AsymmetricReply{{
		Mode: "tcp_dsr", SourceInterface: "lan13", SourceAddresses: prefixes("fdca:1a2b:3::/64"),
		DestinationInterface: "lan13", DestinationAddresses: prefixes("fdca:1a2b:3::400/128"),
	}}
	return b
}

func TestAsymmetricRepliesRemainIPv6ReturnOnlyGeometry(t *testing.T) {
	t.Parallel()
	b := asymmetricBaseline(t)
	if _, err := New(b); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*AsymmetricReply)
	}{
		{"unknown mode", func(reply *AsymmetricReply) { reply.Mode = "any" }},
		{"IPv4 source", func(reply *AsymmetricReply) { reply.SourceAddresses = prefixes("10.240.3.0/24") }},
		{"source escape", func(reply *AsymmetricReply) { reply.SourceAddresses = prefixes("fdca:1a2b:4::/64") }},
		{"broad source", func(reply *AsymmetricReply) { reply.SourceAddresses = prefixes("fdca:1a2b::/32") }},
		{"unknown source interface", func(reply *AsymmetricReply) { reply.SourceInterface = "missing" }},
		{"empty target", func(reply *AsymmetricReply) { reply.DestinationAddresses = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			b := asymmetricBaseline(t)
			test.change(&b.NetworkModel.AsymmetricReplies[0])
			if _, err := New(b); err == nil {
				t.Fatal("unsafe asymmetric return accepted")
			}
		})
	}
}

func TestAsymmetricReplyMayUseAttachedPrefixContainingProtectedRouterAddress(t *testing.T) {
	t.Parallel()
	b := asymmetricBaseline(t)
	b.ProtectedNetworks = append(b.ProtectedNetworks, NetworkBlock{
		ProtectionID: "P01", Networks: prefixes("fdca:1a2b:3::1/128"),
	})
	if _, err := New(b); err != nil {
		t.Fatal(err)
	}
	b.NetworkModel.AsymmetricReplies[0].SourceAddresses = prefixes("fdca:1a2b:3::1/128")
	if _, err := New(b); err == nil {
		t.Fatal("asymmetric reply wholly inside router protection accepted")
	}
}

func TestAsymmetricReplyStrictSchemaRejectsPacketFragments(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(asymmetricBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var model map[string]json.RawMessage
	if err := json.Unmarshal(root["network_model"], &model); err != nil {
		t.Fatal(err)
	}
	var replies []map[string]json.RawMessage
	if err := json.Unmarshal(model["asymmetric_replies"], &replies); err != nil {
		t.Fatal(err)
	}
	replies[0]["ports"] = json.RawMessage(`[22]`)
	model["asymmetric_replies"], _ = json.Marshal(replies)
	root["network_model"], _ = json.Marshal(model)
	raw, _ = json.Marshal(root)
	if _, err := DecodeBaseline(raw); err == nil {
		t.Fatal("asymmetric reply accepted an arbitrary packet fragment")
	}
}
