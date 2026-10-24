package policy

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func namedFixture(t *testing.T) (Baseline, Input) {
	t.Helper()
	b := testBaseline()
	b.Zones = []Zone{b.Zones[2], b.Zones[3]}
	b.Zones[0].Role, b.Zones[1].Role = "servers", "devices"
	b.NetworkModel = &NetworkModel{SchemaVersion: 1, ManagedNetworks: []Role{"devices"}, UplinkInterface: "wan",
		Rules: []NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6053},
			From: []NetworkSelector{{Interface: "lan12", Addresses: prefixes("fdca:1a2b:2::10/128")}},
			To:   []NetworkSelector{{Interface: "lan13", Addresses: prefixes("fdca:1a2b:3::/64")}}}}}
	i := testInput(t)
	for index, group := range i.Directory.Groups {
		raw := strings.ReplaceAll(*group.Policy, "untrusted", "devices")
		if index == 1 {
			raw = strings.ReplaceAll(raw, "fdca:1a2b::10/128", "fdca:1a2b:2::10/128")
		}
		i.Directory.Groups[index].Policy = &raw
	}
	return b, i
}

func TestNamedNetworksCompileAndCheckIndependentCandidate(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	b, err = DecodeBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	compiler := testCompiler(t, b)
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 || len(candidate.Denials) != 0 {
		t.Fatalf("named model compile: %+v, %v", candidate, err)
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	addresses, err := compiler.ClassifyBindings(t.Context(), input.Bindings, []string{input.Directory.Devices[0].MAC}, testNow)
	if err != nil || !slices.Contains(addresses, netip.MustParseAddr("fdca:1a2b:3::10")) {
		t.Fatalf("named classification lost: %v", err)
	}
	// Root configuration is immutable after New, including ordered rule ports.
	b.NetworkModel.Rules[0].Ports[0] = 80
	if _, err := compiler.Compile(input); err != nil {
		t.Fatal(err)
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatal("caller mutation changed owned configuration", err)
	}
	// VLAN 0 is an untagged physical attachment. Only this opted-in root
	// geometry may establish it; the legacy validator still rejects VLAN 0.
	b.NetworkModel.Rules[0].Ports[0] = 6053
	b.Zones[1].VLAN, input.Bindings.Records[0].VLAN = 0, 0
	candidate, err = testCompiler(t, b).Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatalf("untagged managed network: %+v, %v", candidate, err)
	}
}

func TestNamedModelAllowsExplicitEmptyIdentityPolicy(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	b.NetworkModel.ManagedNetworks = []Role{}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := DecodeBaseline(raw)
	if err != nil {
		t.Fatal("a router without inherited directory policy was rejected", err)
	}
	for _, zone := range owned.Zones {
		if owned.DirectoryManaged(zone.Role) {
			t.Fatal("an empty identity policy acquired a managed network")
		}
	}
	// Explicit directory rules still require a grant independently of the
	// networks selected for inherited identity policy.
	compiler := testCompiler(t, owned)
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("explicit directory permission lost its independent integration", candidate, err)
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	b.NetworkModel.ManagedNetworks = nil
	if _, err := New(b); err == nil {
		t.Fatal("missing identity policy was confused with an explicit empty list")
	}
}

func TestNamedRulesPreserveScopeAndTerminalOrdering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Baseline, *Input)
	}{
		{"source", func(b *Baseline, _ *Input) {
			b.NetworkModel.Rules[0].From[0].Addresses = prefixes("fdca:1a2b:2::11/128")
		}},
		{"destination", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].To[0].Addresses = prefixes("fdca:1a2b:3::11/128") }},
		{"ingress", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].From[0].Interface = "wan" }},
		{"egress", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].To[0].Interface = "lan12" }},
		{"port", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].Ports = []uint16{80} }},
		{"protocol", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].Protocol = "udp" }},
		{"family", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].Family = 4 }},
		{"unknown peer MAC", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].From[0].MAC = "02:00:00:00:00:02" }},
		{"static owner is not a delegated capability", func(b *Baseline, _ *Input) { b.NetworkModel.Rules[0].Authorization = "owner" }},
		{"earlier deny", func(b *Baseline, _ *Input) {
			deny := NetworkRule{Action: "deny", Authorization: "inherit", Protocol: "any", From: []NetworkSelector{{}}, To: []NetworkSelector{{}}}
			b.NetworkModel.Rules = append([]NetworkRule{deny}, b.NetworkModel.Rules...)
		}},
		{"protected network", func(b *Baseline, _ *Input) { b.ProtectedNetworks[0].Networks = prefixes("fdca:1a2b:2::10/128") }},
		{"protected port", func(b *Baseline, _ *Input) {
			b.ProtectedEndpoints[0].Networks = prefixes("fdca:1a2b:3::10/128")
			b.ProtectedEndpoints[0].Ports = []uint16{6053}
		}},
		{"wrong binding interface", func(_ *Baseline, i *Input) { i.Bindings.Records[0].Interface = "lan12" }},
		{"wrong binding vlan", func(_ *Baseline, i *Input) { i.Bindings.Records[0].VLAN = 12 }},
		{"unused automation source", func(_ *Baseline, i *Input) {
			raw := strings.ReplaceAll(*i.Directory.Groups[1].Policy, "fdca:1a2b:2::10/128", "fdca:1a2b:2::11/128")
			i.Directory.Groups[1].Policy = &raw
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, input := namedFixture(t)
			tt.mutate(&b, &input)
			candidate, err := testCompiler(t, b).Compile(input)
			if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 {
				t.Fatalf("widened named permission: %+v, %v", candidate, err)
			}
		})
	}
}

func TestNamedModelRejectsUndeclaredPlacementAndWideControllers(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	compiler := testCompiler(t, b)
	if _, err := ParseGroup(*input.Directory.Groups[1].Policy); err == nil {
		t.Fatal("legacy parser silently changed its role boundary")
	}
	for _, role := range []string{"absent", "uplink"} {
		raw := strings.ReplaceAll(*input.Directory.Groups[1].Policy, "devices", role)
		if _, err := compiler.ParseGroup(raw); err == nil {
			t.Fatal("undeclared access role accepted")
		}
	}
	for _, mutate := range []func(*Baseline){
		func(b *Baseline) { b.ControllerInitiators = []ControllerInitiator{{ID: "forbidden"}} },
		func(b *Baseline) { b.NetworkModel.ManagedNetworks = []Role{"absent"} },
		func(b *Baseline) { b.NetworkModel.ManagedNetworks = []Role{"devices", "devices"} },
		func(b *Baseline) { b.NetworkModel.Rules[0].From[0].Interface = "unowned" },
		func(b *Baseline) { b.NetworkModel.Rules[0].To[0].MAC = "02:00:00:00:00:01" },
		func(b *Baseline) { b.NetworkModel.Rules[0].Ports = []uint16{80, 80} },
		func(b *Baseline) { b.NetworkModel.Rules[0].Family = 5 },
	} {
		value, _ := namedFixture(t)
		mutate(&value)
		if _, err := New(value); err == nil {
			t.Fatal("unsafe named geometry accepted")
		}
	}
	data, _ := json.Marshal(b)
	for _, raw := range []string{
		strings.Replace(string(data), `"network_model":{`, `"network_model":{"arbitrary":true,`, 1),
		strings.Replace(string(data), `"protocol":"tcp"`, `"protocol":"tcp","states":["invalid"]`, 1),
		strings.Replace(string(data), `"interface":"lan12"`, `"interface":"lan12","interface":"wan"`, 1),
	} {
		if _, err := DecodeBaseline([]byte(raw)); err == nil {
			t.Fatal("unknown or duplicate named field accepted")
		}
	}
}

func TestNamedGrantExpiryAndRecheckCannotBeBypassed(t *testing.T) {
	t.Parallel()
	b, input := namedFixture(t)
	compiler := testCompiler(t, b)
	candidate, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Grants[0].Port = 80
	if err := compiler.CheckCandidate(t.Context(), candidate); err == nil {
		t.Fatal("candidate port bypassed the ordered root ceiling")
	}
	input.Now = input.Now.Add(90 * time.Second)
	if _, err := compiler.Compile(input); err == nil {
		t.Fatal("expired observation supplied named permission")
	}
}

func TestNamedTranslationCeilingChecksLogicalAndAliasDestinations(t *testing.T) {
	t.Parallel()
	for _, translation := range []string{"nat64", "nat46"} {
		t.Run(translation, func(t *testing.T) {
			t.Parallel()
			for _, denied := range []bool{false, true} {
				b, input := namedFixture(t)
				rule := testRule()
				rule.Direction, rule.DestinationPorts = FromDevice, []uint16{443}
				peer := "10.240.2.20/32"
				if translation == "nat46" {
					peer = "fdca:1a2b:2::20/128"
					input.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("10.240.3.10")
					input.Bindings.Records[0].Addresses[0].Source = "kea_dhcp4"
				}
				rule.Peer.Addresses = []string{peer}
				group := accessGroup(t, "access", false, rule)
				raw := strings.ReplaceAll(*group.Policy, "untrusted", "devices")
				group.Policy = &raw
				input.Directory.Groups[1] = group
				allow := NetworkRule{Action: "allow", Authorization: "inherit", Protocol: "tcp", Ports: []uint16{443},
					From: []NetworkSelector{{Interface: "lan13"}},
					To:   []NetworkSelector{{Interface: "lan12", Addresses: prefixes(peer)}}}
				b.NetworkModel.Rules = []NetworkRule{allow}
				if denied {
					deny := allow
					deny.Action = "deny"
					// NAT64 must retain an IPv4 destination deny behind an
					// IPv6 original packet. NAT46 must also retain a deny
					// expressed using the public alias representation.
					if translation == "nat46" {
						deny.To = []NetworkSelector{{Interface: "nat46", Addresses: prefixes("10.250.0.20/32")}}
					}
					b.NetworkModel.Rules = append([]NetworkRule{deny}, b.NetworkModel.Rules...)
				}
				compiler := testCompiler(t, b)
				candidate, err := compiler.Compile(input)
				if err != nil || len(candidate.Grants) != 1 && !denied || len(candidate.Grants) != 0 && denied {
					t.Fatalf("translation=%s denied=%t: %+v, %v", translation, denied, candidate, err)
				}
				if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestExplicitDirectoryAuthorizationIsIndependentOfInheritedNetworkPolicy(t *testing.T) {
	t.Parallel()
	for _, authorization := range []string{"directory", "inherit", "owner"} {
		t.Run(authorization, func(t *testing.T) {
			t.Parallel()
			b, input := namedFixture(t)
			for index, group := range input.Directory.Groups {
				raw := strings.ReplaceAll(*group.Policy, "devices", "servers")
				input.Directory.Groups[index].Policy = &raw
			}
			rule := testRule()
			rule.Direction, rule.Protocol, rule.DestinationPorts = FromDevice, "tcp", []uint16{443}
			rule.Peer.Addresses = []string{"9.9.9.9/32"}
			group := accessGroup(t, "access", false, rule)
			raw := strings.ReplaceAll(*group.Policy, "untrusted", "servers")
			group.Policy = &raw
			input.Directory.Groups[1] = group
			input.Bindings.Records[0].Interface, input.Bindings.Records[0].VLAN = "lan12", 12
			input.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:2::10")
			b.NetworkModel.Rules = []NetworkRule{{Action: "allow", Authorization: authorization, Protocol: "tcp", Ports: []uint16{443},
				From: []NetworkSelector{{Interface: "lan12", Addresses: prefixes("fdca:1a2b:2::10/128")}},
				To:   []NetworkSelector{{Interface: "wan", Addresses: prefixes("9.9.9.9/32")}}}}
			compiler := testCompiler(t, b)
			candidate, err := compiler.Compile(input)
			want := 0
			if authorization == "directory" {
				want = 1
			}
			if err != nil || len(candidate.Grants) != want {
				t.Fatalf("explicit authorization=%s: %+v, %v", authorization, candidate, err)
			}
			if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNamedTranslatedSelectorsKeepAddressAndAttachmentTogether(t *testing.T) {
	t.Parallel()
	for _, translation := range []struct {
		name, native, translated, translator, attachment string
	}{
		{"private NAT64", "10.240.2.20/32", "fdca:1a2b:64::af0:214/128", "private64", "lan12"},
		{"public NAT64", "93.184.216.34/32", "64:ff9b::5db8:d822/128", "global64", "wan"},
		{"NAT46", "fdca:1a2b:2::20/128", "10.250.0.20/32", "nat46", "lan12"},
	} {
		for _, scope := range []struct {
			name, attachment  string
			translated, match bool
		}{
			{name: "native attachment and native address", attachment: "native", match: true},
			{name: "translator attachment and translated address", attachment: "translator", translated: true, match: true},
			{name: "translator attachment cannot borrow native address", attachment: "translator"},
			{name: "native attachment cannot borrow translated address", attachment: "native", translated: true},
		} {
			t.Run(translation.name+"/"+scope.name, func(t *testing.T) {
				t.Parallel()
				for _, action := range []string{"allow", "deny"} {
					b, input := namedFixture(t)
					rule := testRule()
					rule.Direction, rule.DestinationPorts = FromDevice, []uint16{443}
					if translation.name == "NAT46" {
						input.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("10.240.3.10")
						input.Bindings.Records[0].Addresses[0].Source = "kea_dhcp4"
					}
					rule.Peer.Addresses = []string{translation.native}
					group := accessGroup(t, "access", false, rule)
					raw := strings.ReplaceAll(*group.Policy, "untrusted", "devices")
					group.Policy = &raw
					input.Directory.Groups[1] = group
					attachment, address := translation.attachment, translation.native
					if scope.attachment == "translator" {
						attachment = translation.translator
					}
					if scope.translated {
						address = translation.translated
					}
					selected := NetworkRule{Action: action, Authorization: "directory", Protocol: "tcp", Ports: []uint16{443},
						From: []NetworkSelector{{Interface: "lan13"}},
						To:   []NetworkSelector{{Interface: attachment, Addresses: prefixes(address)}}}
					b.NetworkModel.Rules = []NetworkRule{selected}
					if action == "deny" {
						fallback := selected
						fallback.Action = "allow"
						fallback.To = []NetworkSelector{{Interface: translation.attachment, Addresses: prefixes(translation.native)}}
						b.NetworkModel.Rules = append(b.NetworkModel.Rules, fallback)
					}
					compiler := testCompiler(t, b)
					candidate, err := compiler.Compile(input)
					want := 0
					if scope.match == (action == "allow") {
						want = 1
					}
					if err != nil || len(candidate.Grants) != want {
						t.Fatalf("action=%s: grants=%d want=%d, error=%v", action, len(candidate.Grants), want, err)
					}
					if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
						t.Fatal("candidate recheck changed endpoint interpretation", err)
					}
					if !scope.match && action == "allow" {
						// A matching hash is not permission: independently recheck a
						// grant from a paired ceiling against this crossed ceiling.
						b.NetworkModel.Rules[0].To = []NetworkSelector{{Interface: translation.attachment, Addresses: prefixes(translation.native)}}
						forged, err := testCompiler(t, b).Compile(input)
						if err != nil || len(forged.Grants) != 1 {
							t.Fatal("paired positive control did not compile", err)
						}
						forged.BaselineHash = compiler.BaselineHash()
						if err := compiler.CheckCandidate(t.Context(), forged); err == nil {
							t.Fatal("candidate recheck admitted a crossed attachment")
						}
					}
				}
			})
		}
	}
}

func TestNamedTranslatedCallbacksKeepDeviceAttachmentWithItsAddress(t *testing.T) {
	t.Parallel()
	for _, translation := range []struct{ name, device, translated, peer, translator string }{
		{"NAT46", "fdca:1a2b:3::10/128", "10.250.0.10/32", "10.240.2.10/32", "nat46"},
		{"NAT64", "10.240.3.10/32", "fdca:1a2b:64::af0:30a/128", "fdca:1a2b:2::10/128", "private64"},
	} {
		for _, crossed := range []bool{false, true} {
			t.Run(translation.name+map[bool]string{false: "/paired", true: "/crossed"}[crossed], func(t *testing.T) {
				t.Parallel()
				b, input := namedFixture(t)
				if translation.name == "NAT46" {
					b.NAT46 = append(b.NAT46, NAT46{ID: "device46", Alias: netip.MustParseAddr("10.250.0.10"),
						Target: netip.MustParseAddr("fdca:1a2b:3::10"), Ready: true})
				} else {
					input.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("10.240.3.10")
					input.Bindings.Records[0].Addresses[0].Source = "kea_dhcp4"
				}
				rule := testRule()
				rule.Direction, rule.DestinationPorts, rule.Peer.Addresses = ToDevice, []uint16{6053}, []string{translation.peer}
				group := accessGroup(t, "access", false, rule)
				raw := strings.ReplaceAll(*group.Policy, "untrusted", "devices")
				group.Policy = &raw
				input.Directory.Groups[1] = group
				target := translation.translated
				if crossed {
					target = translation.device
				}
				b.NetworkModel.Rules = []NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "tcp", Ports: []uint16{6053},
					From: []NetworkSelector{{Interface: "lan12", Addresses: prefixes(translation.peer)}},
					To:   []NetworkSelector{{Interface: translation.translator, Addresses: prefixes(target)}}}}
				compiler := testCompiler(t, b)
				candidate, err := compiler.Compile(input)
				want := 1
				if crossed {
					want = 0
				}
				if err != nil || len(candidate.Grants) != want {
					t.Fatalf("grants=%d want=%d, error=%v", len(candidate.Grants), want, err)
				}
				if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
