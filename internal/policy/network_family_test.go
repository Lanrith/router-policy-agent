package policy

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/binding"
)

func TestNamedDualStackGrantsDoNotRequireATranslator(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"dual stack", "IPv4 only", "IPv6 only", "deny IPv4", "deny IPv6"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, input := namedFixture(t)
			b.NAT64, b.NAT46, b.NAT46Pools = []NAT64{}, []NAT46{}, []netip.Prefix{}
			b.NetworkModel.Rules = []NetworkRule{{Action: "allow", Authorization: "directory", Protocol: "any", From: []NetworkSelector{{}}, To: []NetworkSelector{{}}}}
			ipv4 := input.Bindings.Records[0].Addresses[0]
			ipv4.IP, ipv4.Source, ipv4.OwnershipID = netip.MustParseAddr("10.240.3.10"), "kea_dhcp4", "synthetic-native-v4"
			input.Bindings.Records[0].Addresses = append(input.Bindings.Records[0].Addresses, ipv4)
			rules := []any{}
			for _, direction := range []string{"to_device", "from_device"} {
				for _, protocol := range []string{"tcp", "udp"} {
					rules = append(rules, map[string]any{"id": direction + protocol, "direction": direction, "peer": map[string]any{"addresses": []string{"10.240.2.10/32", "fdca:1a2b:2::10/128"}}, "protocol": protocol, "destination_ports": []int{6053}, "reason": "Synthetic dual-stack access"})
				}
			}
			raw, err := json.Marshal(map[string]any{"schema_version": 1, "kind": "access", "vlan_role": "devices", "temporary": false, "rules": rules})
			if err != nil {
				t.Fatal(err)
			}
			value := string(raw)
			input.Directory.Groups[1].Policy = &value
			expected := 8
			switch name {
			case "IPv4 only":
				input.Bindings.Records[0].Addresses = []binding.Address{ipv4}
				expected = 4
			case "IPv6 only":
				input.Bindings.Records[0].Addresses = input.Bindings.Records[0].Addresses[:1]
				expected = 4
			case "deny IPv4", "deny IPv6":
				family := 4
				if name == "deny IPv6" {
					family = 6
				}
				deny := NetworkRule{Action: "deny", Authorization: "inherit", Protocol: "any", Family: family, From: []NetworkSelector{{}}, To: []NetworkSelector{{}}}
				b.NetworkModel.Rules = append([]NetworkRule{deny}, b.NetworkModel.Rules...)
				expected = 0
			}
			compiler := testCompiler(t, b)
			candidate, err := compiler.Compile(input)
			if err != nil || len(candidate.Grants) != expected {
				t.Fatalf("native family combinations: %d grants, want %d, denials=%v, error=%v", len(candidate.Grants), expected, candidate.Denials, err)
			}
			if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
				t.Fatal(err)
			}
			if expected == 0 && len(candidate.Denials) != 1 {
				t.Fatal("compatible denied family weakened all-or-nothing policy validation")
			}
			for _, grant := range candidate.Grants {
				if grant.Device.Real.Is4() != grant.Peer.Real.Is4() {
					t.Fatal("unreachable cross-family grant manufactured")
				}
			}
		})
	}
}
