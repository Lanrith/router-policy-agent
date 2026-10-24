package firewall

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestNativeFactoredScopesMatchUnfactoredPredicates(t *testing.T) {
	t.Parallel()
	prefixes := func(values ...string) []netip.Prefix {
		result := []netip.Prefix{}
		for _, value := range values {
			result = append(result, netip.MustParsePrefix(value))
		}
		return result
	}
	rule := policy.NetworkRule{Action: "allow", Authorization: "owner", Protocol: "tcp", Ports: []uint16{80, 443},
		From: []policy.NetworkSelector{
			{Interface: "a", MAC: "02:00:00:00:00:10", Addresses: prefixes("10.240.0.0/24", "10.240.2.0/24", "fdca:1::/64", "fdca:3::/64")},
			{Interface: "c", Addresses: prefixes("10.240.4.0/24", "fdca:5::/64")},
		},
		To: []policy.NetworkSelector{{Interface: "b", Addresses: prefixes("10.241.0.0/24", "10.241.2.0/24", "fdca:2::/64", "fdca:4::/64")}}}
	addresses := []string{"10.240.0.10", "10.240.2.10", "10.240.4.10", "10.240.1.10", "10.241.0.10", "10.241.2.10", "fdca:1::10", "fdca:3::10", "fdca:5::10", "fdca:2::10", "fdca:4::10", "fdca:6::10"}
	for _, reply := range []bool{false, true} {
		for _, physical := range []bool{false, true} {
			actual, err := (&nativeRuleSet{rules: []policy.NetworkRule{rule}}).scopes(t.Context(), 0, reply, physical)
			if err != nil {
				t.Fatal(err)
			}
			if len(actual) != 4 {
				t.Fatal("endpoint alternatives or families were merged", len(actual))
			}
			original := nativeUnfactoredScopeOracle(rule, reply, physical)
			for _, source := range addresses {
				for _, target := range addresses {
					for _, incoming := range []string{"a", "b", "c", "wrong"} {
						for _, outgoing := range []string{"a", "b", "c", "wrong"} {
							for _, port := range []uint16{80, 443, 81} {
								for _, protocol := range []string{"tcp", "udp"} {
									for _, mac := range []string{"02:00:00:00:00:10", "02:00:00:00:00:ee"} {
										packet := nativeScopeTestPacket{netip.MustParseAddr(source), netip.MustParseAddr(target), incoming, outgoing, protocol, mac, port}
										if nativeScopeTestAny(t, actual, packet) != nativeScopeTestAny(t, original, packet) {
											t.Fatalf("factoring changed a predicate: reply=%v physical=%v packet=%+v", reply, physical, packet)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func nativeUnfactoredScopeOracle(rule policy.NetworkRule, reply, physical bool) []nativeScope {
	result := []nativeScope{}
	for _, source := range rule.From {
		for _, target := range rule.To {
			for _, family := range []int{4, 6} {
				for _, from := range nativePrefixAlternatives(source.Addresses, family) {
					for _, to := range nativePrefixAlternatives(target.Addresses, family) {
						for _, port := range rule.Ports {
							result = append(result, nativeScopePredicate(rule.Protocol, family, source, target, from, to, port, reply, physical))
						}
					}
				}
			}
		}
	}
	return result
}

type nativeScopeTestPacket struct {
	source, target               netip.Addr
	incoming, outgoing, protocol string
	mac                          string
	port                         uint16
}

func nativeScopeTestAny(t testing.TB, scopes []nativeScope, packet nativeScopeTestPacket) bool {
	t.Helper()
	for _, scope := range scopes {
		matched := true
		for _, raw := range scope.expressions {
			match := nativeScopeTestObject(t, nativeScopeTestObject(t, raw)["match"])
			if match["op"] != "==" {
				t.Fatal("unexpected predicate operator")
			}
			left := nativeScopeTestObject(t, match["left"])
			var value any
			if meta, ok := left["meta"].(map[string]any); ok {
				switch meta["key"] {
				case "iifname":
					value = packet.incoming
				case "oifname":
					value = packet.outgoing
				case "nfproto":
					value = "ipv6"
					if packet.source.Is4() {
						value = "ipv4"
					}
				case "protocol":
					value = "ip6"
					if packet.source.Is4() {
						value = "ip"
					}
				default:
					t.Fatal("unexpected metadata predicate")
				}
			} else {
				payload := nativeScopeTestObject(t, left["payload"])
				switch payload["protocol"] {
				case "ip", "ip6":
					if packet.source.Is4() != (payload["protocol"] == "ip") || packet.target.Is4() != packet.source.Is4() {
						matched = false
						continue
					}
					value = packet.source
					if payload["field"] == "daddr" {
						value = packet.target
					}
				case "ether":
					value = packet.mac
				case "tcp", "udp":
					if packet.protocol != payload["protocol"] {
						matched = false
						continue
					}
					value = packet.port
				default:
					t.Fatal("unexpected payload predicate")
				}
			}
			matched = matched && nativeScopeTestValue(value, match["right"])
		}
		if matched {
			return true
		}
	}
	return false
}

func nativeScopeTestObject(t testing.TB, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		t.Fatal("predicate object missing")
	}
	return object
}

func nativeScopeTestValue(value, right any) bool {
	if object, ok := right.(map[string]any); ok {
		if set, ok := object["set"].([]any); ok {
			return slices.ContainsFunc(set, func(member any) bool { return nativeScopeTestValue(value, member) })
		}
		if prefix, ok := object["prefix"].(map[string]any); ok {
			address, ok := value.(netip.Addr)
			return ok && netip.MustParsePrefix(fmt.Sprint(prefix["addr"])+"/"+fmt.Sprint(prefix["len"])).Contains(address)
		}
	}
	if address, ok := value.(netip.Addr); ok {
		return address.String() == right
	}
	return reflect.DeepEqual(value, right)
}

func TestNativePrefixGroupingKeepsIntervalBoundaries(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		prefixes []string
		groups   int
	}{
		{[]string{"10.240.0.0/24", "10.240.2.0/24"}, 1},
		{[]string{"fdca:1::/64", "fdca:3::/64"}, 1},
		{[]string{"10.240.0.0/24", "10.240.1.0/24"}, 2},
		{[]string{"fdca:1::10/128", "fdca:1::11/128"}, 2},
		{[]string{"10.240.0.0/24", "10.240.0.10/32"}, 2},
		{[]string{"::/0", "fdca:1::/64"}, 2},
	} {
		prefixes := []netip.Prefix{}
		for _, value := range test.prefixes {
			prefixes = append(prefixes, netip.MustParsePrefix(value))
		}
		original := slices.Clone(prefixes)
		if len(nativePrefixGroups(prefixes)) != test.groups || !slices.Equal(prefixes, original) {
			t.Fatal("interval grouping changed a boundary or caller slice", test)
		}
	}
}
