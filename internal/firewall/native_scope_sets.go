package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Factor only within one endpoint alternative and one address family. Keep
// overlapping or adjacent prefixes separate: nft can coalesce their intervals
// into a different literal representation. The unmodified conjunction remains
// available for those cases, including /0 mixed with a narrower prefix.
func nativePrefixGroups(prefixes []netip.Prefix) [][]netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	if len(prefixes) == 1 {
		return [][]netip.Prefix{prefixes}
	}
	ordered := slices.Clone(prefixes)
	slices.SortFunc(ordered, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	for index := 1; index < len(ordered); index++ {
		last := nativePrefixLast(ordered[index-1])
		if last.Compare(ordered[index].Addr()) >= 0 || last.Next() == ordered[index].Addr() {
			groups := make([][]netip.Prefix, len(prefixes))
			for index, prefix := range prefixes {
				groups[index] = []netip.Prefix{prefix}
			}
			return groups
		}
	}
	return [][]netip.Prefix{prefixes}
}

func nativePrefixLast(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	last, _ := netip.AddrFromSlice(bytes)
	return last
}

func nativePrefixLiteral(prefix netip.Prefix) (any, string) {
	if prefix.Bits() == prefix.Addr().BitLen() {
		return prefix.Addr().String(), prefix.Addr().String()
	}
	return controllerPrefix(prefix), prefix.String()
}

// The representative predicate retains its interface, MAC, family and typed
// transport checks. Replacing one equality with a literal set preserves exactly
// the independent alternatives within this original conjunction.
func nativeAlternativeScope(protocol string, family int, source, target policy.NetworkSelector, from, to []netip.Prefix, ports []uint16, reply, physical bool) (nativeScope, error) {
	if len(from) == 0 || len(to) == 0 || len(ports) == 0 {
		return nativeScope{}, errors.New("firewall: missing compiled scope alternatives")
	}
	scope := nativeScopePredicate(protocol, family, source, target, from[0], to[0], ports[0], reply, physical)
	spelling := "ip"
	if family == 6 {
		spelling = "ip6"
	}
	for _, column := range []struct {
		field    string
		prefixes []netip.Prefix
	}{{"saddr", from}, {"daddr", to}} {
		if len(column.prefixes) < 2 {
			continue
		}
		field := column.field
		if reply {
			if field == "saddr" {
				field = "daddr"
			} else {
				field = "saddr"
			}
		}
		values, literals := []any{}, []string{}
		for _, prefix := range column.prefixes {
			value, literal := nativePrefixLiteral(prefix)
			values, literals = append(values, value), append(literals, literal)
		}
		if err := nativeScopeLiteralSet(&scope, guardPayload(spelling, field), spelling+" "+field, values, literals); err != nil {
			return nativeScope{}, err
		}
	}
	if len(ports) > 1 {
		field := "dport"
		if reply {
			field = "sport"
		}
		values, literals := []any{}, []string{}
		for _, port := range ports {
			values, literals = append(values, port), append(literals, fmt.Sprint(port))
		}
		if err := nativeScopeLiteralSet(&scope, guardPayload(protocol, field), protocol+" "+field, values, literals); err != nil {
			return nativeScope{}, err
		}
	}
	return scope, nil
}

func nativeScopeLiteralSet(scope *nativeScope, left any, selector string, values []any, literals []string) error {
	for _, expression := range scope.expressions {
		object, ok := expression.(map[string]any)
		if !ok {
			continue
		}
		match, ok := object["match"].(map[string]any)
		if !ok || !reflect.DeepEqual(match["left"], left) {
			continue
		}
		original := selector + " " + literals[0]
		if match["op"] != "==" || !strings.Contains(scope.text, original) {
			return errors.New("firewall: invalid compiled literal alternative")
		}
		match["right"] = map[string]any{"set": values}
		scope.text = strings.Replace(scope.text, original, selector+" { "+strings.Join(literals, ", ")+" }", 1)
		return nil
	}
	return errors.New("firewall: missing compiled literal selector")
}

func nativeGroupedScopeCount(rule policy.NetworkRule) (int, error) {
	// Preserve the original bound on the logical selector product even when
	// factoring reduces the emitted program. No input quota is enlarged.
	if _, err := nativeScopeCount(rule); err != nil {
		return 0, err
	}
	count := 0
	for _, source := range rule.From {
		for _, target := range rule.To {
			for _, family := range []int{4, 6} {
				if rule.Family != 0 && rule.Family != family || rule.Protocol == "icmp" && family != 4 || rule.Protocol == "icmpv6" && family != 6 {
					continue
				}
				from := nativePrefixGroups(nativePrefixAlternatives(source.Addresses, family))
				to := nativePrefixGroups(nativePrefixAlternatives(target.Addresses, family))
				count += len(from) * len(to)
			}
		}
	}
	return count, nil
}
