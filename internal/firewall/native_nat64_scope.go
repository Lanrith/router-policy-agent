package firewall

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeNAT64DestinationPrefix(translation, destination netip.Prefix) netip.Prefix {
	if !translation.IsValid() || !translation.Addr().Is6() || translation.Bits() != 96 ||
		!destination.IsValid() || !destination.Addr().Is4() {
		return netip.Prefix{}
	}
	address := translation.Addr().As16()
	ipv4 := destination.Addr().As4()
	copy(address[12:], ipv4[:])
	return netip.PrefixFrom(netip.AddrFrom16(address), 96+destination.Bits()).Masked()
}

func nativeNAT64IPv4Prefix(translation, encoded netip.Prefix) netip.Prefix {
	if !translation.IsValid() || !encoded.IsValid() || !translation.Contains(encoded.Addr()) || encoded.Bits() < 96 {
		return netip.Prefix{}
	}
	encodedAddress := encoded.Addr().As16()
	var address [4]byte
	copy(address[:], encodedAddress[12:])
	return netip.PrefixFrom(netip.AddrFrom4(address), encoded.Bits()-96).Masked()
}

// nativeNAT64ProjectedRules preserves original rule indices. IPv4 uplink
// targets are encoded under this component's /96 before first-match policy is
// evaluated; explicit translator selectors retain their IPv6 representation.
// Incompatible entries remain inert placeholders so a connection mark always
// names the same immutable rule in the original graph.
func nativeNAT64ProjectedRules(ctx context.Context, set *nativeRuleSet, transport *nativeNAT64Transport) (*nativeRuleSet, error) {
	if ctx == nil || set == nil || transport == nil || set.baselineHash == "" || set.baselineHash != transport.baselineHash {
		return nil, errors.New("firewall: missing NAT64 projected rule dependencies")
	}
	projected := &nativeRuleSet{baselineHash: set.baselineHash, rules: make([]policy.NetworkRule, len(set.rules))}
	for index, rule := range set.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		candidate := policy.NetworkRule{Action: rule.Action, Authorization: rule.Authorization, Protocol: rule.Protocol, Ports: slices.Clone(rule.Ports), Family: 6}
		if rule.Family == 4 || !slices.Contains([]string{"any", "tcp", "udp", "icmp", "icmpv6"}, rule.Protocol) {
			projected.rules[index] = candidate
			continue
		}
		if candidate.Protocol == "icmp" {
			candidate.Protocol = "icmpv6"
		}
		for _, source := range rule.From {
			selected := source
			selected.Addresses = nativeNAT64FamilyPrefixes(source.Addresses, true)
			if len(source.Addresses) == 0 || len(selected.Addresses) != 0 {
				candidate.From = append(candidate.From, selected)
			}
		}
		for _, target := range rule.To {
			selected := policy.NetworkSelector{Interface: transport.component}
			switch target.Interface {
			case "", transport.component:
				if len(target.Addresses) == 0 {
					selected.Addresses = append(selected.Addresses, transport.prefix)
				}
				for _, prefix := range target.Addresses {
					if prefix.Addr().Is6() && prefix.Overlaps(transport.prefix) {
						selected.Addresses = append(selected.Addresses, prefix)
					} else if target.Interface == "" && prefix.Addr().Is4() {
						selected.Addresses = append(selected.Addresses, nativeNAT64DestinationPrefix(transport.prefix, prefix))
					}
				}
			case transport.uplink:
				if len(target.Addresses) == 0 {
					selected.Addresses = append(selected.Addresses, transport.prefix)
				}
				for _, prefix := range target.Addresses {
					if prefix.Addr().Is4() {
						selected.Addresses = append(selected.Addresses, nativeNAT64DestinationPrefix(transport.prefix, prefix))
					}
				}
			}
			selected.Addresses = slices.DeleteFunc(selected.Addresses, func(prefix netip.Prefix) bool { return !prefix.IsValid() })
			slices.SortFunc(selected.Addresses, func(a, b netip.Prefix) int {
				if compared := a.Addr().Compare(b.Addr()); compared != 0 {
					return compared
				}
				return a.Bits() - b.Bits()
			})
			selected.Addresses = slices.Compact(selected.Addresses)
			if len(selected.Addresses) != 0 {
				candidate.To = append(candidate.To, selected)
			}
		}
		if len(candidate.From) == 0 || len(candidate.To) == 0 {
			candidate.From, candidate.To = nil, nil
		}
		projected.rules[index] = candidate
	}
	return projected, ctx.Err()
}

func nativeNAT64FamilyPrefixes(prefixes []netip.Prefix, ipv6 bool) []netip.Prefix {
	result := []netip.Prefix{}
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() == ipv6 {
			result = append(result, prefix)
		}
	}
	return result
}
