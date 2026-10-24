package firewall

import (
	"context"
	"errors"
	"net/netip"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Keep the complete generated graph below a fixed count as well as the byte
// limit enforced when the immutable artifact is built. Thirty-two thousand
// rules accommodates the bounded multi-network/dual-translator profile while
// remaining far below nftables' practical object limits.
const nativeRuleCapacity = 32768

func nativeRuleHasFamily(rule policy.NetworkRule, family int) bool {
	if rule.Family != 0 && rule.Family != family || rule.Protocol == "icmp" && family != 4 || rule.Protocol == "icmpv6" && family != 6 {
		return false
	}
	for _, source := range rule.From {
		if nativePrefixCount(source.Addresses, family) == 0 {
			continue
		}
		for _, target := range rule.To {
			if nativePrefixCount(target.Addresses, family) != 0 {
				return true
			}
		}
	}
	return false
}

// Count selector products before allocating text or expression trees. This is
// the unfactored conjunction expansion, retaining the original input quota.
func nativeScopeCount(rule policy.NetworkRule) (int, error) {
	count, ports := 0, max(1, len(rule.Ports))
	for _, source := range rule.From {
		for _, target := range rule.To {
			for _, family := range []int{4, 6} {
				if rule.Family != 0 && rule.Family != family || rule.Protocol == "icmp" && family != 4 || rule.Protocol == "icmpv6" && family != 6 {
					continue
				}
				from, to := nativePrefixCount(source.Addresses, family), nativePrefixCount(target.Addresses, family)
				if from == 0 || to == 0 {
					continue
				}
				if from > (nativeRuleCapacity-count)/to/ports {
					return 0, errors.New("firewall: native predicate expansion exceeds capacity")
				}
				count += from * to * ports
			}
		}
	}
	return count, nil
}

func nativePrefixCount(prefixes []netip.Prefix, family int) int {
	if len(prefixes) == 0 {
		return 1
	}
	count := 0
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() == (family == 4) {
			count++
		}
	}
	return count
}

// Budget the reachable physical predicates and fixed decision/token plumbing.
// This avoids multiplying every scope by every interface and context, while
// retaining the existing program cap and rejecting oversized trees up front.
func (access *nativeAccess) ruleBudget(ctx context.Context, set *nativeRuleSet, index int, managed, _ []string) (int, error) {
	rule := set.rules[index]
	scopes, err := nativeGroupedScopeCount(rule)
	if err != nil {
		return 0, err
	}
	if rule.Action == "deny" {
		return 3 * scopes, nil
	}
	modes, decision := 3, 40+8*len(managed)
	switch rule.Authorization {
	case "owner":
		modes, decision = 2, 32+8*len(managed)
	case "directory":
		modes, decision = 1, 16
	}
	contexts := len(access.contexts[index])
	tokens := 13
	if contexts != 0 {
		tokens = 21
	}
	count := 5*scopes + decision + modes*tokens
	if contexts != 0 {
		// One selector per direction retains all original predicates. Its
		// callers keep independent owner/configuration/directory checks.
		count += 4 + 2*contexts
	}
	if count > nativeRuleCapacity {
		return 0, errors.New("firewall: native access expansion exceeds capacity")
	}
	for _, reply := range []bool{false, true} {
		for _, group := range nativePhysicalContexts(access.contexts[index], reply) {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			selected := set.physicalRule(index, group.packet, reply, false, "")
			scopes, err := nativeGroupedScopeCount(selected)
			if err != nil {
				return 0, err
			}
			count += scopes
			if count > nativeRuleCapacity {
				return 0, errors.New("firewall: native access expansion exceeds capacity")
			}
		}
	}
	return count, nil
}
