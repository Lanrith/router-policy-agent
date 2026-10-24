package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

type nativeContextSource struct {
	source    *nativeSourceClass
	family    int
	pools     []netip.Prefix
	predicate nativeScope
}

func nativeContextSources(ctx context.Context, set *nativeRuleSet, iface string) ([]nativeContextSource, error) {
	if ctx == nil || set == nil {
		return nil, errors.New("firewall: missing source context dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var pools []netip.Prefix
	for _, path := range set.uplinkNAT {
		if path.Interface == iface {
			pools = append(pools, path.Sources...)
		}
	}
	if len(pools) == 0 {
		return []nativeContextSource{{}}, ctx.Err()
	}
	boundaries := []netip.Prefix{}
	for _, rule := range set.rules {
		for _, endpoints := range [][]policy.NetworkSelector{rule.From, rule.To} {
			for _, source := range endpoints {
				if source.Interface == "" || source.Interface == iface {
					boundaries = append(boundaries, source.Addresses...)
				}
			}
		}
	}
	classes, err := partitionNativeSources(ctx, pools, boundaries)
	if err != nil {
		return nil, err
	}
	result := make([]nativeContextSource, 0, len(classes)+2)
	for _, class := range classes {
		predicate := nativeScopePredicate("any", 4, policy.NetworkSelector{}, policy.NetworkSelector{}, class.prefix, netip.Prefix{}, 0, false, false)
		for _, child := range class.children {
			predicate = nativeJoin(predicate, nativeSourceExclusion(child))
		}
		result = append(result, nativeContextSource{source: &class, family: 4, pools: slices.Clone(pools), predicate: predicate})
	}
	outside := nativeScope{}
	for _, pool := range pools {
		outside = nativeJoin(outside, nativeSourceExclusion(pool))
	}
	result = append(result, nativeContextSource{family: 4, pools: slices.Clone(pools), predicate: outside}, nativeContextSource{family: 6, predicate: nativeMatch("meta nfproto ipv6", guardMeta("nfproto"), "ipv6")})
	return result, ctx.Err()
}

func nativeSourceExclusion(prefix netip.Prefix) nativeScope {
	value, text := controllerPrefix(prefix), prefix.String()
	if prefix.Bits() == 32 {
		value, text = prefix.Addr().String(), prefix.Addr().String()
	}
	return nativeScope{text: fmt.Sprintf("ip saddr != %s", text), expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardPayload("ip", "saddr"), "right": value}}}}
}

func (class nativeContextSource) relevant(rule policy.NetworkRule, iface, mac string) bool {
	if class.family == 0 {
		return nativeRuleHasFamily(rule, 4) || nativeRuleHasFamily(rule, 6)
	}
	if !nativeRuleHasFamily(rule, class.family) {
		return false
	}
	for direction, endpoints := range [][]policy.NetworkSelector{rule.From, rule.To} {
		for _, endpoint := range endpoints {
			if endpoint.Interface != "" && endpoint.Interface != iface || direction == 0 && endpoint.MAC != "" && endpoint.MAC != mac {
				continue
			}
			if len(endpoint.Addresses) == 0 {
				return true
			}
			for _, prefix := range endpoint.Addresses {
				if prefix.Addr().Is4() != (class.family == 4) {
					continue
				}
				if class.family == 6 {
					return true
				}
				if class.source != nil {
					if class.source.within(prefix) {
						return true
					}
					continue
				}
				contained := false
				for _, pool := range class.pools {
					contained = contained || pool.Bits() <= prefix.Bits() && pool.Contains(prefix.Addr())
				}
				if !contained {
					return true
				}
			}
		}
	}
	return false
}
