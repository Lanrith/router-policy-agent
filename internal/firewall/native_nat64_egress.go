package firewall

import (
	"context"
	"errors"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// A raw packet reaches the translator before IPv4 routing selects its final
// interface. Keep each possible final path separate: a WAN-only deny cannot
// terminate a LAN path, and a LAN permit cannot become a WAN permit. Rule
// indices and authorization remain those of the original immutable graph.
// The raw predicates alone never establish which final path is authorized.
type nativeNAT64EgressPolicy struct {
	iface string
	raw   *nativeRuleSet
}

func nativeNAT64EgressPolicies(ctx context.Context, set *nativeRuleSet, transport *nativeNAT64Transport) ([]nativeNAT64EgressPolicy, error) {
	if ctx == nil || set == nil || transport == nil || len(transport.destinations) == 0 ||
		set.baselineHash == "" || set.baselineHash != transport.baselineHash {
		return nil, errors.New("firewall: missing NAT64 final-egress dependencies")
	}
	paths := make([]nativeNAT64EgressPolicy, 0, len(transport.destinations))
	for _, iface := range transport.destinations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		filtered := &nativeRuleSet{baselineHash: set.baselineHash, rules: make([]policy.NetworkRule, len(set.rules))}
		for index, rule := range set.rules {
			selected := rule
			selected.To = nil
			for _, target := range rule.To {
				switch target.Interface {
				case "", transport.component:
					selected.To = append(selected.To, target)
				case iface:
					// Projection encodes IPv4 destination prefixes under this
					// translator. The retained path identity, not the rewritten
					// raw oifname, owns the actual final interface constraint.
					target.Interface = transport.uplink
					selected.To = append(selected.To, target)
				}
			}
			filtered.rules[index] = selected
		}
		raw, err := nativeNAT64ProjectedRules(ctx, filtered, transport)
		if err != nil {
			return nil, err
		}
		paths = append(paths, nativeNAT64EgressPolicy{iface: iface, raw: raw})
	}
	return slices.Clip(paths), ctx.Err()
}
