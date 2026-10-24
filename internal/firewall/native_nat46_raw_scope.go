package firewall

import (
	"context"
	"net/netip"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// The mapped context independently selects one ready alias. Project only
// destinations paired with that alias or its real IPv6 target; keep original
// source CIDRs, attachment, MAC class, protocol and listener ordering.
func (model *nativeNAT46Model) sharedRawScopes(ctx context.Context, index int, original nativePacketContext, protocol string, reply, physical bool) ([]nativeScope, error) {
	rule := model.rules.rules[index]
	if rule.Family == 6 || rule.Protocol != "any" && rule.Protocol != protocol {
		return nil, ctx.Err()
	}
	projected := policy.NetworkRule{Family: 4, Protocol: protocol, Ports: rule.Ports}
	for _, source := range rule.From {
		if source.Interface != "" && source.Interface != original.iface || source.MAC != "" && source.MAC != original.mac {
			continue
		}
		source.Interface, source.MAC = original.iface, ""
		projected.From = append(projected.From, source)
	}
	for mappingIndex, mapping := range model.mappings {
		if nativeNAT46Destination(rule.To, mapping, false) {
			covered, err := model.contextCovered(ctx, index, mappingIndex, original, protocol)
			if err != nil {
				return nil, err
			}
			if covered {
				continue
			}
			projected.To = append(projected.To, policy.NetworkSelector{Interface: "nat46", Addresses: []netip.Prefix{netip.PrefixFrom(mapping.alias, 32)}})
		}
	}
	if len(projected.From) == 0 || len(projected.To) == 0 {
		return nil, ctx.Err()
	}
	if protocol == "icmp" {
		projected.Protocol = "any"
	}
	scopes, err := (&nativeRuleSet{rules: []policy.NetworkRule{projected}}).scopes(ctx, 0, reply, physical)
	if err != nil {
		return nil, err
	}
	if protocol == "icmp" {
		kind := "echo-request"
		if reply {
			kind = "echo-reply"
		}
		for i := range scopes {
			scopes[i] = nativeJoin(scopes[i], nativeMatch("icmp type "+kind, guardPayload("icmp", "type"), kind), nativeMatch("icmp code 0", guardPayload("icmp", "code"), 0))
		}
	}
	return scopes, ctx.Err()
}
