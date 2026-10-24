package firewall

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// A correlated reply retains its original authorization, but must still obey
// an earlier matching reverse-direction owner deny. These selectors describe
// the actual return packet, including its destination port. A reverse allow
// only ends this deny scan; it never replaces the original flow permission.
func (access *nativeAccess) compileNAT46Reverse(ctx context.Context, plan *nativeNAT46ContextPlan) error {
	for _, physical := range []bool{false, true} {
		graph := access.inet
		if physical {
			graph = access.netdev
		}
		for _, wire := range []bool{false, true} {
			selector := nativeNAT46ReverseName(wire)
			shared := map[string]string{}
			for _, group := range plan.groups {
				key := group.iface + "/" + group.protocol
				name, exists := shared[key]
				if !exists {
					name = fmt.Sprintf("%s_%d", selector, group.index)
					shared[key] = name
					for index, rule := range plan.model.rules.rules {
						scopes, err := plan.model.reverseScopes(ctx, index, group, wire, physical)
						if err != nil {
							return err
						}
						verdict := "return"
						if rule.Action == "deny" {
							verdict = "drop"
						}
						for _, scope := range scopes {
							graph[name] = append(graph[name], nativeJoin(scope, nativeVerdict(verdict, "")))
						}
					}
					graph[name] = append(graph[name], nativeVerdict("return", ""))
				}
				graph[selector] = append(graph[selector], nativeJoin(group.binding(plan.model, wire, true, physical), nativeVerdict("goto", name)))
			}
			graph[selector] = append(graph[selector], nativeVerdict("drop", ""))
		}
	}
	return ctx.Err()
}

func nativeNAT46ReverseName(wire bool) string {
	if wire {
		return "native_n46_wire_reverse"
	}
	return "native_n46_raw_reverse"
}

func (model *nativeNAT46Model) reverseScopes(ctx context.Context, index int, group nativeNAT46ContextGroup, wire, physical bool) ([]nativeScope, error) {
	rule := model.rules.rules[index]
	if rule.Protocol != "any" && rule.Protocol != group.protocol && (!wire || group.protocol != "icmp" || rule.Protocol != "icmpv6") {
		return nil, ctx.Err()
	}
	family, protocol := 4, group.protocol
	if protocol == "icmp" {
		// The typed echo fields below already constrain the protocol. nft
		// removes a redundant meta l4proto match from its canonical listing.
		protocol = "any"
	}
	if wire {
		family = 6
	}
	projected := policy.NetworkRule{Family: family, Protocol: protocol, Ports: rule.Ports}
	seen := map[policyEndpoint]bool{}
	for _, source := range rule.From {
		for _, mapping := range model.mappings {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			native := rule.Family != 4 && (source.Interface == "" || source.Interface == mapping.targetInterface) && nativeNAT46Contains(source.Addresses, mapping.target)
			alias := rule.Family != 6 && (source.Interface == "" || source.Interface == "nat46") && nativeNAT46Contains(source.Addresses, mapping.alias)
			if !native && !alias {
				continue
			}
			iface, address := "nat46", mapping.alias
			if wire {
				iface, address = mapping.targetInterface, mapping.target
			}
			key := policyEndpoint{iface, netip.PrefixFrom(address, address.BitLen())}
			if !seen[key] {
				seen[key] = true
				projected.From = append(projected.From, policy.NetworkSelector{Interface: iface, Addresses: []netip.Prefix{key.prefix}})
			}
		}
	}
	for _, target := range rule.To {
		if target.Interface != "" && target.Interface != group.iface {
			continue
		}
		for _, prefix := range nativePrefixAlternatives(target.Addresses, 4) {
			if rule.Family == 6 && prefix.IsValid() {
				continue
			}
			if !prefix.IsValid() {
				prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			}
			iface := group.iface
			if wire {
				iface, prefix = "nat46", nativeNAT46SourcePrefix(model.prefix, prefix)
			}
			projected.To = append(projected.To, policy.NetworkSelector{Interface: iface, Addresses: []netip.Prefix{prefix}})
		}
	}
	if len(projected.From) == 0 || len(projected.To) == 0 {
		return nil, ctx.Err()
	}
	scopes, err := (&nativeRuleSet{rules: []policy.NetworkRule{projected}}).scopes(ctx, 0, false, physical)
	if err != nil {
		return nil, err
	}
	if group.protocol == "icmp" {
		proto := "icmp"
		if wire {
			proto = "icmpv6"
		}
		for i := range scopes {
			scopes[i] = nativeJoin(scopes[i], nativeMatch(proto+" type echo-reply", guardPayload(proto, "type"), "echo-reply"), nativeMatch(proto+" code 0", guardPayload(proto, "code"), 0))
		}
	}
	return scopes, ctx.Err()
}

type policyEndpoint struct {
	iface  string
	prefix netip.Prefix
}

func nativeNAT46Contains(prefixes []netip.Prefix, address netip.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
