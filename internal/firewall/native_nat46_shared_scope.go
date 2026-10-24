package firewall

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Shared scopes retain native destination prefixes. Alias selectors project
// only ready mappings and retain each target's attachment. The independent
// context binding must first pin the actual selected mapping and protocol.
func (model *nativeNAT46Model) sharedWireScopes(ctx context.Context, index int, original nativePacketContext, protocol string, reply, physical bool) ([]nativeScope, error) {
	if ctx == nil || model == nil || model.rules == nil || index < 0 || index >= len(model.rules.rules) || original.iface == "" || original.family != 0 && original.family != 4 && original.family != 6 ||
		protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return nil, errors.New("firewall: missing shared nat46 scope geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rule := model.rules.rules[index]
	if original.family == 6 || rule.Family == 6 || rule.Protocol != "any" && rule.Protocol != protocol {
		return nil, ctx.Err()
	}
	projected := policy.NetworkRule{Protocol: protocol, Ports: rule.Ports, Family: 6}
	for _, source := range rule.From {
		if source.Interface != "" && source.Interface != original.iface || source.MAC != "" && source.MAC != original.mac {
			continue
		}
		for _, prefix := range nativePrefixAlternatives(source.Addresses, 4) {
			if !prefix.IsValid() {
				prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			}
			projected.From = append(projected.From, policy.NetworkSelector{Interface: "nat46", Addresses: []netip.Prefix{nativeNAT46SourcePrefix(model.prefix, prefix)}})
		}
	}
	type destination struct {
		iface  string
		prefix netip.Prefix
	}
	targets := []destination{}
	appendTarget := func(candidate destination) {
		for _, target := range targets {
			if target.iface == candidate.iface && target.prefix.Bits() <= candidate.prefix.Bits() && target.prefix.Contains(candidate.prefix.Addr()) {
				return
			}
		}
		targets = slices.DeleteFunc(targets, func(target destination) bool {
			return target.iface == candidate.iface && candidate.prefix.Bits() <= target.prefix.Bits() && candidate.prefix.Contains(target.prefix.Addr())
		})
		targets = append(targets, candidate)
	}
	for _, selector := range rule.To {
		for mappingIndex, mapping := range model.mappings {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !nativeNAT46Destination([]policy.NetworkSelector{selector}, mapping, false) {
				continue
			}
			covered, err := model.contextCovered(ctx, index, mappingIndex, original, protocol)
			if err != nil {
				return nil, err
			}
			if covered {
				continue
			}
			native := false
			if selector.Interface == "" || selector.Interface == mapping.targetInterface {
				if len(selector.Addresses) == 0 {
					appendTarget(destination{selector.Interface, netip.PrefixFrom(netip.IPv6Unspecified(), 0)})
					native = true
				}
				for _, prefix := range selector.Addresses {
					if prefix.Addr().Is6() && prefix.Contains(mapping.target) {
						appendTarget(destination{selector.Interface, prefix})
						native = true
					}
				}
			}
			if !native {
				appendTarget(destination{mapping.targetInterface, netip.PrefixFrom(mapping.target, 128)})
			}
		}
	}
	for _, target := range targets {
		projected.To = append(projected.To, policy.NetworkSelector{Interface: target.iface, Addresses: []netip.Prefix{target.prefix}})
	}
	if len(projected.From) == 0 || len(projected.To) == 0 {
		return nil, ctx.Err()
	}
	if protocol == "icmp" {
		projected.Protocol = "any"
	}
	if _, err := nativeScopeCount(projected); err != nil {
		return nil, err
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
		for index := range scopes {
			scopes[index] = nativeJoin(scopes[index], nativeMatch("icmpv6 type "+kind, guardPayload("icmpv6", "type"), kind), nativeMatch("icmpv6 code 0", guardPayload("icmpv6", "code"), 0))
		}
	}
	return scopes, ctx.Err()
}
