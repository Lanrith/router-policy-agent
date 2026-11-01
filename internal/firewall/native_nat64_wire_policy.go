package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

type nativeNAT64WireContext struct {
	nativeSourceIdentity
	ids []uint64
}

// The imported token identifies the original source interface/MAC class and
// rule. IPv4 routing now supplies the real destination interface. Re-evaluate
// first-match policy with those facts and the allocator's current IPv6 source;
// a token from a different logical path must never supply permission here.
func (access *nativeAccess) compileNAT64WirePolicy(ctx context.Context, transport *nativeNAT64Transport) error {
	paths, err := nativeNAT64EgressPolicies(ctx, access.ruleSet, transport)
	if err != nil {
		return err
	}
	groups := []nativeNAT64WireContext{}
	indices := map[nativeSourceIdentity]int{}
	for index, rule := range access.ruleSet.rules {
		if !nativeNAT64RuleEligible(rule, transport) {
			continue
		}
		for _, packet := range access.contexts[index] {
			if packet.family != 0 && packet.family != 6 || packet.source != nil {
				continue
			}
			identity := nativeSourceIdentity{iface: packet.iface, mac: packet.mac}
			position, found := indices[identity]
			if !found {
				position = len(groups)
				indices[identity] = position
				groups = append(groups, nativeNAT64WireContext{nativeSourceIdentity: identity})
			}
			groups[position].ids = append(groups[position].ids, packet.id)
		}
	}
	for _, reply := range []bool{false, true} {
		direction, field := "original", "oifname"
		if reply {
			direction, field = "reply", "iifname"
		}
		entry := transport.name + "_wire_order_" + direction
		for groupIndex, group := range groups {
			for pathIndex, path := range paths {
				branch := fmt.Sprintf("%s_%d_%d", entry, groupIndex, pathIndex)
				access.add(entry, nativeNAT64WireContextIDs(group.ids), nativeInterface(field, path.iface), nativeVerdict("goto", branch))
				for index, rule := range path.raw.rules {
					scopes, err := nativeNAT64WireScopes(ctx, transport, path, group.nativeSourceIdentity, index, reply)
					if err != nil {
						return err
					}
					for _, scope := range scopes {
						if rule.Action == "allow" {
							authorization := rule.Authorization
							if authorization == "inherit" && (slices.Contains(access.managed, group.iface) || slices.Contains(access.managed, path.iface)) {
								authorization = "directory"
							}
							access.add(branch, scope,
								nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, index), guardBinary("&", nativeCT("mark"), ownershipRuleMask), index),
								nativePhysicalKinds(authorization, reply, group.ids), nativeVerdict("return", ""))
						}
						// A matching deny, different original rule or insufficient
						// authorization terminates here; no wider later rule applies.
						access.add(branch, scope, nativeVerdict("drop", ""))
					}
				}
				access.add(branch, nativeVerdict("drop", ""))
			}
		}
		access.add(entry, nativeVerdict("drop", ""))
	}
	return ctx.Err()
}

func nativeNAT64WireContextIDs(ids []uint64) nativeScope {
	values := slices.Clone(ids)
	slices.Sort(values)
	values = slices.Compact(values)
	if len(values) == 1 {
		return nativeMark(uint64(ownershipRuleMask), values[0])
	}
	literals := make([]string, len(values))
	for index, value := range values {
		literals[index] = fmt.Sprint(value)
	}
	return nativeMatch("meta mark & 0x3ff { "+strings.Join(literals, ", ")+" }",
		guardBinary("&", guardMeta("mark"), ownershipRuleMask), map[string]any{"set": values})
}

func nativeNAT64WireScopes(ctx context.Context, transport *nativeNAT64Transport, path nativeNAT64EgressPolicy, original nativeSourceIdentity, index int, reply bool) ([]nativeScope, error) {
	if ctx == nil || transport == nil || path.raw == nil || index < 0 || index >= len(path.raw.rules) ||
		path.raw.baselineHash != transport.baselineHash || !slices.Contains(transport.destinations, path.iface) {
		return nil, errors.New("firewall: missing NAT64 wire predicate origin")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw := path.raw.rules[index]
	candidate := raw
	candidate.Family, candidate.To = 4, nil
	if candidate.Protocol == "icmpv6" {
		candidate.Protocol = "icmp"
	}
	for _, target := range raw.To {
		converted := policy.NetworkSelector{Interface: path.iface}
		for _, prefix := range target.Addresses {
			if prefix.Bits() < transport.prefix.Bits() && prefix.Overlaps(transport.prefix) {
				prefix = transport.prefix
			}
			decoded := nativeNAT64IPv4Prefix(transport.prefix, prefix)
			if !decoded.IsValid() {
				return nil, errors.New("firewall: NAT64 wire predicate lost its encoded destination")
			}
			converted.Addresses = append(converted.Addresses, decoded)
		}
		candidate.To = append(candidate.To, converted)
	}
	result := []nativeScope{}
	for _, source := range raw.From {
		if source.Interface != "" && source.Interface != original.iface || source.MAC != "" && source.MAC != original.mac {
			continue
		}
		candidate.From = []policy.NetworkSelector{{Interface: transport.component}}
		scopes, err := (&nativeRuleSet{rules: []policy.NetworkRule{candidate}}).scopes(ctx, 0, reply, false)
		if err != nil {
			return nil, err
		}
		prefixes := source.Addresses
		if len(prefixes) == 0 {
			prefixes = []netip.Prefix{{}}
		}
		for _, prefix := range prefixes {
			predicate := nativeScope{}
			if prefix.IsValid() {
				field := "saddr"
				if reply {
					field = "daddr"
				}
				index := slices.Index(transport.sourceScopes, prefix.Masked())
				if index < 0 {
					return nil, errors.New("firewall: NAT64 wire source escaped its immutable scope inventory")
				}
				name := transport.sourceScopeName(index)
				predicate = nativeMatch("ip "+field+" @"+name, guardPayload("ip", field), "@"+name)
			}
			if len(result)+len(scopes) > 16384 {
				return nil, errors.New("firewall: NAT64 wire predicate expansion exceeds capacity")
			}
			for _, scope := range scopes {
				result = append(result, nativeJoin(predicate, scope))
			}
		}
	}
	return result, ctx.Err()
}
