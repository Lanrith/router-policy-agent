package firewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Mixed IPv6-source/IPv4-destination rules may have no native-family context.
// Append bounded NAT64 source classes without altering ordinary native gates.
func (access *nativeAccess) compileNAT64CarrierContexts(ctx context.Context, transport *nativeNAT64Transport) error {
	next := uint64(0)
	for _, contexts := range access.contexts {
		for _, packet := range contexts {
			next = max(next, packet.id+1)
		}
	}
	interfaces := make([]string, 0, len(transport.sourceNetworks))
	for iface := range transport.sourceNetworks {
		interfaces = append(interfaces, iface)
	}
	slices.Sort(interfaces)
	for index, rule := range access.ruleSet.rules {
		if !nativeNAT64RuleEligible(rule, transport) {
			continue
		}
		for _, iface := range interfaces {
			macs := nativeContextMACs(access.ruleSet, iface)
			for _, mac := range append(slices.Clone(macs), "") {
				if err := ctx.Err(); err != nil {
					return err
				}
				possible := false
				for _, source := range rule.From {
					possible = possible || (source.Interface == "" || source.Interface == iface) && (source.MAC == "" || source.MAC == mac) &&
						(len(source.Addresses) == 0 || len(nativeNAT64FamilyPrefixes(source.Addresses, true)) != 0)
				}
				if !possible {
					continue
				}
				if slices.ContainsFunc(access.contexts[index], func(packet nativePacketContext) bool {
					return packet.iface == iface && packet.mac == mac && packet.source == nil && (packet.family == 0 || packet.family == 6)
				}) {
					continue
				}
				if next > uint64(ownershipRuleMask) {
					return errors.New("firewall: NAT64 carrier context capacity exceeded")
				}
				predicate := nativeJoin(nativeInterface("iifname", iface), nativeMatch("meta nfproto ipv6", guardMeta("nfproto"), "ipv6"))
				if mac != "" {
					predicate = nativeJoin(predicate, nativeMatch("ether saddr "+mac, guardPayload("ether", "saddr"), mac))
				} else if len(macs) != 0 {
					value, spelling := any(macs[0]), macs[0]
					if len(macs) > 1 {
						value, spelling = map[string]any{"set": macs}, "{ "+strings.Join(macs, ", ")+" }"
					}
					predicate = nativeJoin(predicate, nativeScope{text: "ether saddr != " + spelling, expressions: []any{
						map[string]any{"match": map[string]any{"op": "!=", "left": guardPayload("ether", "saddr"), "right": value}},
					}})
				}
				access.contexts[index] = append(access.contexts[index], nativePacketContext{id: next, family: 6, predicate: predicate, iface: iface, mac: mac})
				next++
			}
		}
	}
	return ctx.Err()
}

// A carrier admits connectivity only to the selected translator. It binds
// source provenance independently of destination permission or grant presence.
func (access *nativeAccess) compileNAT64Carrier(ctx context.Context, transport *nativeNAT64Transport, paths []nativeNAT64EgressPolicy) error {
	programs, err := nativeNAT64RawPrograms(ctx, paths)
	if err != nil {
		return err
	}
	prefix := transport.name + "_carrier"
	for _, hook := range []string{"guard_forward", "permit_flow"} {
		entry := transport.name + "_ordered_" + hook
		for pathIndex, raw := range programs {
			branch := fmt.Sprintf("%s_%d", entry, pathIndex)
			access.add(entry, nativeVerdict("jump", branch))
			for index, rule := range raw.rules {
				scopes, err := raw.scopes(ctx, index, false, false)
				if err != nil {
					return err
				}
				for _, scope := range scopes {
					verdict := nativeVerdict("return", "")
					if rule.Action == "allow" {
						verdict = nativeVerdict("goto", fmt.Sprintf("%s_%d_%s_original", prefix, index, hook))
					}
					access.add(branch, scope, verdict)
				}
			}
			access.add(branch, nativeVerdict("return", ""))
		}
		access.add(entry, nativeVerdict("drop", ""))
		for index, rule := range access.ruleSet.rules {
			if nativeNAT64RuleEligible(rule, transport) {
				rule.Authorization = "owner"
				access.compileDecisionNamed(prefix, index, rule, hook, false, access.managed)
			}
		}
	}
	for groupIndex, group := range access.nat64ContextGroups(transport) {
		chain := fmt.Sprintf("%s_physical_%d", prefix, groupIndex)
		if _, exists := access.sourceGuards[group.iface]; !exists {
			return errors.New("firewall: NAT64 carrier lacks its original source floor")
		}
		access.compilePhysicalContextSource(chain, group.iface, nil)
		packet := nativePacketContext{iface: group.iface, mac: group.mac, family: 6}
		for pathIndex, raw := range programs {
			branch := fmt.Sprintf("%s_%d", chain, pathIndex)
			access.netdev[chain] = append(access.netdev[chain], nativeVerdict("jump", branch))
			for index, rule := range raw.rules {
				scopes, err := raw.physicalScopes(ctx, index, packet, false, false)
				if err != nil {
					return err
				}
				for _, scope := range scopes {
					if ids := group.rules[index]; rule.Action == "allow" && len(ids) != 0 {
						// The first matching rule must still name the source
						// context selected by this raw connection. Other rule
						// contexts cannot borrow its physical permission.
						access.netdev[branch] = append(access.netdev[branch], nativeJoin(scope,
							nativePhysicalKinds("owner", false, ids), nativeVerdict("goto", "native_physical_admitted")))
					}
					access.netdev[branch] = append(access.netdev[branch], nativeJoin(scope, nativeVerdict("return", "")))
				}
			}
			access.netdev[branch] = append(access.netdev[branch], nativeVerdict("return", ""))
		}
		access.netdev[chain] = append(access.netdev[chain], nativeVerdict("drop", ""))
		geometry := nativeJoin(nativeInterface("oifname", transport.component),
			nativeMatch("ip6 daddr "+transport.prefix.String(), guardPayload("ip6", "daddr"), controllerPrefix(transport.prefix)),
			nativePhysicalKinds("owner", false, group.ids))
		access.netdev["native_scope_gate"] = slices.Insert(access.netdev["native_scope_gate"], 0, nativeJoin(geometry, nativeVerdict("goto", chain)))
	}
	return ctx.Err()
}
