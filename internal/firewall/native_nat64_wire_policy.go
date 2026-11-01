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
	ids   []uint64
	rules map[int][]uint64
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
	groups := access.nat64ContextGroups(transport)
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
							decision := fmt.Sprintf("%s_%d_rule_%d_%s_%t", entry, groupIndex, index, authorization, slices.Contains(access.managed, path.iface))
							if _, exists := access.inet[decision]; !exists {
								access.compileNAT64WireDecision(transport, decision, index, authorization, reply, slices.Contains(access.managed, path.iface), group.ids)
							}
							access.add(branch, scope, nativeVerdict("goto", decision))
						}
						// A matching deny, conflicting connection rule or insufficient
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

func (access *nativeAccess) nat64ContextGroups(transport *nativeNAT64Transport) []nativeNAT64WireContext {
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
				groups = append(groups, nativeNAT64WireContext{nativeSourceIdentity: identity, rules: map[int][]uint64{}})
			}
			groups[position].ids = append(groups[position].ids, packet.id)
			groups[position].rules[index] = append(groups[position].rules[index], packet.id)
		}
	}
	return groups
}

// The final IPv4 route selects permission. Only a private unconfirmed wire
// connection may bind its actual rule; raw source provenance is held separately.
func (access *nativeAccess) compileNAT64WireDecision(transport *nativeNAT64Transport, chain string, index int, authorization string, reply, targetManaged bool, ids []uint64) {
	bound := chain + "_bound"
	target := access.compileNAT64TargetDecision(transport, index, authorization, reply)
	access.add(chain+"_target", nativeVerdict("jump", target))
	access.add(chain+"_target", nativeVerdict("goto", bound))
	for _, directory := range []bool{false, true} {
		access.add(chain, nativeMark(0xff000000, nativeNAT64TargetTag(directory, reply)), nativeVerdict("goto", chain+"_target"))
	}
	configuration := nativeMark(0xff000000, nativeTag(true, reply))
	targetVerdict := []nativeScope{nativeVerdict("goto", chain+"_target")}
	if reply {
		targetVerdict = []nativeScope{nativeVerdict("drop", "")}
	}
	if targetManaged || authorization == "directory" {
		access.add(chain, append([]nativeScope{configuration}, targetVerdict...)...)
	} else {
		peer := "daddr"
		if reply {
			peer = "saddr"
		}
		access.add(chain, append([]nativeScope{configuration, nativeMatch("ip "+peer+" @"+classified4Set, guardPayload("ip", peer), "@"+classified4Set)}, targetVerdict...)...)
	}
	if authorization == "directory" && !reply {
		for _, kind := range []uint64{nativeTag(false, false), nativeDirectoryTag(false)} {
			access.add(chain, nativeMark(0xff000000, kind), nativeStampKind(nativeDirectoryTag(false)), nativeVerdict("goto", bound))
		}
	} else {
		access.add(chain, nativePhysicalKinds(authorization, reply, ids), nativeVerdict("goto", bound))
	}
	access.add(chain, nativeVerdict("drop", ""))
	if !reply {
		access.add(bound, nativeMatch("ct mark 0", nativeCT("mark"), 0),
			nativeScope{text: "ct status confirmed", expressions: []any{map[string]any{"match": map[string]any{
				"op": "in", "left": nativeCT("status"), "right": "confirmed",
			}}}}, nativeVerdict("drop", ""))
		stamp := []nativeScope{nativeMatch("ct mark 0", nativeCT("mark"), 0), nativeState("new"),
			nativeMangle("ct mark set meta priority & 0xfffffc00", nativeCT("mark"), guardBinary("&", guardMeta("priority"), "ffff:fc00"))}
		if index != 0 {
			stamp = append(stamp, nativeMangle(fmt.Sprintf("ct mark set ct mark | %d", index), nativeCT("mark"), guardBinary("|", nativeCT("mark"), index)))
		}
		access.add(bound, stamp...)
	}
	access.add(bound, nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, index), guardBinary("&", nativeCT("mark"), ownershipRuleMask), index), nativeVerdict("goto", bound+"_epoch"))
	access.add(bound, nativeVerdict("drop", ""))
	access.add(bound+"_epoch", nativeVerdict("jump", "native_translation_facts_epoch"))
	access.add(bound+"_epoch", nativeVerdict("return", ""))
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
