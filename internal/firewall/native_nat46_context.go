package firewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// These contexts pin a ready mapping and protocol to an original root decision.
// They are immutable compiler data, separate from source UIDs and static GIDs.
// Neither a context nor its tuple predicates supply forwarding authority.
type nativeNAT46Context struct {
	originalIDs []uint64
	rule        int
	mapping     int
	protocol    string
	packet      nativePacketContext
}

type nativeNAT46ContextGroup struct {
	index    int
	entries  []nativeNAT46Context
	protocol string
	iface    string
	mac      string
}

type nativeNAT46ContextPlan struct {
	model   *nativeNAT46Model
	entries []nativeNAT46Context
	groups  []nativeNAT46ContextGroup
}

func (model *nativeNAT46Model) contextPlan(ctx context.Context, original map[int][]nativePacketContext) (*nativeNAT46ContextPlan, error) {
	if ctx == nil || model == nil || model.rules == nil || original == nil {
		return nil, errors.New("firewall: missing nat46 root context inventory")
	}
	indices, ids := []int{}, map[uint64]bool{}
	next := uint64(0)
	for index, contexts := range original {
		if index < 0 || index >= len(model.rules.rules) || model.rules.rules[index].Action != "allow" {
			return nil, errors.New("firewall: invalid nat46 original rule context")
		}
		indices = append(indices, index)
		for _, original := range contexts {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if original.id > uint64(ownershipRuleMask) || ids[original.id] || original.iface == "" || original.family != 0 && original.family != 4 && original.family != 6 {
				return nil, errors.New("firewall: invalid or duplicate nat46 original context")
			}
			ids[original.id] = true
			next = max(next, original.id+1)
		}
	}
	slices.Sort(indices)
	plan := &nativeNAT46ContextPlan{model: model}
	for _, index := range indices {
		contexts := slices.Clone(original[index])
		slices.SortFunc(contexts, func(a, b nativePacketContext) int {
			if a.id < b.id {
				return -1
			}
			if a.id > b.id {
				return 1
			}
			return 0
		})
		for _, original := range contexts {
			if original.family == 6 {
				continue
			}
			for mapping := range model.mappings {
				for _, protocol := range []string{"tcp", "udp", "icmp"} {
					if protocol == "icmp" && model.directoryRule(index, original.iface, mapping) {
						continue
					}
					scopes, err := model.wireScopes(ctx, index, mapping, original, protocol, false, false)
					if err != nil {
						return nil, err
					}
					if len(scopes) == 0 {
						continue
					}
					covered, err := model.contextCovered(ctx, index, mapping, original, protocol)
					if err != nil {
						return nil, err
					}
					if covered {
						continue
					}
					// IPv4 source classes are needed after NAT44 removes the original
					// address. NAT46 retains every source bit in the wire address:
					// current ordered CIDRs and exact UID/GID checks remain available.
					// Coalesce only those classes, retaining every original raw ID.
					prior := slices.IndexFunc(plan.entries, func(entry nativeNAT46Context) bool {
						return entry.rule == index && entry.mapping == mapping && entry.protocol == protocol && entry.packet.iface == original.iface && entry.packet.mac == original.mac
					})
					if prior != -1 {
						plan.entries[prior].originalIDs = append(plan.entries[prior].originalIDs, original.id)
						continue
					}
					if next > uint64(ownershipRuleMask) {
						return nil, errors.New("firewall: nat46 mapped contexts exceed reserved capacity")
					}
					entry := nativeNAT46Context{originalIDs: []uint64{original.id}, rule: index, mapping: mapping, protocol: protocol,
						packet: nativePacketContext{id: next, iface: original.iface, mac: original.mac, family: 4}}
					next++
					plan.entries = append(plan.entries, entry)
				}
			}
		}
	}
	for _, entry := range plan.entries {
		group := slices.IndexFunc(plan.groups, func(group nativeNAT46ContextGroup) bool {
			return group.protocol == entry.protocol && group.iface == entry.packet.iface && group.mac == entry.packet.mac
		})
		if group == -1 {
			group = len(plan.groups)
			plan.groups = append(plan.groups, nativeNAT46ContextGroup{index: group, protocol: entry.protocol, iface: entry.packet.iface, mac: entry.packet.mac})
		}
		plan.groups[group].entries = append(plan.groups[group].entries, entry)
	}
	return plan, ctx.Err()
}

func (model *nativeNAT46Model) directoryRule(index int, iface string, mapping int) bool {
	rule := model.rules.rules[index]
	return rule.Authorization == "directory" || rule.Authorization == "inherit" &&
		(slices.Contains(model.managed, iface) || slices.Contains(model.managed, model.mappings[mapping].targetInterface))
}

// geometry checks actual attachment, mapped endpoint and protocol. The full
// ordered scope must still check the client CIDR and listener; current source
// and target evidence, immutable facts and fresh tuple proofs remain mandatory.
func (entry nativeNAT46Context) geometry(model *nativeNAT46Model, wire, reply, physical bool) nativeScope {
	mapping := model.mappings[entry.mapping]
	family, target, input, output := "ip", mapping.alias, entry.packet.iface, "nat46"
	if wire {
		family, target, input, output = "ip6", mapping.target, "nat46", mapping.targetInterface
	}
	field, clientField := "daddr", "saddr"
	if reply {
		field, clientField, input, output = "saddr", "daddr", output, input
	}
	parts := []nativeScope{nativeMatch(fmt.Sprintf("oifname %q", output), guardMeta("oifname"), output),
		nativeMatch(family+" "+field+" "+target.String(), guardPayload(family, field), target.String())}
	if !physical {
		parts = append(parts, nativeMatch(fmt.Sprintf("iifname %q", input), guardMeta("iifname"), input))
	}
	if wire {
		parts = append(parts, nativeMatch(family+" "+clientField+" "+model.prefix.String(), guardPayload(family, clientField), controllerPrefix(model.prefix)))
	}
	if entry.protocol == "icmp" {
		protocol, kind := "icmp", "echo-request"
		if wire {
			protocol = "icmpv6"
		}
		if reply {
			kind = "echo-reply"
		}
		parts = append(parts, nativeMatch(protocol+" type "+kind, guardPayload(protocol, "type"), kind), nativeMatch(protocol+" code 0", guardPayload(protocol, "code"), 0))
	} else {
		parts = append(parts, nativeMatch("meta l4proto "+entry.protocol, guardMeta("l4proto"), entry.protocol))
	}
	return nativeJoin(parts...)
}

func (entry nativeNAT46Context) binding(model *nativeNAT46Model, wire, reply, physical bool) nativeScope {
	return nativeJoin(nativeMark(uint64(ownershipRuleMask), entry.packet.id), entry.geometry(model, wire, reply, physical))
}

// Remapping may consume only an original root decision for this exact raw
// mapping/protocol. It preserves the source identity, authorization kind, QoS
// and priority. The caller must check current epochs and permission separately.
func (plan *nativeNAT46ContextPlan) handoff(ctx context.Context) (map[string][]nativeScope, error) {
	if ctx == nil || plan == nil || plan.model == nil {
		return nil, errors.New("firewall: missing nat46 context handoff")
	}
	rules := []nativeScope{}
	for _, entry := range plan.entries {
		if len(rules)+4 > nativeRuleCapacity {
			return nil, errors.New("firewall: nat46 context handoff exceeds capacity")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kinds := []uint64{nativeTag(false, false), nativeTag(true, false)}
		if plan.model.directoryRule(entry.rule, entry.packet.iface, entry.mapping) {
			kinds = []uint64{nativeDirectoryTag(false)}
		}
		for _, kind := range kinds {
			rules = append(rules, nativeJoin(nativeFactsPositiveConnection(),
				nativeMatch("ct direction original", nativeCT("direction"), "original"),
				nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, entry.rule), guardBinary("&", nativeCT("mark"), ownershipRuleMask), entry.rule),
				nativeMark(0xff000000, kind), nativeNAT46IDs(entry.originalIDs), entry.geometry(plan.model, false, false, false),
				nativeMangle("meta mark set meta mark & 0xfffffc00", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xfffffc00))),
				nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", entry.packet.id), guardMeta("mark"), guardBinary("|", guardMeta("mark"), entry.packet.id)), nativeVerdict("return", "")))
		}
	}
	return map[string][]nativeScope{"native_n46_select_context": append(rules, nativeVerdict("drop", ""))}, ctx.Err()
}

func nativeNAT46ContextIDs(entries []nativeNAT46Context) nativeScope {
	ids := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.packet.id)
	}
	return nativeNAT46IDs(ids)
}

func nativeNAT46IDs(ids []uint64) nativeScope {
	if len(ids) == 1 {
		return nativeMark(uint64(ownershipRuleMask), ids[0])
	}
	spellings := make([]string, 0, len(ids))
	for _, id := range ids {
		spellings = append(spellings, fmt.Sprintf("%#x", id))
	}
	return nativeMatch("meta mark & 0x3ff == { "+strings.Join(spellings, ", ")+" }", guardBinary("&", guardMeta("mark"), ownershipRuleMask), map[string]any{"set": slices.Clone(ids)})
}
