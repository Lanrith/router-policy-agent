package firewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// The original rule index remains in CT. At confirmation the packet's low mark
// bits instead identify that rule plus the actual ingress and source MAC policy
// class. Physical egress has neither the ingress frame's MAC nor its iif. This
// fixed context lets it re-evaluate first-match denies against the actual final
// addresses and listener, without broadening a partial deny to other sources.
// Classes use only MACs mentioned in immutable rules, plus their complement.
type nativePacketContext struct {
	id         uint64
	chain      string
	rawChain   string
	family     int
	predicate  nativeScope
	source     *nativeSourceClass
	iface, mac string
}

type nativePhysicalContext struct {
	packet nativePacketContext
	ids    []uint64
}

// Native packets retain the actual source address. Source classes used only
// after uplink NAT can therefore share an otherwise identical native gate.
// The translated gate continues to use each separate source class.
func nativePhysicalContexts(contexts []nativePacketContext, reply bool) []nativePhysicalContext {
	type key struct {
		iface, mac, chain string
		family            int
	}
	indices := map[key]int{}
	groups := []nativePhysicalContext{}
	for _, packet := range contexts {
		identity := key{packet.iface, packet.mac, packet.physicalChain(reply), packet.family}
		index, exists := indices[identity]
		if !exists {
			index = len(groups)
			indices[identity] = index
			groups = append(groups, nativePhysicalContext{packet: packet})
		}
		groups[index].ids = append(groups[index].ids, packet.id)
	}
	return groups
}

func (packetContext nativePacketContext) physicalChain(reply bool) string {
	chain := packetContext.rawChain
	if chain == "" {
		chain = packetContext.chain
	}
	if reply {
		return chain + "_reply"
	}
	return chain + "_original"
}

func (packetContext nativePacketContext) natPhysicalChain(reply bool) string {
	if reply {
		return packetContext.chain + "_reply_nat"
	}
	return packetContext.chain + "_original_nat"
}

func (access *nativeAccess) compileContexts(ctx context.Context, set *nativeRuleSet, interfaces []string) error {
	access.contexts = map[int][]nativePacketContext{}
	id := uint64(0)
	for classIndex, iface := range interfaces {
		macs := nativeContextMACs(set, iface)
		classes := append(slices.Clone(macs), "")
		// These attachments are closed to ordinary owner/directory traffic
		// before either forwarding hook's ordered program. Core kinds have
		// independent scopes and do not consume native packet contexts.
		if slices.Contains(access.serviceInterfaces, iface) {
			continue
		}
		for macIndex, mac := range classes {
			if err := ctx.Err(); err != nil {
				return err
			}
			chain := fmt.Sprintf("native_physical_context_%d_%d", classIndex, macIndex)
			predicate := nativeMatch(fmt.Sprintf("iifname %q", iface), guardMeta("iifname"), iface)
			if mac != "" {
				predicate = nativeJoin(predicate, nativeMatch("ether saddr "+mac, guardPayload("ether", "saddr"), mac))
			} else if len(macs) != 0 {
				right, text := any(macs[0]), macs[0]
				if len(macs) > 1 {
					right, text = map[string]any{"set": macs}, "{ "+strings.Join(macs, ", ")+" }"
				}
				predicate = nativeJoin(predicate, nativeScope{text: "ether saddr != " + text, expressions: []any{
					map[string]any{"match": map[string]any{"op": "!=", "left": guardPayload("ether", "saddr"), "right": right}},
				}})
			}
			classes, err := nativeContextSources(ctx, set, iface)
			if err != nil {
				return err
			}
			for sourceIndex, sourceClass := range classes {
				selectedChain := chain
				if len(classes) > 1 {
					selectedChain = fmt.Sprintf("%s_source_%d", chain, sourceIndex)
				}
				selectedPredicate := nativeJoin(predicate, sourceClass.predicate)
				used := false
				for index, rule := range set.rules {
					if rule.Action != "allow" || !nativeContextInterface(rule, iface) || !sourceClass.relevant(rule, iface, mac) {
						continue
					}
					if id > uint64(ownershipRuleMask) {
						return errors.New("firewall: native packet context capacity exceeded")
					}
					access.contexts[index] = append(access.contexts[index], nativePacketContext{id: id, chain: selectedChain, rawChain: chain, family: sourceClass.family, predicate: selectedPredicate, source: sourceClass.source, iface: iface, mac: mac})
					id++
					used = true
				}
				if used {
					for _, reply := range []bool{false, true} {
						// Native ordering still checks actual CIDRs. Its identical
						// chains can be shared across the saved NAT source classes;
						// rewritten paths retain their separate class-specific chains.
						packetContext := nativePacketContext{chain: chain}
						if _, exists := access.netdev[packetContext.physicalChain(reply)]; exists {
							continue
						}
						if err := access.compilePhysicalOrder(ctx, set, packetContext.physicalChain(reply), iface, mac, reply); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return ctx.Err()
}

// A source MAC bound to one incoming attachment cannot affect ordering on
// another attachment. Keep unscoped MAC selectors on every interface.
func nativeContextMACs(set *nativeRuleSet, iface string) []string {
	macs := []string{}
	for _, rule := range set.rules {
		for _, source := range rule.From {
			if source.MAC != "" && (source.Interface == "" || source.Interface == iface) {
				macs = append(macs, source.MAC)
			}
		}
	}
	slices.Sort(macs)
	return slices.Compact(macs)
}

func nativeContextInterface(rule policy.NetworkRule, iface string) bool {
	// Original and correlated reply packets have opposite incoming endpoints.
	for _, entries := range [][]policy.NetworkSelector{rule.From, rule.To} {
		for _, endpoint := range entries {
			if endpoint.Interface == "" || endpoint.Interface == iface {
				return true
			}
		}
	}
	return false
}

func (access *nativeAccess) compilePhysicalOrder(ctx context.Context, set *nativeRuleSet, chain, iface, mac string, reply bool) error {
	return access.compilePhysicalOrderSource(ctx, set, chain, iface, mac, reply, nil)
}

func (access *nativeAccess) compilePhysicalOrderSource(ctx context.Context, set *nativeRuleSet, chain, iface, mac string, reply bool, sourceClass *nativeSourceClass) error {
	if sourceClass == nil {
		access.netdev[chain] = append(access.netdev[chain], nativeVerdict("jump", "native_raw_floor"), nativeVerdict("jump", access.sourceGuards[iface]))
	}
	sourceGuard := chain + "_source"
	access.netdev[chain] = append(access.netdev[chain], nativeVerdict("jump", sourceGuard))
	switch {
	case sourceClass != nil:
		access.netdev[sourceGuard] = []nativeScope{nativeVerdict("goto", "native_nat_source")}
	case slices.Contains(access.managed, iface):
		access.netdev[sourceGuard] = []nativeScope{nativeVerdict("goto", "native_bound_source")}
	default:
		for _, family := range []struct{ protocol, set string }{{"ip", classified4Set}, {"ip6", classified6Set}} {
			access.netdev[sourceGuard] = append(access.netdev[sourceGuard], nativeJoin(nativeMatch(family.protocol+" saddr @"+family.set, guardPayload(family.protocol, "saddr"), "@"+family.set), nativeVerdict("goto", "native_bound_source")))
		}
		for _, condition := range []nativeScope{
			{text: "meta mark & 0xe000 != 0", expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardBinary("&", guardMeta("mark"), uint64(0xe000)), "right": uint64(0)}}}},
			{text: "meta priority & 0x3ff != none", expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardBinary("&", guardMeta("priority"), "0:3ff"), "right": "none"}}}},
		} {
			access.netdev[sourceGuard] = append(access.netdev[sourceGuard], nativeJoin(condition, nativeVerdict("goto", "native_bound_source")))
		}
		access.netdev[sourceGuard] = append(access.netdev[sourceGuard], nativeVerdict("return", ""))
	}
	for _, rule := range set.rules {
		selected := rule
		if sourceClass != nil {
			if rule.Family == 6 || rule.Protocol == "icmpv6" {
				continue
			}
			selected.Family = 4
		}
		selected.From = []policy.NetworkSelector{}
		for _, source := range rule.From {
			if source.Interface != "" && source.Interface != iface || source.MAC != "" && source.MAC != mac {
				continue
			}
			if sourceClass != nil {
				matched := len(source.Addresses) == 0
				for _, prefix := range source.Addresses {
					matched = matched || sourceClass.within(prefix)
				}
				if !matched {
					continue
				}
				source.Addresses = nil
			}
			selected.From = append(selected.From, source)
		}
		if len(selected.From) == 0 {
			continue
		}
		scopes, err := (&nativeRuleSet{rules: []policy.NetworkRule{selected}}).scopes(ctx, 0, false, true)
		if err != nil {
			return err
		}
		if access.physicalRuleCount+len(scopes)+1 > 16384 {
			return errors.New("firewall: physical ordered predicate expansion exceeds capacity")
		}
		access.physicalRuleCount += len(scopes)
		for _, scope := range scopes {
			admitted, directoryTag := "native_physical_admitted", nativeDirectoryTag(false)
			if sourceClass != nil {
				admitted, directoryTag = "native_nat_admitted", nativeNATTag(directoryTag, false)
			}
			verdict := nativeVerdict("goto", admitted)
			if !reply && rule.Action != "deny" && (rule.Authorization == "directory" || rule.Authorization == "inherit" && slices.Contains(access.managed, iface)) {
				access.netdev[chain] = append(access.netdev[chain], nativeJoin(scope, nativeMark(0xff000000, directoryTag), verdict))
			}
			if rule.Action == "deny" || !reply && (rule.Authorization == "directory" || rule.Authorization == "inherit" && slices.Contains(access.managed, iface)) {
				verdict = nativeVerdict("drop", "")
			} else if !reply && rule.Authorization == "inherit" {
				for _, managed := range access.managed {
					access.netdev[chain] = append(access.netdev[chain], nativeJoin(scope, nativeMatch(fmt.Sprintf("oifname %q", managed), guardMeta("oifname"), managed), nativeMark(0xff000000, directoryTag), verdict))
					access.netdev[chain] = append(access.netdev[chain], nativeJoin(scope, nativeMatch(fmt.Sprintf("oifname %q", managed), guardMeta("oifname"), managed), nativeVerdict("drop", "")))
					access.physicalRuleCount++
				}
			}
			access.netdev[chain] = append(access.netdev[chain], nativeJoin(scope, verdict))
		}
	}
	access.physicalRuleCount++
	verdict := nativeVerdict("drop", "")
	if reply {
		verdict = nativeVerdict("goto", "native_physical_admitted")
		if sourceClass != nil {
			verdict = nativeVerdict("goto", "native_nat_admitted")
		}
	}
	access.netdev[chain] = append(access.netdev[chain], verdict)
	return ctx.Err()
}
