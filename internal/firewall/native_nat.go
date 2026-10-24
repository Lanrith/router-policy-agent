package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Source NAT is checked on every packet, around priority 100. A NAT chain only
// runs for the first packet of a connection and cannot serve as this guard.
// The pending kind is never admitted at physical egress. Neither stage changes
// the original connection mark, including its original epoch and rule index.
func nativeNATTag(tag uint64, pending bool) uint64 {
	if pending {
		return tag&0x0f000000 | 0xa0000000
	}
	return tag&0x0f000000 | 0xe0000000
}

const (
	nativeCoreNATPending = uint64(0xab000000)
	nativeCoreNATFinal   = uint64(0xbb000000)
)

func nativeStampKind(kind uint64) nativeScope {
	return nativeJoin(nativeMangle("meta mark set meta mark & 0x00ffffff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0x00ffffff))),
		nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", kind), guardMeta("mark"), guardBinary("|", guardMeta("mark"), kind)))
}

func nativeSNATStatus(present bool) nativeScope {
	op := "in"
	text := "ct status snat"
	if !present {
		return nativeScope{text: "ct status & snat == 0", expressions: []any{map[string]any{"match": map[string]any{"op": "!", "left": nativeCT("status"), "right": "snat"}}}}
	}
	return nativeScope{text: text, expressions: []any{map[string]any{"match": map[string]any{"op": op, "left": nativeCT("status"), "right": "snat"}}}}
}

func (access *nativeAccess) compileNAT(ctx context.Context, set *nativeRuleSet, b policy.Baseline) error {
	enabled := len(set.uplinkNAT) != 0
	for _, scope := range access.core {
		enabled = enabled || scope.upstream != nil && scope.upstream.Masquerade
	}
	if !enabled {
		return nil
	}
	access.inet["native_before_snat"], access.inet["native_after_snat"] = []nativeScope{}, []nativeScope{}
	access.compileNATSourceChecks()
	// These are mandatory router/bogon checks, not delegation ceilings. P03
	// remains a ceiling on directory grants and is not an owner prohibition.
	for _, family := range []struct {
		spelling string
		prefixes []string
	}{{"ip", []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"}}, {"ip6", []string{"::/128", "::1/128", "fe80::/10", "ff00::/8"}}} {
		for _, raw := range family.prefixes {
			access.addNATGuard(family.spelling, netip.MustParsePrefix(raw))
		}
	}
	for _, block := range b.ProtectedNetworks {
		if block.ProtectionID == "P01" {
			for _, prefix := range block.Networks {
				family := "ip6"
				if prefix.Addr().Is4() {
					family = "ip"
				}
				access.addNATGuard(family, prefix)
			}
		}
	}
	access.add("native_nat_raw_source", nativeVerdict("return", ""))
	access.add("native_nat_target", nativeVerdict("return", ""))
	access.netdev["native_nat_target"] = append(access.netdev["native_nat_target"], nativeVerdict("return", ""))
	for _, scope := range access.core {
		if scope.upstream != nil && scope.upstream.Masquerade {
			access.compileCoreNAT(scope)
		}
	}
	for index, rule := range set.rules {
		if rule.Action != "allow" {
			continue
		}
		for _, packetContext := range access.contexts[index] {
			if packetContext.source == nil {
				continue
			}
			var addresses []netip.Addr
			for _, path := range set.uplinkNAT {
				if path.Interface == packetContext.iface {
					addresses = path.Addresses
				}
			}
			if len(addresses) == 0 {
				return errors.New("firewall: uplink source NAT requires qualified dynamic addresses")
			}
			for _, reply := range []bool{false, true} {
				selected := set.physicalRule(index, packetContext, reply, true, b.NetworkModel.UplinkInterface)
				count, err := nativeScopeCount(selected)
				if err != nil {
					return err
				}
				if count == 0 {
					continue
				}
				chain := packetContext.natPhysicalChain(reply)
				if _, exists := access.netdev[chain]; !exists {
					if err := access.compilePhysicalOrderSource(ctx, set, chain, packetContext.iface, packetContext.mac, reply, packetContext.source); err != nil {
						return err
					}
				}
				if err := access.compileNATContext(ctx, set, index, packetContext, reply, b.NetworkModel.UplinkInterface, addresses, chain); err != nil {
					return err
				}
			}
		}
	}
	for _, reply := range []bool{false, true} {
		for _, tag := range []uint64{nativeTag(false, reply), nativeTag(true, reply), nativeDirectoryTag(reply)} {
			access.add("native_after_snat", nativeMark(0xff000000, nativeNATTag(tag, true)), nativeVerdict("drop", ""))
		}
	}
	access.add("native_after_snat", nativeMark(0xff000000, nativeCoreNATPending), nativeVerdict("drop", ""))
	access.compileNATPhysical()
	return ctx.Err()
}

func (access *nativeAccess) addNATGuard(family string, prefix netip.Prefix) {
	for _, field := range []string{"saddr", "daddr"} {
		value, text := controllerPrefix(prefix), prefix.String()
		if prefix.Bits() == prefix.Addr().BitLen() {
			value, text = prefix.Addr().String(), prefix.Addr().String()
		}
		rule := nativeJoin(nativeMatch(family+" "+field+" "+text, guardPayload(family, field), value), nativeVerdict("drop", ""))
		chain := "native_nat_target"
		if field == "saddr" {
			chain = "native_nat_raw_source"
		} else {
			access.netdev[chain] = append(access.netdev[chain], rule)
		}
		access.add(chain, rule)
	}
}

func nativeSourceRequired() []nativeScope {
	return []nativeScope{
		{text: "meta mark & 0xe000 != 0", expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardBinary("&", guardMeta("mark"), uint64(0xe000)), "right": uint64(0)}}}},
		{text: "meta priority & 0x3ff != none", expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardBinary("&", guardMeta("priority"), "0:3ff"), "right": "none"}}}},
	}
}

func (access *nativeAccess) compileNATSourceChecks() {
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload("ip", "saddr")}}
	access.add("native_nat_bound_source", nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . ip saddr @"+nativeSource4, key, "@"+nativeSource4), nativeVerdict("return", ""))
	access.add("native_nat_bound_source", nativeVerdict("drop", ""))
	for _, iface := range access.managed {
		access.add("native_nat_source", nativeMatch(fmt.Sprintf("iifname %q", iface), guardMeta("iifname"), iface), nativeVerdict("goto", "native_nat_bound_source"))
	}
	access.add("native_nat_source", nativeMatch("ether saddr @"+cohortSet, guardPayload("ether", "saddr"), "@"+cohortSet), nativeVerdict("goto", "native_nat_bound_source"))
	access.add("native_nat_source", nativeMatch("ip saddr @"+classified4Set, guardPayload("ip", "saddr"), "@"+classified4Set), nativeVerdict("goto", "native_nat_bound_source"))
	for _, required := range nativeSourceRequired() {
		access.add("native_nat_source", required, nativeVerdict("goto", "native_nat_bound_source"))
	}
	access.add("native_nat_source", nativeVerdict("return", ""))
	// The ID was checked against the raw address before NAT. After rewriting,
	// only an independently published current per-address proof can keep it live.
	key = map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff")}}
	access.netdev["native_nat_live_source"] = []nativeScope{nativeJoin(nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) @"+nativeSourceLive4, key, "@"+nativeSourceLive4), nativeVerdict("return", "")), nativeVerdict("drop", "")}
	for _, reply := range []bool{false, true} {
		access.netdev["native_nat_source"] = append(access.netdev["native_nat_source"], nativeJoin(nativeMark(0xff000000, nativeNATTag(nativeTag(true, reply), false)),
			nativeMark(uint64(nativeSourceMask), 0), nativeMatch("meta priority & 0x3ff == none", guardBinary("&", guardMeta("priority"), "0:3ff"), "none"), nativeVerdict("return", "")))
		for _, tag := range []uint64{nativeTag(false, reply), nativeDirectoryTag(reply)} {
			access.netdev["native_nat_source"] = append(access.netdev["native_nat_source"], nativeJoin(nativeMark(0xff000000, nativeNATTag(tag, false)), nativeVerdict("goto", "native_nat_live_source")))
		}
	}
	access.netdev["native_nat_source"] = append(access.netdev["native_nat_source"], nativeVerdict("drop", ""))
}

func (access *nativeAccess) compileNATContext(ctx context.Context, set *nativeRuleSet, index int, packetContext nativePacketContext, reply bool, wan string, addresses []netip.Addr, physicalChain string) error {
	rule := set.rules[index]
	raw := set.physicalRule(index, packetContext, reply, false, wan)
	rawScopes, err := (&nativeRuleSet{rules: []policy.NetworkRule{raw}}).scopes(ctx, 0, reply, false)
	if err != nil {
		return err
	}
	wireScopes, err := nativeNATWireScopes(ctx, set, index, packetContext, reply, wan)
	if err != nil {
		return err
	}
	// Bound the product before allocating hook/alias copies. A final complete
	// count includes service rules copied across physical interfaces as well.
	if 128+6*len(rawScopes)+6*len(addresses)*len(wireScopes) > 16384 {
		return errors.New("firewall: source NAT predicate expansion exceeds capacity")
	}
	for mode := range 3 {
		if rule.Authorization == "owner" && mode == 2 || rule.Authorization == "directory" && mode != 2 {
			continue
		}
		configuration := mode == 1
		tag := nativeTag(configuration, reply)
		if mode == 2 {
			tag = nativeDirectoryTag(reply)
		}
		pending, final := nativeNATTag(tag, true), nativeNATTag(tag, false)
		chain := fmt.Sprintf("native_nat_%d_%d_%d_%t", index, packetContext.id, mode, reply)
		wanMatch := nativeMatch(fmt.Sprintf("oifname %q", wan), guardMeta("oifname"), wan)
		access.add("native_before_snat", nativeMark(nativeTagMask, tag|packetContext.id), wanMatch, nativeVerdict("goto", chain))
		access.add(chain, nativeVerdict("jump", "native_nat_raw_source"))
		access.add(chain, nativeVerdict("jump", "native_nat_target"))
		access.add(chain, nativeVerdict("jump", "native_nat_source"))
		if mode == 2 {
			access.add(chain, nativeVerdict("jump", "native_grant"))
		}
		epoch, _, _, physicalEpoch := nativeEpoch(configuration)
		checks := nativeJoin(nativeMatch(fmt.Sprintf("ct mark & %#x @%s", ownershipEpochMask, epoch), guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+epoch),
			nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, index), guardBinary("&", nativeCT("mark"), ownershipRuleMask), index))
		for _, raw := range rawScopes {
			access.add(chain, checks, packetContext.predicate, raw, nativeStampKind(pending), nativeVerdict("accept", ""))
		}
		access.add(chain, nativeVerdict("drop", ""))
		access.add("native_after_snat", nativeMark(nativeTagMask, pending|packetContext.id), wanMatch, checks, nativeVerdict("goto", chain+"_after"))
		for _, address := range addresses {
			source := nativeMatch("ip saddr "+address.String(), guardPayload("ip", "saddr"), address.String())
			for _, wire := range wireScopes {
				access.add(chain+"_after", nativeSNATStatus(true), source, wire, nativeStampKind(final), nativeVerdict("accept", ""))
				access.egress[wan] = append(access.egress[wan], nativeJoin(nativeMark(nativeTagMask, final|packetContext.id), nativePriorityEpoch(physicalEpoch), source, wire, nativeVerdict("goto", physicalChain)))
			}
		}
		// A connection first seen from WAN may have a null source-NAT binding.
		// Its reply remains native only while the original raw class still holds.
		for _, raw := range rawScopes {
			access.add(chain+"_after", nativeSNATStatus(false), packetContext.predicate, raw, nativeStampKind(tag), nativeVerdict("accept", ""))
		}
		access.add(chain+"_after", nativeVerdict("drop", ""))
	}
	if err := access.checkCapacity(nil); err != nil {
		return err
	}
	return ctx.Err()
}

// Remove only the source selector whose truth is preserved by this packet's
// immutable class. Retain the original rule's destination, transport, listener,
// direction and endpoint pairing at both confirmation and physical egress.
func nativeNATWireScopes(ctx context.Context, set *nativeRuleSet, index int, packetContext nativePacketContext, reply bool, outgoing string) ([]nativeScope, error) {
	if ctx == nil || set == nil || index < 0 || index >= len(set.rules) || packetContext.source == nil {
		return nil, errors.New("firewall: missing source nat packet context")
	}
	selected := set.physicalRule(index, packetContext, reply, true, outgoing)
	return (&nativeRuleSet{rules: []policy.NetworkRule{selected}}).scopes(ctx, 0, reply, true)
}

func (access *nativeAccess) compileNATPhysical() {
	access.netdev["native_nat_admitted"] = []nativeScope{nativeVerdict("jump", "native_nat_target")}
	for _, reply := range []bool{false, true} {
		for _, configuration := range []bool{false, true} {
			_, _, _, epoch := nativeEpoch(configuration)
			tag := nativeNATTag(nativeTag(configuration, reply), false)
			access.netdev["native_nat_admitted"] = append(access.netdev["native_nat_admitted"], nativeJoin(nativeMark(0xff000000, tag), nativePriorityEpoch(epoch), nativeVerdict("goto", "native_nat_restore")))
		}
		access.netdev["native_nat_admitted"] = append(access.netdev["native_nat_admitted"], nativeJoin(nativeMark(0xff000000, nativeNATTag(nativeDirectoryTag(reply), false)), nativeVerdict("goto", "native_nat_directory")))
	}
	access.netdev["native_nat_admitted"] = append(access.netdev["native_nat_admitted"], nativeVerdict("drop", ""))
	for _, ref := range nativeIDLeaseRefs() {
		name := strings.TrimPrefix(ref.Name, "native_id_")
		_, protocol := guardProtocol(name)
		fromDevice := strings.HasPrefix(name, "lease_from")
		for _, reply := range []bool{false, true} {
			if fromDevice == reply {
				continue // A WAN destination cannot supply LAN device ownership.
			}
			port := "dport"
			if reply {
				port = "sport"
			}
			_, _, _, epoch := nativeEpoch(false)
			key := map[string]any{"concat": []any{guardMeta("priority"), guardBinary("&", guardMeta("mark"), nativeSourceMask), guardPayload("ip", "daddr"), guardPayload(protocol, port)}}
			access.netdev["native_nat_directory"] = append(access.netdev["native_nat_directory"], nativeJoin(nativeMark(0xff000000, nativeNATTag(nativeDirectoryTag(reply), false)), nativePriorityEpoch(epoch),
				nativeMatch("meta priority . (meta mark & 0xe000) . ip daddr . "+protocol+" "+port+" @"+ref.Name, key, "@"+ref.Name), nativeVerdict("goto", "native_nat_restore")))
		}
	}
	access.netdev["native_nat_directory"] = append(access.netdev["native_nat_directory"], nativeVerdict("drop", ""))
	access.netdev["native_nat_restore"] = []nativeScope{nativeMangle("meta mark set meta mark & 0xffff1fff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xffff1fff))), nativeVerdict("goto", "restore_owner_priority")}
}

func (access *nativeAccess) compileCoreNAT(scope nativeCoreScope) {
	chain := fmt.Sprintf("native_core_nat_%d", scope.id)
	wan := nativeMatch(fmt.Sprintf("oifname %q", scope.clientInterface), guardMeta("oifname"), scope.clientInterface)
	marker := nativeMatch(fmt.Sprintf("ct mark %#x", nativeCoreEpoch|scope.id), nativeCT("mark"), nativeCoreEpoch|scope.id)
	priority := nativeMatch("meta priority 0xfffffc00", guardMeta("priority"), "ffff:fc00")
	access.add("native_before_snat", nativeMark(nativeTagMask, nativeCoreTag(false)|scope.id), wan, nativeVerdict("goto", chain))
	access.add(chain, nativeVerdict("jump", "native_nat_raw_source"))
	access.add(chain, nativeVerdict("jump", "native_nat_target"))
	for _, raw := range scope.predicates(false, false) {
		access.add(chain, marker, priority, raw, nativeStampKind(nativeCoreNATPending), nativeVerdict("accept", ""))
	}
	access.add(chain, nativeVerdict("drop", ""))
	access.add("native_after_snat", nativeMark(nativeTagMask, nativeCoreNATPending|scope.id), wan, marker, priority, nativeVerdict("goto", chain+"_after"))
	for _, wire := range scope.predicates(false, true) {
		access.add(chain+"_after", nativeSNATStatus(true), wire, nativeStampKind(nativeCoreNATFinal), nativeVerdict("accept", ""))
	}
	access.add(chain+"_after", nativeVerdict("drop", ""))
}
