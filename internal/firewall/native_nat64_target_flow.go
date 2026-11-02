package firewall

import (
	"fmt"
	"strings"
)

func (access *nativeAccess) compileNAT64TargetDecision(transport *nativeNAT64Transport, index int, authorization string, reply bool) string {
	chain := fmt.Sprintf("%s_target_%d_%s_%t", transport.name, index, authorization, reply)
	if _, exists := access.inet[chain]; exists {
		return chain
	}
	iface, peer := "oifname", "daddr"
	keyID := index * 2
	if reply {
		iface, peer = "iifname", "saddr"
		keyID++
	}
	key := map[string]any{"concat": []any{guardMeta("priority"), guardBinary("&", guardMeta("mark"), ownershipRuleMask), guardMeta(iface), guardPayload("ip", peer)}}
	access.add(chain, nativeMangle("meta priority set "+nativeNAT64TargetKeyClassID(uint32(keyID)), guardMeta("priority"), nativeNAT64TargetKeyClassID(uint32(keyID)))) // #nosec G115 -- doubled rule indices fit eleven bits.
	access.add(chain, nativeMangle("meta priority set meta priority . (meta mark & 0x3ff) . "+iface+" . ip "+peer+" map @"+transport.name+"_target_tokens", guardMeta("priority"), map[string]any{"map": map[string]any{"key": key, "data": "@" + transport.name + "_target_tokens"}}), nativeVerdict("goto", chain+"_identity"))
	access.add(chain, nativeVerdict("drop", ""))
	directory := authorization == "directory"
	for group := uint32(0); group < 8; group++ {
		high := group << 13
		lookup := map[string]any{"concat": []any{guardMeta("priority"), high}}
		access.add(chain+"_identity", nativeMatch(fmt.Sprintf("meta priority . %d @%s_target_highs", high, transport.name), lookup, "@"+transport.name+"_target_highs"),
			nativeMangle(fmt.Sprintf("meta mark set (meta mark & %#x) | %#x", uint64(0x00ff1fff)|nativeNAT64TargetTag(directory, reply)|uint64(high), nativeNAT64TargetTag(directory, reply)|uint64(high)), guardMeta("mark"), guardBinary("|", guardBinary("&", guardMeta("mark"), uint64(0x00ff1fff)|nativeNAT64TargetTag(directory, reply)|uint64(high)), nativeNAT64TargetTag(directory, reply)|uint64(high))),
			nativeMangle("meta priority set meta priority map @"+transport.name+"_export_channel", guardMeta("priority"), map[string]any{"map": map[string]any{"key": guardMeta("priority"), "data": "@" + transport.name + "_export_channel"}}), nativeVerdict("return", ""))
	}
	access.add(chain+"_identity", nativeVerdict("drop", ""))
	return chain
}

func nativeNAT64TargetAuthority(leg nativeNAT64Leg, imported, directory, physical bool) nativeScope {
	_, epoch := epochChannelNames(false)
	offset := 128 // Actual IPv4 destination on the translated original.
	if leg.reply {
		offset = 96
		if imported {
			offset = 160
		}
	}
	peer := nativeRawField(offset, 32)
	if !physical && (!leg.reply || !imported) {
		field := "daddr"
		if leg.reply {
			field = "saddr"
		}
		peer = guardPayload("ip", field)
	}
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), peer}}
	scope := nativeJoin(nativeMark(0xff000000, nativeNAT64TargetTag(directory, leg.reply)), nativePriorityEpoch(epoch),
		nativeMatch(fmt.Sprintf("(meta mark & 0xe000) . (meta priority & 0x3ff) . @nh,%d,32 @%s", offset, nativeSourceBits4), key, "@"+nativeSourceBits4))
	return scope
}

func nativeNAT64CurrentTarget(leg nativeNAT64Leg, imported, directory bool) nativeScope {
	scope := nativeNAT64TargetAuthority(leg, imported, directory, false)
	if leg.reply && imported {
		scope = nativeJoin(scope, nativeMatch("ct mark & 0xfffffc00 @"+configurationEpochSet, guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+configurationEpochSet))
	}
	return scope
}

// The return import has already verified its exact tuple and connection
// provenance. A classified encoded IPv6 source is the current owned IPv4
// target, not a native IPv6 sender on the translator attachment. Validate that
// independently bound target UID/address/epoch before continuing permission
// checks. Other authority kinds keep ordinary source validation.
func (access *nativeAccess) compileNAT64TranslatedSource(transport *nativeNAT64Transport, leg nativeNAT64Leg) string {
	chain := transport.name + "_translated_source"
	if _, exists := access.inet[chain]; exists {
		return chain
	}
	for _, directory := range []bool{false, true} {
		access.add(chain, nativeNAT64CurrentTarget(leg, true, directory), nativeVerdict("return", ""))
	}
	_, epoch := epochChannelNames(false)
	for _, kind := range []uint64{nativeTag(false, true), nativeDirectoryTag(true)} {
		access.add(chain, nativeMark(0xff000000, kind), nativePriorityEpoch(epoch), nativeNAT64SourceLive(), nativeNAT64IPv4SenderEpoch(true), nativeVerdict("return", ""))
	}
	access.add(chain, nativeVerdict("jump", "validate_source"))
	access.add(chain, nativeVerdict("return", ""))
	return chain
}

// Physical checks consume the current target authority before replacing the
// priority channel with its independently bound configuration origin.
func (access *nativeAccess) compileNAT64TargetPhysical(transport *nativeNAT64Transport, leg nativeNAT64Leg, imported, directory bool) string {
	chain := fmt.Sprintf("%s_target_physical_%t_%t", leg.name, imported, directory)
	entry := chain
	if leg.reply && imported {
		for _, group := range access.nat64ContextGroups(transport) {
			scopes := []nativeScope{nativeNAT64WireContextIDs(group.ids), nativeInterface("oifname", group.iface)}
			if group.mac != "" {
				scopes = append(scopes, nativeMatch("ether daddr "+group.mac, guardPayload("ether", "daddr"), group.mac))
			} else if macs := nativeContextMACs(access.ruleSet, group.iface); len(macs) != 0 {
				value, spelling := any(macs[0]), macs[0]
				if len(macs) > 1 {
					value = map[string]any{"set": macs}
					spelling = "{ " + strings.Join(macs, ", ") + " }"
				}
				scopes = append(scopes, nativeScope{text: "ether daddr != " + spelling, expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardPayload("ether", "daddr"), "right": value}}}})
			}
			access.netdev[chain] = append(access.netdev[chain], nativeJoin(append(scopes, nativeVerdict("goto", chain+"_context"))...))
		}
		access.netdev[chain] = append(access.netdev[chain], nativeVerdict("drop", ""))
		chain += "_context"
	}
	scope := nativeNAT64TargetAuthority(leg, imported, directory, true)
	if directory {
		grant, ok := nativeNAT64TargetGrant(leg, imported)
		if !ok {
			access.netdev[entry] = []nativeScope{nativeVerdict("drop", "")}
			return entry
		}
		scope = nativeJoin(scope, grant)
	}
	access.netdev[chain] = append(access.netdev[chain], nativeJoin(scope, nativeVerdict("goto", chain+"_current")), nativeVerdict("drop", ""))
	current := chain + "_current"
	if !leg.reply && imported {
		access.netdev[current] = append(access.netdev[current], nativeVerdict("jump", "native_target"))
	}
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeFactsMask), guardMeta("priority")}}
	access.netdev[current] = append(access.netdev[current], nativeJoin(
		nativeMangle("meta priority set (meta mark & 0xff00e3ff) . meta priority map @"+transport.name+"_target_origins", guardMeta("priority"), map[string]any{"map": map[string]any{"key": key, "data": "@" + transport.name + "_target_origins"}}), nativeVerdict("goto", chain+"_configuration")), nativeVerdict("drop", ""))
	_, epoch := epochChannelNames(true)
	access.netdev[chain+"_configuration"] = []nativeScope{nativeJoin(nativePriorityEpoch(epoch), nativeMangle("meta mark set meta mark & 0xffff1fff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xffff1fff))), nativeVerdict("goto", "restore_owner_priority")), nativeVerdict("drop", "")}
	return entry
}
