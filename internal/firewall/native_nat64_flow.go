package firewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

func nativeNAT64CurrentConfiguration(reply bool) nativeScope {
	return nativeJoin(
		nativeMark(0xff000000, nativeTag(true, reply)),
		nativeMatch("ct mark & 0xfffffc00 @"+configurationEpochSet,
			guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+configurationEpochSet),
	)
}

func nativeNAT64SourceLive() nativeScope {
	key := map[string]any{"concat": []any{
		guardBinary("&", guardMeta("mark"), nativeSourceMask),
		guardBinary("&", guardMeta("priority"), "0:3ff"),
	}}
	return nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) @"+nativeSourceLive6, key, "@"+nativeSourceLive6)
}

func nativeNAT64CurrentSource(reply bool) nativeScope {
	return nativeJoin(
		nativeMark(0xff000000, nativeTag(false, reply)),
		nativeMatch("ct mark & 0xfffffc00 @"+ownershipEpochSet,
			guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+ownershipEpochSet),
		nativeNAT64SourceLive(),
	)
}

func nativeNAT64Kinds(reply bool) nativeScope {
	values := []uint64{nativeTag(false, reply), nativeTag(true, reply)}
	return nativeMatch("meta mark & 0xff000000 { "+fmt.Sprintf("%#x, %#x", values[0], values[1])+" }",
		guardBinary("&", guardMeta("mark"), uint64(0xff000000)), map[string]any{"set": values})
}

func nativeNAT64Grant(leg nativeNAT64Leg, imported bool) (nativeScope, bool) {
	if leg.protocol != "tcp" && leg.protocol != "udp" {
		return nativeScope{}, false
	}
	family, version := "ip6", 6
	if leg.reply != imported {
		family, version = "ip", 4
	}
	peer, port := "daddr", "dport"
	if leg.reply {
		peer, port = "saddr", "sport"
	}
	set := fmt.Sprintf("native_n64_from%d_%s", version, leg.protocol)
	key := map[string]any{"concat": []any{
		guardMeta("priority"), guardBinary("&", guardMeta("mark"), nativeSourceMask),
		guardPayload(family, peer), guardPayload(leg.protocol, port),
	}}
	return nativeMatch(fmt.Sprintf("meta priority . (meta mark & 0xe000) . %s %s . %s %s @%s", family, peer, leg.protocol, port, set), key, "@"+set), true
}

func nativeNAT64CurrentDirectory(reply bool, grant nativeScope) nativeScope {
	return nativeJoin(
		nativeMark(0xff000000, nativeDirectoryTag(reply)),
		nativeMatch("ct mark & 0xfffffc00 @"+ownershipEpochSet,
			guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+ownershipEpochSet),
		nativeNAT64SourceLive(), grant,
	)
}

func (access *nativeAccess) compileNAT64Flows(ctx context.Context, transports []*nativeNAT64Transport) error {
	if ctx == nil || access == nil || len(transports) == 0 {
		return errors.New("firewall: missing NAT64 flow dependencies")
	}
	facts, err := nativeTranslationFacts(ctx)
	if err != nil {
		return err
	}
	if err := mergeNativeChains(access.inet, facts); err != nil {
		return err
	}
	original, reply, translatedReply := "native_n64_wire_original", "native_n64_wire_reply", "native_n64_translated_reply"
	originalConfirm, replyConfirm, translatedReplyConfirm := original+"_confirm", reply+"_confirm", translatedReply+"_confirm"
	access.add(original, nativeVerdict("jump", "validate_source"))
	access.add(original, nativeVerdict("jump", "native_forward_floor"))
	for _, iface := range access.managed {
		access.add(original, nativeMatch(fmt.Sprintf("iifname %q", iface), guardMeta("iifname"), iface), nativeVerdict("jump", "native_source"))
	}
	access.add(originalConfirm, nativeVerdict("jump", "validate_source"))
	access.add(originalConfirm, nativeVerdict("jump", "native_forward_floor"))
	for _, iface := range access.managed {
		access.add(originalConfirm, nativeMatch(fmt.Sprintf("iifname %q", iface), guardMeta("iifname"), iface), nativeVerdict("jump", "native_source"))
	}
	access.add(reply, nativeVerdict("jump", "native_forward_floor"))
	access.add(reply, nativeVerdict("jump", "validate_source"))
	access.add(replyConfirm, nativeVerdict("jump", "native_forward_floor"))
	access.add(replyConfirm, nativeVerdict("jump", "validate_source"))
	access.add(translatedReply, nativeVerdict("jump", "validate_source"))
	access.add(translatedReplyConfirm, nativeVerdict("jump", "validate_source"))
	for _, transport := range transports {
		access.add(original, nativeVerdict("jump", transport.name+"_request"))
		for _, leg := range transport.legs {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !leg.reply {
				geometry := nativeJoin(leg.geometry(true), leg.allocation(transport, true))
				grantGeometry := nativeJoin(leg.grantGeometry(true), leg.allocation(transport, true))
				grant, delegated := nativeNAT64Grant(leg, true)
				access.add(original, geometry, nativeVerdict("jump", leg.name+"_import"))
				access.add(original, geometry, nativeVerdict("jump", "native_translation_facts_capture"))
				access.add(original, geometry, nativeNAT64CurrentConfiguration(false), nativeVerdict("accept", ""))
				access.add(original, geometry, nativeNAT64CurrentSource(false), nativeVerdict("accept", ""))
				if delegated {
					access.add(original, grantGeometry, nativeNAT64CurrentDirectory(false, grant), nativeVerdict("accept", ""))
				}
				access.add(originalConfirm, geometry, nativeNAT64CurrentConfiguration(false), nativeVerdict("accept", ""))
				access.add(originalConfirm, geometry, nativeNAT64CurrentSource(false), nativeVerdict("accept", ""))
				if delegated {
					access.add(originalConfirm, grantGeometry, nativeNAT64CurrentDirectory(false, grant), nativeVerdict("accept", ""))
				}
				continue
			}
			wireGeometry := nativeJoin(leg.geometry(false), leg.allocation(transport, false))
			wireGrantGeometry := nativeJoin(leg.grantGeometry(false), leg.allocation(transport, false))
			wireGrant, wireDelegated := nativeNAT64Grant(leg, false)
			access.add(reply, wireGeometry, nativeVerdict("jump", "native_translation_facts_restore"))
			access.add(reply, wireGeometry, nativeNAT64CurrentConfiguration(true), nativeVerdict("accept", ""))
			access.add(reply, wireGeometry, nativeNAT64CurrentSource(true), nativeVerdict("accept", ""))
			if wireDelegated {
				access.add(reply, wireGrantGeometry, nativeNAT64CurrentDirectory(true, wireGrant), nativeVerdict("accept", ""))
			}
			access.add(replyConfirm, wireGeometry, nativeNAT64CurrentConfiguration(true), nativeVerdict("accept", ""))
			access.add(replyConfirm, wireGeometry, nativeNAT64CurrentSource(true), nativeVerdict("accept", ""))
			if wireDelegated {
				access.add(replyConfirm, wireGrantGeometry, nativeNAT64CurrentDirectory(true, wireGrant), nativeVerdict("accept", ""))
			}
			rawGeometry := nativeJoin(leg.geometry(true), leg.allocation(transport, true))
			rawGrantGeometry := nativeJoin(leg.grantGeometry(true), leg.allocation(transport, true))
			rawGrant, rawDelegated := nativeNAT64Grant(leg, true)
			access.add(translatedReply, rawGeometry, nativeVerdict("jump", leg.name+"_import"))
			access.add(translatedReply, rawGeometry, nativeNAT64CurrentConfiguration(true), nativeVerdict("accept", ""))
			access.add(translatedReply, rawGeometry, nativeNAT64CurrentSource(true), nativeVerdict("accept", ""))
			if rawDelegated {
				access.add(translatedReply, rawGrantGeometry, nativeNAT64CurrentDirectory(true, rawGrant), nativeVerdict("accept", ""))
			}
			access.add(translatedReplyConfirm, rawGeometry, nativeNAT64CurrentConfiguration(true), nativeVerdict("accept", ""))
			access.add(translatedReplyConfirm, rawGeometry, nativeNAT64CurrentSource(true), nativeVerdict("accept", ""))
			if rawDelegated {
				access.add(translatedReplyConfirm, rawGrantGeometry, nativeNAT64CurrentDirectory(true, rawGrant), nativeVerdict("accept", ""))
			}
		}
	}
	for _, name := range []string{original, reply, translatedReply, originalConfirm, replyConfirm, translatedReplyConfirm} {
		access.add(name, nativeVerdict("drop", ""))
	}

	for _, transport := range transports {
		for _, hook := range []string{"guard_forward", "permit_flow"} {
			position := slices.IndexFunc(access.inet[hook], func(rule nativeScope) bool { return rule.text == "jump native_forward_floor" })
			if position < 0 {
				return errors.New("firewall: NAT64 flow dispatch lost mandatory floor boundary")
			}
			selectedOriginal, selectedReply, selectedTranslatedReply := original, reply, translatedReply
			if hook == "permit_flow" {
				selectedOriginal, selectedReply, selectedTranslatedReply = originalConfirm, replyConfirm, translatedReplyConfirm
			}
			dispatch := []nativeScope{
				nativeJoin(nativeInterface("iifname", transport.component),
					nativeMatch("ip saddr "+transport.pool.String(), guardPayload("ip", "saddr"), controllerPrefix(transport.pool)), nativeVerdict("goto", selectedOriginal)),
				nativeJoin(nativeInterface("iifname", transport.component),
					nativeMatch("ip6 saddr "+transport.prefix.String(), guardPayload("ip6", "saddr"), controllerPrefix(transport.prefix)), nativeVerdict("goto", selectedTranslatedReply)),
				nativeJoin(nativeInterface("oifname", transport.component),
					nativeMatch("ip daddr "+transport.pool.String(), guardPayload("ip", "daddr"), controllerPrefix(transport.pool)), nativeVerdict("goto", selectedReply)),
			}
			access.inet[hook] = slices.Insert(access.inet[hook], position, dispatch...)
		}
	}

	physical := []nativeScope{}
	physicalChain := "native_n64_physical_admitted"
	physicalDirectory := "native_n64_physical_directory"
	for _, reply := range []bool{false, true} {
		access.netdev[physicalChain] = append(access.netdev[physicalChain],
			nativeJoin(nativeMark(0xff000000, nativeTag(true, reply)), nativeVerdict("goto", "native_physical_admitted")),
			nativeJoin(nativeMark(0xff000000, nativeTag(false, reply)), nativeNAT64SourceLive(), nativeVerdict("goto", "native_physical_admitted")),
		)
	}
	access.netdev[physicalChain] = append(access.netdev[physicalChain], nativeVerdict("drop", ""))
	for _, iface := range access.managed {
		access.netdev[physicalDirectory] = append(access.netdev[physicalDirectory], nativeJoin(
			nativeMatch(fmt.Sprintf("oifname %q", iface), guardMeta("oifname"), iface), nativeVerdict("jump", "native_target")))
	}
	for _, family := range []struct{ protocol, set string }{{"ip", classified4Set}, {"ip6", classified6Set}} {
		access.netdev[physicalDirectory] = append(access.netdev[physicalDirectory], nativeJoin(
			nativeMatch(family.protocol+" daddr @"+family.set, guardPayload(family.protocol, "daddr"), "@"+family.set), nativeVerdict("jump", "native_target")))
	}
	_, physicalEpoch := epochChannelNames(false)
	for _, reply := range []bool{false, true} {
		access.netdev[physicalDirectory] = append(access.netdev[physicalDirectory], nativeJoin(
			nativeMark(0xff000000, nativeDirectoryTag(reply)), nativePriorityEpoch(physicalEpoch), nativeNAT64SourceLive(),
			nativeMangle("meta mark set meta mark & 0xffff1fff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xffff1fff))),
			nativeVerdict("goto", "restore_owner_priority")))
	}
	access.netdev[physicalDirectory] = append(access.netdev[physicalDirectory], nativeVerdict("drop", ""))
	for _, transport := range transports {
		for _, leg := range transport.legs {
			for _, imported := range []bool{false, true} {
				if !leg.reply && !imported {
					continue // raw originals retain projected first-match physical policy.
				}
				physical = append(physical, nativeJoin(leg.physicalGeometry(imported), nativeNAT64Kinds(leg.reply),
					nativeVerdict("goto", physicalChain)))
				if grant, delegated := nativeNAT64Grant(leg, imported); delegated {
					physical = append(physical, nativeJoin(leg.physicalGrantGeometry(imported), nativeMark(0xff000000, nativeDirectoryTag(leg.reply)),
						nativeNAT64SourceLive(), grant, nativeVerdict("goto", physicalDirectory)))
				}
			}
		}
	}
	access.netdev["native_scope_gate"] = slices.Insert(access.netdev["native_scope_gate"], 0, physical...)
	return ctx.Err()
}
