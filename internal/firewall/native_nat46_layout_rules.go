package firewall

import (
	"fmt"
	"slices"
)

// Leg selection retains exact mapping, protocol, state and tuple geometry.
// Only the identical checks after that selection are shared.
func (access *nativeAccess) compileNAT46Leg(leg nativeNAT46Leg) {
	for _, physical := range []bool{false, true} {
		graph := access.inet
		if physical {
			graph = access.netdev
		}
		for _, wire := range []bool{false, true} {
			if !wire && !leg.reply {
				continue
			}
			graph[leg.joinName(wire, "grant")] = leg.mixedGrantChecks(wire)
			if leg.protocol != "icmp" {
				selector := nativeNAT46GrantSelector(wire)
				graph[selector] = append(graph[selector], nativeJoin(leg.frameGeometry(wire), nativeVerdict("goto", leg.joinName(wire, "grant"))))
			}
			target := leg.identityName(wire, "target")
			if _, exists := graph[target]; !exists {
				graph[target] = access.nat46TargetChecks(leg, wire, physical)
				family, field, address := "ip", "saddr", leg.mapping.alias
				if wire {
					family, address = "ip6", leg.mapping.target
				}
				if !leg.reply {
					field = "daddr"
				}
				selector := nativeNAT46CommonName(wire, leg.reply, "targets")
				graph[selector] = append(graph[selector], nativeJoin(nativeMatch(family+" "+field+" "+address.String(), guardPayload(family, field), address.String()), nativeVerdict("goto", target)))
			}
			if physical {
				graph["native_n46_physical"] = append(graph["native_n46_physical"], nativeJoin(leg.frameGeometry(wire), nativeVerdict("goto", nativeNAT46CommonName(wire, leg.reply, "checked"))))
			}
		}
	}
	if !leg.reply {
		access.add("native_n46_raw_eligible", leg.geometry(false), nativeVerdict("return", ""))
		// Export changes only tuple collections, leaving this repeated geometry
		// unchanged. Two rules avoid an unnecessary static validation level.
		access.add("native_n46_raw_export", leg.geometry(false), nativeVerdict("jump", leg.name+"_export"))
		access.add("native_n46_raw_export", leg.geometry(false), nativeVerdict("accept", ""))
		access.add("native_n46_import", leg.geometry(true), nativeVerdict("goto", leg.joinName(true, "import")))
		access.inet[leg.joinName(true, "import")] = []nativeScope{nativeVerdict("jump", leg.name+"_import"), nativeVerdict("jump", "native_n46_handoff"), nativeVerdict("goto", nativeNAT46CommonName(true, false, "checked"))}
	} else {
		access.add("native_n46_import", leg.geometry(true), nativeVerdict("goto", leg.joinName(false, "import")))
		access.inet[leg.joinName(false, "import")] = []nativeScope{nativeVerdict("jump", leg.name+"_import"), nativeVerdict("goto", nativeNAT46CommonName(false, true, "checked"))}
		access.add("native_n46_wire_reply", leg.geometry(false), nativeVerdict("goto", "native_n46_restore_reply"))
		access.add("native_n46_wire_reply_confirm", leg.geometry(false), nativeVerdict("goto", "native_n46_restore_reply_confirm"))
		access.add("native_n46_reply_export", leg.geometry(false), nativeVerdict("jump", leg.name+"_export"))
		access.add("native_n46_reply_export", leg.geometry(false), nativeVerdict("accept", ""))
	}
}

func nativeNAT46CommonName(wire, reply bool, suffix string) string {
	side, direction := "raw", "original"
	if wire {
		side = "wire"
	}
	if reply {
		direction = "reply"
	}
	return "native_n46_common_" + side + "_" + direction + "_" + suffix
}

func (access *nativeAccess) compileNAT46Common() {
	for _, physical := range []bool{false, true} {
		graph := access.inet
		if physical {
			graph = access.netdev
		}
		for _, side := range []struct{ wire, reply bool }{{true, false}, {true, true}, {false, true}} {
			wire, reply := side.wire, side.reply
			leg := nativeNAT46Leg{reply: reply}
			rules := []nativeScope{nativeVerdict("jump", "native_raw_floor")}
			if reply {
				rules = append(rules, nativeVerdict("jump", nativeNAT46ReverseName(wire)))
			}
			if physical {
				source := leg.identityName(wire, "source")
				graph[source] = leg.joinSourcePhysical(wire)
				rules = append(rules, nativeVerdict("jump", source))
			}
			target := nativeNAT46CommonName(wire, reply, "targets")
			graph[target] = append(graph[target], nativeVerdict("drop", ""))
			rules = append(rules, nativeVerdict("jump", target))
			policy := "native_n46_wire_policy"
			if !wire {
				policy = "native_n46_raw_policy"
			}
			rules = append(rules, nativeVerdict("jump", policy))
			if physical {
				rules = append(rules, nativeVerdict("goto", "restore_owner_priority"))
			} else {
				if wire && !reply {
					rules = append(rules, nativeVerdict("jump", "native_translation_facts_capture"))
				}
				if wire && reply {
					confirmed := append([]nativeScope{}, rules...)
					graph[nativeNAT46CommonName(wire, reply, "checked")+"_confirm"] = append(confirmed, nativeVerdict("goto", "native_n46_reply_export"))
				}
				rules = append(rules, nativeVerdict("accept", ""))
			}
			graph[nativeNAT46CommonName(wire, reply, "checked")] = rules
		}
	}
	sender := []nativeScope{nativeVerdict("jump", "native_raw_floor"), nativeVerdict("jump", "native_forward_floor"), nativeVerdict("jump", "validate_source")}
	for _, iface := range access.managed {
		sender = append(sender, nativeJoin(nativeInterface("iifname", iface), nativeVerdict("jump", "native_source")))
	}
	access.inet["native_n46_reply_sender"] = append(sender, nativeVerdict("return", ""))
	for _, confirmed := range []bool{false, true} {
		name, facts, target := "native_n46_restore_reply", "native_translation_facts_restore", nativeNAT46CommonName(true, true, "checked")
		if confirmed {
			name += "_confirm"
			facts = "native_n46_reply_confirm_facts"
			target += "_confirm"
		}
		access.inet[name] = []nativeScope{nativeVerdict("jump", "native_n46_reply_sender"), nativeVerdict("jump", facts), nativeVerdict("goto", target)}
	}
	access.add("native_n46_reply_export", nativeVerdict("drop", ""))
}

func nativeNAT46GrantSelector(wire bool) string {
	if wire {
		return "native_n46_wire_grants"
	}
	return "native_n46_raw_grants"
}

// Share only identical identity predicates. Source checks do not depend on a
// mapped target; target checks retain their particular mapping. Protocol,
// listener, context and authorization checks remain in each leg's caller.
func (leg nativeNAT46Leg) identityName(wire bool, kind string) string {
	side, direction := "raw", "original"
	if wire {
		side = "wire"
	}
	if leg.reply {
		direction = "reply"
	}
	prefix := "native_n46_identity_"
	if kind != "source" {
		prefix += leg.mapping.id + "_"
	}
	return prefix + side + "_" + direction + "_" + kind
}

// Physical hooks have no usable original iif, connection state or mark. The
// context binding, full source/target proofs and current permission follow.
func (leg nativeNAT46Leg) frameGeometry(wire bool) nativeScope {
	family, field, address := "ip", "daddr", leg.mapping.alias
	if wire {
		family, address = "ip6", leg.mapping.target
	}
	if leg.reply {
		field = "saddr"
	}
	parts := []nativeScope{nativeMatch(family+" "+field+" "+address.String(), guardPayload(family, field), address.String())}
	if wire {
		peer := "saddr"
		if leg.reply {
			peer = "daddr"
		}
		parts = append(parts, nativeMatch("ip6 "+peer+" "+leg.prefix.String(), guardPayload("ip6", peer), controllerPrefix(leg.prefix)))
	}
	if leg.protocol == "icmp" {
		proto, kind := "icmp", "echo-request"
		if wire {
			proto = "icmpv6"
		}
		if leg.reply {
			kind = "echo-reply"
		}
		parts = append(parts, nativeMatch(proto+" type "+kind, guardPayload(proto, "type"), kind), nativeMatch(proto+" code 0", guardPayload(proto, "code"), 0))
	} else {
		parts = append(parts, nativeMatch("meta l4proto "+leg.protocol, guardMeta("l4proto"), leg.protocol))
	}
	return nativeJoin(parts...)
}

func (leg nativeNAT46Leg) mixedGrantChecks(wire bool) []nativeScope {
	if leg.protocol != "tcp" && leg.protocol != "udp" {
		return []nativeScope{nativeVerdict("drop", "")}
	}
	if wire {
		from := leg.wireSourceGrant()
		return append(from[:len(from)-1], leg.targetGrant(true)...)
	}
	port := "dport"
	if leg.reply {
		port = "sport"
	}
	set := "native_id_lease_from4_" + leg.protocol
	key := map[string]any{"concat": []any{guardMeta("priority"), guardBinary("&", guardMeta("mark"), nativeSourceMask), leg.mapping.alias.String(), guardPayload(leg.protocol, port)}}
	from := nativeJoin(nativeMark(0xff000000, nativeDirectoryTag(leg.reply)),
		nativeMatch(fmt.Sprintf("meta priority . (meta mark & 0xe000) . %s . %s %s @%s", leg.mapping.alias, leg.protocol, port, set), key, "@"+set), nativeVerdict("return", ""))
	return append([]nativeScope{from}, leg.targetGrant(false)...)
}

func (access *nativeAccess) nat46TargetChecks(leg nativeNAT46Leg, wire, physical bool) []nativeScope {
	family, field := "ip6", "daddr"
	if !wire {
		family = "ip"
	}
	if leg.reply {
		field = "saddr"
	}
	history := classified6Set
	if !wire {
		history = classified4Set
	}
	name := leg.identityName(wire, "target_current")
	rules := []nativeScope{}
	if slices.Contains(access.managed, leg.mapping.targetInterface) {
		rules = append(rules, nativeVerdict("goto", name))
	} else {
		rules = append(rules, nativeJoin(nativeMatch(family+" "+field+" @"+history, guardPayload(family, field), "@"+history), nativeVerdict("goto", name)), nativeVerdict("return", ""))
	}
	graph := access.inet
	if physical {
		graph = access.netdev
		proof := leg.targetPhysical()
		if wire {
			proof = leg.targetWirePhysical()
		}
		graph[name] = proof
	} else {
		// The inet hook still sees the ingress Ethernet header. Exact target
		// MAC/address/individual-deadline proof belongs to final physical
		// egress; do not create a new receipt from this connection check.
		current := nativeMatch("ct mark & 0xfffffc00 @"+ownershipEpochSet, guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+ownershipEpochSet)
		graph[name] = nil
		for _, kind := range []uint64{nativeTag(false, leg.reply), nativeDirectoryTag(leg.reply), nativeNAT46StaticSourceTag(false, leg.reply), nativeNAT46StaticSourceTag(true, leg.reply)} {
			graph[name] = append(graph[name], nativeJoin(nativeMark(0xff000000, kind), current, nativeVerdict("return", "")))
		}
		graph[name] = append(graph[name], nativeVerdict("drop", ""))
	}
	return rules
}

func (leg nativeNAT46Leg) joinSourcePhysical(wire bool) []nativeScope {
	family, client, history := "ip6", "saddr", classified6Set
	if leg.reply {
		client = "daddr"
	}
	if !wire {
		family, history = "ip", classified4Set
	}
	_, sourceEpoch := epochChannelNames(false)
	_, cfgEpoch := epochChannelNames(true)
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload(family, client)}}
	text := "(meta mark & 0xe000) . (meta priority & 0x3ff) . " + family + " " + client
	set := nativeNAT46StaticBindings6
	if !wire {
		key = map[string]any{"concat": []any{guardMeta("oifname"), guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload(family, client)}}
		text = "oifname . " + text
		set = nativeNAT46StaticReturn4
	}
	static := nativeMatch(text+" @"+set, key, "@"+set)
	// Negative history is checked in the branch, not on NAS UID packets.
	rules := []nativeScope{}
	for _, directory := range []bool{false, true} {
		rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeNAT46StaticSourceTag(directory, leg.reply)), nativePriorityEpoch(sourceEpoch),
			nativeScope{text: family + " " + client + " != @" + history, expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardPayload(family, client), "right": "@" + history}}}}, nat46StaticSourceLive(), static, nativeVerdict("return", "")))
	}
	rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeNAT46StaticTag(leg.reply)), nativePriorityEpoch(cfgEpoch),
		nativeScope{text: family + " " + client + " != @" + history, expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardPayload(family, client), "right": "@" + history}}}}, static, nativeVerdict("return", "")))
	var raw = guardPayload("ip", client)
	rawText, nativeSet := "ip "+client, nativeSource4
	if wire {
		offset := 160
		if leg.reply {
			offset = 288
		}
		raw, rawText, nativeSet = nativeRawPayload(offset), fmt.Sprintf("@nh,%d,32", offset), nativeSourceBits4
	}
	key = map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), raw}}
	proof := nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . "+rawText+" @"+nativeSet, key, "@"+nativeSet)
	for _, kind := range []uint64{nativeTag(false, leg.reply), nativeDirectoryTag(leg.reply)} {
		rules = append(rules, nativeJoin(nativeMark(0xff000000, kind), nativePriorityEpoch(sourceEpoch), proof, nativeVerdict("return", "")))
	}
	return append(rules, nativeVerdict("drop", ""))
}
