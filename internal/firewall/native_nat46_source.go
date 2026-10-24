package firewall

import "fmt"

// wireSourceGrant checks only the original IPv4 device's delegated listener.
// The alias is fixed by compiler-owned mapping geometry; the wire frame cannot
// substitute its IPv6 target, another alias or a static geometry ID. Both inet
// and netdev copies are derived from the same opaque publication and retain
// the shorter original source/grant deadline. Current exact source ownership,
// scope, connection facts and tuple proofs remain independent caller gates.
func (leg nativeNAT46Leg) wireSourceGrant() []nativeScope {
	if leg.protocol != "tcp" && leg.protocol != "udp" {
		return []nativeScope{nativeVerdict("drop", "")}
	}
	port, target, source := "dport", "daddr", "saddr"
	if leg.reply {
		port, target, source = "sport", "saddr", "daddr"
	}
	set := "native_id_lease_from4_" + leg.protocol
	key := map[string]any{"concat": []any{guardMeta("priority"), guardBinary("&", guardMeta("mark"), nativeSourceMask), leg.mapping.alias.String(), guardPayload(leg.protocol, port)}}
	checks := nativeJoin(nativeMark(0xff000000, nativeDirectoryTag(leg.reply)),
		nativeMatch("ip6 "+target+" "+leg.mapping.target.String(), guardPayload("ip6", target), leg.mapping.target.String()),
		nativeMatch("ip6 "+source+" "+leg.prefix.String(), guardPayload("ip6", source), controllerPrefix(leg.prefix)),
		nativeMatch(fmt.Sprintf("meta priority . (meta mark & 0xe000) . %s . %s %s @%s", leg.mapping.alias, leg.protocol, port, set), key, "@"+set))
	return []nativeScope{nativeJoin(checks, nativeVerdict("return", "")), nativeVerdict("drop", "")}
}

// targetPhysical retains the native IPv6 device's individual ownership after
// translation hides that device behind its fixed IPv4 alias. An earlier native
// reply and a fresh return tuple cannot keep an expired target alive. Source
// identity, ordered permission, grants and tuple admission are separate gates.
// Only source-epoch namespaces can consume this proof; CFG geometry cannot.
func (leg nativeNAT46Leg) targetPhysical() []nativeScope {
	_, epoch := epochChannelNames(false)
	target := any(leg.mapping.target.String())
	geometry := nativeJoin(
		nativeMatch(fmt.Sprintf("oifname %q", leg.mapping.targetInterface), guardMeta("oifname"), leg.mapping.targetInterface),
		nativeMatch("ip6 daddr "+leg.mapping.target.String(), guardPayload("ip6", "daddr"), leg.mapping.target.String()),
		nativeMatch("ip6 saddr "+leg.prefix.String(), guardPayload("ip6", "saddr"), controllerPrefix(leg.prefix)))
	if !leg.reply {
		key := map[string]any{"concat": []any{guardMeta("oifname"), guardPayload("ether", "daddr"), guardPayload("ip6", "daddr")}}
		geometry = nativeJoin(geometry, nativeMatch("oifname . ether daddr . ip6 daddr @"+ownership6Set, key, "@"+ownership6Set))
		target = guardPayload("ip6", "daddr")
	} else {
		geometry = nativeMatch("ip saddr "+leg.mapping.alias.String(), guardPayload("ip", "saddr"), leg.mapping.alias.String())
	}
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("priority"), "ffff:fc00"), target}}
	value := "ip6 daddr"
	if leg.reply {
		value = leg.mapping.target.String()
	}
	proof := nativeMatch("(meta priority & 0xfffffc00) . "+value+" @"+nativeSourceEpoch6, key, "@"+nativeSourceEpoch6)
	kinds := []uint64{nativeTag(false, leg.reply), nativeDirectoryTag(leg.reply), 0xf1000000, 0xf5000000}
	if leg.reply {
		kinds[2] += 0x01000000
		kinds[3] += 0x01000000
	}
	checks := []nativeScope{}
	for _, kind := range kinds {
		checks = append(checks, nativeJoin(nativeMark(0xff000000, kind), geometry, nativePriorityEpoch(epoch), proof, nativeVerdict("return", "")))
	}
	return append(checks, nativeVerdict("drop", ""))
}

// sourcePhysical binds a managed original IPv4 client to the actual packet at
// physical egress. Neither a live UID by itself nor an earlier inet check can
// substitute for the exact current address. Its deadline is the original
// ownership deadline, mirrored by the typed publisher in both families.
//
// This is an identity predicate only. The caller must separately enforce the
// current ordered scope, grants, original attachment and mapped listener. In
// particular, it must never substitute this NAS namespace for static geometry.
func (leg nativeNAT46Leg) sourcePhysical() []nativeScope {
	_, epoch := epochChannelNames(false)
	// Typed IP address predicates already constrain the network family.
	// nft omits a redundant Ethernet-type predicate from its canonical graph.
	geometry := nativeJoin(
		nativeMatch(fmt.Sprintf("oifname %q", leg.mapping.targetInterface), guardMeta("oifname"), leg.mapping.targetInterface),
		nativeMatch("ip6 daddr "+leg.mapping.target.String(), guardPayload("ip6", "daddr"), leg.mapping.target.String()),
		nativeMatch("ip6 saddr "+leg.prefix.String(), guardPayload("ip6", "saddr"), controllerPrefix(leg.prefix)))
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), nativeRawPayload(160)}}
	proof := nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . @nh,160,32 @"+nativeSourceBits4, key, "@"+nativeSourceBits4)
	if leg.reply {
		geometry = nativeMatch("ip saddr "+leg.mapping.alias.String(), guardPayload("ip", "saddr"), leg.mapping.alias.String())
		key = map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload("ip", "daddr")}}
		proof = nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . ip daddr @"+nativeSource4, key, "@"+nativeSource4)
	}
	checks := nativeJoin(geometry, nativePriorityEpoch(epoch), proof)
	return []nativeScope{
		nativeJoin(nativeMark(0xff000000, nativeTag(false, leg.reply)), checks, nativeVerdict("return", "")),
		nativeJoin(nativeMark(0xff000000, nativeDirectoryTag(leg.reply)), checks, nativeVerdict("return", "")),
		nativeVerdict("drop", ""),
	}
}

// A native reply still exposes the mapped device's IPv6 source before TAYGA.
// Its input MAC must be checked before routing replaces the Ethernet header;
// this physical predicate repeats the exact native address/epoch liveness.
func (leg nativeNAT46Leg) targetWirePhysical() []nativeScope {
	if !leg.reply {
		return leg.targetPhysical()
	}
	_, epoch := epochChannelNames(false)
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("priority"), "ffff:fc00"), guardPayload("ip6", "saddr")}}
	geometry := nativeJoin(nativeMatch("oifname \"nat46\"", guardMeta("oifname"), "nat46"), nativeMatch("ip6 saddr "+leg.mapping.target.String(), guardPayload("ip6", "saddr"), leg.mapping.target.String()), nativeMatch("ip6 daddr "+leg.prefix.String(), guardPayload("ip6", "daddr"), controllerPrefix(leg.prefix)))
	kinds := []uint64{nativeTag(false, true), nativeDirectoryTag(true), nativeNAT46StaticSourceTag(false, true), nativeNAT46StaticSourceTag(true, true)}
	rules := []nativeScope{}
	for _, kind := range kinds {
		rules = append(rules, nativeJoin(nativeMark(0xff000000, kind), geometry, nativePriorityEpoch(epoch), nativeMatch("(meta priority & 0xfffffc00) . ip6 saddr @"+nativeSourceEpoch6, key, "@"+nativeSourceEpoch6), nativeVerdict("return", "")))
	}
	return append(rules, nativeVerdict("drop", ""))
}
