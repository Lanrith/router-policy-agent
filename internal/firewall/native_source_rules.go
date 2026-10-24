package firewall

import "fmt"

func nativePriorityEpoch(set string) nativeScope {
	return nativeMatch("meta priority & 0xfffffc00 @"+set, guardBinary("&", guardMeta("priority"), "ffff:fc00"), "@"+set)
}

func (access *nativeAccess) compileSourceHandoff() {
	epoch := func(configuration bool) nativeScope {
		set, _, _, _ := nativeEpoch(configuration)
		return nativeMatch(fmt.Sprintf("ct mark & %#x @%s", ownershipEpochMask, set), guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+set)
	}
	for _, configuration := range []bool{false, true} {
		name := "native_source_handoff"
		if configuration {
			name = "native_configuration_handoff"
		} else {
			for _, iface := range access.managed {
				access.add(name, nativeMatch(fmt.Sprintf("iifname %q", iface), guardMeta("iifname"), iface), nativeVerdict("goto", "native_bound_source"))
			}
			access.add(name, nativeMatch("ether saddr @"+cohortSet, guardPayload("ether", "saddr"), "@"+cohortSet), nativeVerdict("goto", "native_bound_source"))
			for _, family := range []struct{ protocol, set string }{{"ip", classified4Set}, {"ip6", classified6Set}} {
				access.add(name, nativeMatch(family.protocol+" saddr @"+family.set, guardPayload(family.protocol, "saddr"), "@"+family.set), nativeVerdict("goto", "native_bound_source"))
			}
		}
		_, _, channel, _ := nativeEpoch(configuration)
		access.add(name, epoch(configuration), nativeMangle(fmt.Sprintf("meta priority set ct mark & %#x map @%s", ownershipEpochMask, channel), guardMeta("priority"),
			map[string]any{"map": map[string]any{"key": guardBinary("&", nativeCT("mark"), ownershipEpochMask), "data": "@" + channel}}), nativeVerdict("return", ""))
		access.add(name, nativeVerdict("drop", ""))
	}
	for _, family := range []struct{ name, protocol string }{{"4", "ipv4"}, {"6", "ipv6"}} {
		access.add("native_bound_source", nativeMatch("meta nfproto "+family.protocol, guardMeta("nfproto"), family.protocol), nativeVerdict("goto", "native_bound_source"+family.name))
	}
	access.add("native_bound_source", nativeVerdict("drop", ""))
	key4 := map[string]any{"concat": []any{guardBinary("&", nativeCT("mark"), ownershipEpochMask), guardMeta("iifname"), guardPayload("ether", "saddr"), guardPayload("ip", "saddr")}}
	access.add("native_bound_source4", epoch(false), nativeMangle(fmt.Sprintf("meta priority set (ct mark & %#x) . iifname . ether saddr . ip saddr map @%s", ownershipEpochMask, nativeSourceIDs4), guardMeta("priority"),
		map[string]any{"map": map[string]any{"key": key4, "data": "@" + nativeSourceIDs4}}), nativeVerdict("goto", "native_source_high_bits"))
	access.add("native_bound_source4", nativeVerdict("drop", ""))
	key := map[string]any{"concat": []any{guardBinary("&", nativeCT("mark"), ownershipEpochMask), guardMeta("iifname"), guardPayload("ether", "saddr"), guardPayload("ip6", "saddr")}}
	access.add("native_bound_source6", epoch(false), nativeMangle(fmt.Sprintf("meta priority set (ct mark & %#x) . iifname . ether saddr . ip6 saddr map @%s", ownershipEpochMask, nativeSourceIDs6), guardMeta("priority"),
		map[string]any{"map": map[string]any{"key": key, "data": "@" + nativeSourceIDs6}}), nativeVerdict("goto", "native_source_high_bits"))
	access.add("native_bound_source6", nativeVerdict("drop", ""))
	for group := uint32(0); group <= 7; group++ {
		parts := []nativeScope{nativeMatch(fmt.Sprintf("meta priority & 0x1c00 == %#x", group<<10), guardBinary("&", guardMeta("priority"), "0:1c00"), nativeLowHighClassID(group<<10)),
			nativeMangle("meta mark set meta mark & 0xffff1fff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xffff1fff)))}
		if group != 0 {
			parts = append(parts, nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", group<<13), guardMeta("mark"), guardBinary("|", guardMeta("mark"), group<<13)))
		}
		parts = append(parts, nativeVerdict("goto", "native_source_low_bits"))
		access.add("native_source_high_bits", parts...)
	}
	access.add("native_source_high_bits", nativeVerdict("drop", ""))
	key = map[string]any{"concat": []any{guardBinary("&", nativeCT("mark"), ownershipEpochMask), guardBinary("&", guardMeta("priority"), "0:3ff")}}
	access.add("native_source_low_bits", epoch(false), nativeMangle(fmt.Sprintf("meta priority set (ct mark & %#x) . (meta priority & 0x3ff) map @%s", ownershipEpochMask, nativeSourceChannel), guardMeta("priority"),
		map[string]any{"map": map[string]any{"key": key, "data": "@" + nativeSourceChannel}}), nativeVerdict("return", ""))
	access.add("native_source_low_bits", nativeVerdict("drop", ""))
}

func nativeLowHighClassID(value uint32) string {
	if value == 0 {
		return "none"
	}
	return epochClassID(value)
}

func (access *nativeAccess) compilePhysicalSource() {
	for _, family := range []struct{ protocol, set string }{{"ip", nativeSource4}, {"ip6", nativeSource6}} {
		key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload(family.protocol, "saddr")}}
		access.netdev["native_bound_source"] = append(access.netdev["native_bound_source"], nativeJoin(
			nativeMatch(fmt.Sprintf("(meta mark & %#x) . (meta priority & 0x3ff) . %s saddr @%s", nativeSourceMask, family.protocol, family.set), key, "@"+family.set), nativeVerdict("return", "")))
	}
	access.netdev["native_bound_source"] = append(access.netdev["native_bound_source"], nativeVerdict("drop", ""))
}
