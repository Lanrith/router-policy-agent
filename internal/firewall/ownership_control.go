package firewall

// ownershipLocalControl preserves only locally generated link control. A
// classified MAC must still be able to discover its router while ownership or
// directory state is sealed. No ownership epoch or forwarding permission is set.
// Local IP services remain subject to the router's separate output firewall;
// forwarded packets cannot retain the reserved local-output origin token.
func ownershipLocalControl() []nativeScope {
	local := nativeMatch("meta iif 0", guardMeta("iif"), "0")
	arp := nativeJoin(local,
		nativeMatch("arp htype 1", guardPayload("arp", "htype"), 1),
		nativeMatch("arp ptype ip", guardPayload("arp", "ptype"), "ip"),
		nativeMatch("arp hlen 6", guardPayload("arp", "hlen"), 6),
		nativeMatch("arp plen 4", guardPayload("arp", "plen"), 4))
	var rules []nativeScope
	for _, operation := range []string{"request", "reply"} {
		rules = append(rules, nativeJoin(arp, nativeMatch("arp operation "+operation, guardPayload("arp", "operation"), operation), nativeVerdict("return", "")))
	}
	// Redirects and ordinary ICMP are excluded. Hop limit 255 and code zero
	// retain the on-link control contract even for unicast link-local replies,
	// whose destination is not an application-address ownership tuple.
	for _, origin := range []nativeScope{local, nativeMark(0xff000000, localOutputTag)} {
		for _, kind := range []string{"nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert"} {
			rules = append(rules, nativeJoin(origin,
				nativeMatch("ip6 hoplimit 255", guardPayload("ip6", "hoplimit"), 255),
				nativeMatch("icmpv6 type "+kind, guardPayload("icmpv6", "type"), kind),
				nativeMatch("icmpv6 code 0", guardPayload("icmpv6", "code"), 0),
				nativeMangle("meta mark set meta mark & 0x00ffffff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0x00ffffff))),
				nativeVerdict("return", "")))
		}
	}
	return rules
}

// The output hook supplies an origin token; forwarded packets never traverse
// it, and guard_forward clears the reserved high byte before any admission.
// Kernel neighbor replies can report their output device as an input identity
// in postrouting, so an interface-zero test alone is insufficient.
const localOutputTag = uint64(0xbc000000)

func ownershipLocalOutput() []nativeScope {
	return []nativeScope{
		nativeMangle("meta mark set meta mark & 0x00ffffff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0x00ffffff))),
		nativeMangle("meta mark set meta mark | 0xbc000000", guardMeta("mark"), guardBinary("|", guardMeta("mark"), localOutputTag)),
	}
}
