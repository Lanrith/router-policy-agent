package firewall

import (
	"fmt"
	"net/netip"
)

// Import binds the allocated IPv4 alias to the original IPv6 source facts.
// A classified alias is not a native IPv4 device on the translator attachment.
// Only current owned-source kinds can use that representation; configuration
// and target-authorized kinds retain the ordinary native source validator.
func (access *nativeAccess) compileNAT64AliasSource(transport *nativeNAT64Transport) string {
	chain := transport.name + "_alias_source"
	if _, exists := access.inet[chain]; exists {
		return chain
	}
	_, epoch := epochChannelNames(false)
	for _, kind := range []uint64{nativeTag(false, false), nativeDirectoryTag(false)} {
		access.add(chain, nativeMark(0xff000000, kind), nativePriorityEpoch(epoch), nativeNAT64SourceLive(), nativeVerdict("return", ""))
	}
	access.add(chain, nativeVerdict("jump", "validate_source"))
	access.add(chain, nativeVerdict("return", ""))
	return chain
}

// The allocated return alias leads back through the translator. Current caller
// identity remains mandatory here; its actual IPv6 address/interface/MAC is
// checked again at final client egress. Directory tuple checks precede this
// continuation. Configuration-based flows keep their existing target checks.
func (access *nativeAccess) compileNAT64ReturnAlias(transport *nativeNAT64Transport, directory bool) string {
	chain := fmt.Sprintf("%s_return_alias_%t", transport.name, directory)
	if _, exists := access.netdev[chain]; exists {
		return chain
	}
	kind := nativeTag(false, true)
	if directory {
		kind = nativeDirectoryTag(true)
	}
	access.netdev[chain] = []nativeScope{nativeJoin(nativeMark(0xff000000, kind), nativeNAT64SourceLive(), nativeVerdict("goto", "native_final_source"))}
	if !directory {
		access.netdev[chain] = append(access.netdev[chain], nativeJoin(nativeMark(0xff000000, nativeTag(true, true)), nativeVerdict("goto", "native_physical_admitted")))
	}
	access.netdev[chain] = append(access.netdev[chain], nativeVerdict("drop", ""))
	return chain
}

// The source UID remains the original IPv6 caller's. The separately published
// epoch/address mirror validates the IPv4 sender without borrowing that UID.
func nativeNAT64IPv4SenderEpoch(imported bool) nativeScope {
	offset := 96
	if imported {
		offset = 160
	}
	peer := nativeRawField(offset, 32)
	if !imported {
		peer = guardPayload("ip", "saddr")
	}
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("priority"), "ffff:fc00"), peer}}
	return nativeMatch(fmt.Sprintf("(meta priority & 0xfffffc00) . @nh,%d,32 @%s", offset, nativeSourceEpoch4), key, "@"+nativeSourceEpoch4)
}

// This check is additional to current caller/grant checks. Historical target
// classification survives expiration, so a classified return sender must keep
// its independent current IPv4 ownership through the final physical hook.
func (access *nativeAccess) compileNAT64ReturnSender(transport *nativeNAT64Transport, imported bool, continuation string) string {
	chain := fmt.Sprintf("%s_return_sender_%t_%s", transport.name, imported, continuation)
	if _, exists := access.netdev[chain]; exists {
		return chain
	}
	family, classified := "ip", classified4Set
	if imported {
		family, classified = "ip6", classified6Set
	}
	known := nativeMatch(family+" saddr @"+classified, guardPayload(family, "saddr"), "@"+classified)
	scopes := []nativeScope{known}
	for _, network := range transport.managedIPv4 {
		if imported {
			bits := transport.prefix.Addr().As16()
			address := network.Addr().As4()
			copy(bits[12:], address[:])
			network = netip.PrefixFrom(netip.AddrFrom16(bits), transport.prefix.Bits()+network.Bits())
		}
		scopes = append(scopes, nativeFloorPrefix(network, false, true))
	}
	for _, scope := range scopes {
		access.netdev[chain] = append(access.netdev[chain],
			nativeJoin(scope, nativeNAT64IPv4SenderEpoch(imported), nativeVerdict("goto", continuation)),
			nativeJoin(scope, nativeVerdict("drop", "")))
	}
	access.netdev[chain] = append(access.netdev[chain], nativeVerdict("goto", continuation))
	return chain
}
