package firewall

import (
	"fmt"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"strings"
)

// This validator has no forwarding or tuple-publication verdict. Its caller
// first checks the selected leg's geometry and full tuple, then records only
// that leg's new snapshot after these current namespace/source checks return.
func (transport *nativeNAT46Transport) sourceChecks(leg nativeNAT46Leg, imported bool, current string, continuation nativeScope) map[string][]nativeScope {
	chains := map[string][]nativeScope{}
	chains[current] = append(chains[current], nativeVerdict("jump", "native_n46_same_epoch"))
	for _, configuration := range []bool{false, true} {
		epoch, _, _, _ := nativeEpoch(configuration)
		kinds := []uint64{nativeTag(configuration, leg.reply)}
		if configuration && transport.staticGeometry != (policy.NAT46StaticGeometry{}) {
			kinds = append(kinds, nativeNAT46StaticTag(leg.reply))
		}
		if !configuration && leg.protocol != "icmp" {
			kinds = append(kinds, nativeDirectoryTag(leg.reply))
		}
		if !configuration && transport.sourceGeometry {
			kinds = append(kinds, nativeNAT46StaticSourceTag(false, leg.reply))
			if leg.protocol != "icmp" {
				kinds = append(kinds, nativeNAT46StaticSourceTag(true, leg.reply))
			}
		}
		for _, kind := range kinds {
			chains[current] = append(chains[current], nativeJoin(nativeMark(0xff000000, kind), nativeMatch(fmt.Sprintf("ct mark & %#x @%s", ownershipEpochMask, epoch), guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+epoch), nativeVerdict("goto", current+"_source")))
		}
	}
	chains[current] = append(chains[current], nativeVerdict("drop", ""))
	source := current + "_source"
	// A nonzero ID must still name the original IPv4 client, including on
	// return legs where that client is the packet's destination.
	if transport.staticGeometry != (policy.NAT46StaticGeometry{}) {
		raw := leg.key(imported).expressions[0]
		offset := strings.Split(leg.key(imported).text, " . ")[0]
		key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), raw}}
		static := source + "_static"
		chains[source] = append(chains[source], nativeJoin(nativeMark(0xff000000, nativeNAT46StaticTag(leg.reply)), nativeVerdict("goto", static)))
		family, client, target := "ip", "saddr", "daddr"
		if leg.reply != imported {
			family = "ip6"
		}
		if leg.reply {
			client, target = "daddr", "saddr"
		}
		chains[static] = nativeNAT46StaticHistory(family, client, target)
		chains[static] = append(chains[static],
			nativeJoin(nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . "+offset+" @"+nativeNAT46StaticBits4, key, "@"+nativeNAT46StaticBits4), continuation),
			nativeVerdict("drop", ""),
		)
		if transport.sourceGeometry {
			staticSource := source + "_source_geometry"
			for _, directory := range []bool{false, true} {
				if directory && leg.protocol == "icmp" {
					continue
				}
				chains[source] = append(chains[source], nativeJoin(nativeMark(0xff000000, nativeNAT46StaticSourceTag(directory, leg.reply)), nativeVerdict("goto", staticSource)))
			}
			history := classified4Set
			if family == "ip6" {
				history = classified6Set
			}
			chains[staticSource] = []nativeScope{
				nativeJoin(nativeMatch(family+" "+client+" @"+history, guardPayload(family, client), "@"+history), nativeVerdict("drop", "")),
				nativeJoin(nat46StaticSourceLive(), nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . "+offset+" @"+nativeNAT46StaticBits4, key, "@"+nativeNAT46StaticBits4), continuation),
				nativeVerdict("drop", ""),
			}
		}
	}
	chains[source] = append(chains[source], nativeJoin(nativeMark(uint64(nativeSourceMask), 0), nativeMatch("meta priority & 0x3ff == none", guardBinary("&", guardMeta("priority"), "0:3ff"), "none"), continuation))
	raw := leg.key(imported).expressions[0]
	offset := strings.Split(leg.key(imported).text, " . ")[0]
	sourceKey := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), raw}}
	chains[source] = append(chains[source], nativeJoin(nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . "+offset+" @"+nativeSourceBits4, sourceKey, "@"+nativeSourceBits4), continuation), nativeVerdict("drop", ""))
	return chains
}

func (leg nativeNAT46Leg) sharedCurrentName(imported bool) string {
	family, direction, protocol := "raw4", "original", "transport"
	if leg.reply != imported {
		family = "wire6"
	}
	if leg.reply {
		direction = "reply"
	}
	if leg.protocol == "icmp" {
		protocol = "echo"
	}
	return "native_n46_current_" + family + "_" + direction + "_" + protocol
}
