package firewall

import "fmt"

const nativeNAT64OriginValidBit = uint(126)

// Retain the original IPv6 connection marker separately from the IPv4
// authorization facts. The latter may name a different final-interface rule.
// Labels 0..31 and 126 are private to NAT64; shared authorization facts use
// labels 32..95 and 127. None of these chains supplies forwarding permission.
func (transport *nativeNAT64Transport) originChains() map[string][]nativeScope {
	prefix := transport.name + "_origin"
	chains := map[string][]nativeScope{}
	chains[prefix+"_capture"] = []nativeScope{
		nativeJoin(nativeFactLabel(nativeNAT64OriginValidBit, true), nativeVerdict("goto", prefix+"_compare")),
		nativeJoin(nativeScope{text: "ct status confirmed", expressions: []any{map[string]any{"match": map[string]any{
			"op": "in", "left": nativeCT("status"), "right": "confirmed",
		}}}}, nativeVerdict("drop", "")),
		nativeVerdict("jump", prefix+"_empty"), nativeVerdict("jump", prefix+"_copy"),
		nativeFactSetLabel(nativeNAT64OriginValidBit), nativeVerdict("goto", prefix+"_compare"),
	}
	chains[prefix+"_restore"] = []nativeScope{
		nativeJoin(nativeFactLabel(nativeNAT64OriginValidBit, false), nativeVerdict("drop", "")),
		nativeMangle("meta priority set 0", guardMeta("priority"), "none"),
	}
	for index := uint(0); index < 32; index++ {
		bit := nativeFactBit{field: "priority", mask: uint32(1) << index, label: index}
		chains[prefix+"_empty"] = append(chains[prefix+"_empty"], nativeJoin(nativeFactLabel(index, true), nativeVerdict("drop", "")))
		chains[prefix+"_copy"] = append(chains[prefix+"_copy"], nativeJoin(bit.packet(true), nativeFactSetLabel(index)))
		chains[prefix+"_compare"] = append(chains[prefix+"_compare"],
			nativeJoin(nativeFactLabel(index, true), bit.packet(false), nativeVerdict("drop", "")),
			nativeJoin(nativeFactLabel(index, false), bit.packet(true), nativeVerdict("drop", "")))
		chains[prefix+"_restore"] = append(chains[prefix+"_restore"], nativeJoin(nativeFactLabel(index, true), bit.restore()))
		chains[prefix+"_connection"] = append(chains[prefix+"_connection"],
			nativeJoin(nativeMatch(fmt.Sprintf("ct mark & %#x == %#x", bit.mask, bit.mask), guardBinary("&", nativeCT("mark"), bit.mask), bit.mask), bit.packet(false), nativeVerdict("drop", "")),
			nativeJoin(nativeMatch(fmt.Sprintf("ct mark & %#x == 0", bit.mask), guardBinary("&", nativeCT("mark"), bit.mask), 0), bit.packet(true), nativeVerdict("drop", "")))
	}
	for _, suffix := range []string{"_empty", "_copy", "_compare", "_restore", "_connection"} {
		chains[prefix+suffix] = append(chains[prefix+suffix], nativeVerdict("return", ""))
	}
	return chains
}
