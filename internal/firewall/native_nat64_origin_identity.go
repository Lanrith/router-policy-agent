package firewall

const nativeNAT64OriginIdentityValidBit = uint(125)

type nativeNAT64OriginIdentityBit struct {
	packet nativeFactBit
	label  uint
	word   uint32
}

// The separate origin identity contains context (10 bits), source UID (13)
// and configuration-versus-owned provenance (1). The original marker already
// carries its epoch. Authorization labels 32..95, unrelated label 100 and the
// original marker at 0..31 remain untouched. A numeric epoch alone cannot
// distinguish independently numbered configuration and ownership channels.
func nativeNAT64OriginIdentityBits() []nativeNAT64OriginIdentityBit {
	fields := make([]nativeFactBit, 0, 24)
	for index := uint(0); index < 10; index++ {
		fields = append(fields, nativeFactBit{field: "mark", mask: uint32(1) << index, label: 32 + index})
	}
	for index := uint(0); index < 10; index++ {
		fields = append(fields, nativeFactBit{field: "priority", mask: uint32(1) << index, label: 64 + index})
	}
	for index := uint(13); index < 16; index++ {
		fields = append(fields, nativeFactBit{field: "mark", mask: uint32(1) << index, label: 32 + index})
	}
	// Original configuration kind d3 has this bit; owner/source d1 and
	// delegated/source d5 do not. Direction and destination permission are
	// deliberately absent from this source provenance discriminator.
	fields = append(fields, nativeFactBit{field: "mark", mask: 1 << 25, label: 57})
	bits := make([]nativeNAT64OriginIdentityBit, 0, len(fields))
	for index, packet := range fields {
		label := uint(96 + index) // #nosec G115 -- the identity has exactly 24 bits.
		if label >= 100 {
			label++
		}
		bits = append(bits, nativeNAT64OriginIdentityBit{packet: packet, label: label, word: uint32(1) << index})
	}
	return bits
}

// These chains retain provenance only. Their caller must supply the exact
// original tuple and repeat current allocation, policy and authority checks.
func (transport *nativeNAT64Transport) originIdentityChains() map[string][]nativeScope {
	prefix := transport.name + "_origin_identity"
	chains := map[string][]nativeScope{}
	chains[prefix+"_capture"] = []nativeScope{
		nativeJoin(nativeFactLabel(nativeNAT64OriginIdentityValidBit, true), nativeVerdict("goto", prefix+"_compare")),
		nativeJoin(nativeScope{text: "ct status confirmed", expressions: []any{map[string]any{"match": map[string]any{
			"op": "in", "left": nativeCT("status"), "right": "confirmed",
		}}}}, nativeVerdict("drop", "")),
		nativeVerdict("jump", prefix+"_empty"), nativeVerdict("jump", prefix+"_copy"),
		nativeFactSetLabel(nativeNAT64OriginIdentityValidBit), nativeVerdict("goto", prefix+"_compare"),
	}
	chains[prefix+"_restore"] = []nativeScope{
		nativeJoin(nativeFactLabel(nativeNAT64OriginIdentityValidBit, false), nativeVerdict("drop", "")),
		nativeMangle("meta priority set 0", guardMeta("priority"), "none"),
	}
	// Raw IPv6 originals retain their complete source facts before export.
	// A return must match those facts, even if its wire authorization uses a
	// different rule, kind or independently numbered destination epoch.
	chains[prefix+"_connection"] = []nativeScope{
		nativeJoin(nativeFactLabel(nativeFactsValidBit, false), nativeVerdict("drop", "")),
	}
	for _, bit := range nativeNAT64OriginIdentityBits() {
		word := nativeFactBit{field: "priority", mask: bit.word}
		chains[prefix+"_empty"] = append(chains[prefix+"_empty"], nativeJoin(nativeFactLabel(bit.label, true), nativeVerdict("drop", "")))
		chains[prefix+"_copy"] = append(chains[prefix+"_copy"], nativeJoin(bit.packet.packet(true), nativeFactSetLabel(bit.label)))
		chains[prefix+"_compare"] = append(chains[prefix+"_compare"],
			nativeJoin(nativeFactLabel(bit.label, true), bit.packet.packet(false), nativeVerdict("drop", "")),
			nativeJoin(nativeFactLabel(bit.label, false), bit.packet.packet(true), nativeVerdict("drop", "")))
		chains[prefix+"_restore"] = append(chains[prefix+"_restore"], nativeJoin(nativeFactLabel(bit.label, true), word.restore()))
		chains[prefix+"_connection"] = append(chains[prefix+"_connection"],
			nativeJoin(nativeFactLabel(bit.packet.label, true), word.packet(false), nativeVerdict("drop", "")),
			nativeJoin(nativeFactLabel(bit.packet.label, false), word.packet(true), nativeVerdict("drop", "")))
	}
	for _, suffix := range []string{"_empty", "_copy", "_compare", "_restore", "_connection"} {
		chains[prefix+suffix] = append(chains[prefix+suffix], nativeVerdict("return", ""))
	}
	return chains
}
