package firewall

// Export uses packet priority as temporary correlation storage. A connection
// marker is never scratch space: it must retain its original epoch and rule
// even if publication changes or a later lookup fails. The packet mark keeps
// its complete source context, QoS byte and saved original priority throughout.
func (transport *nativeNAT64Transport) exportChains(leg nativeNAT64Leg, checked, keyText string, key any) map[string][]nativeScope {
	chains := map[string][]nativeScope{}
	tokenStage, record := checked+"_token", checked+"_record"
	if leg.reply {
		restoreStage := checked + "_priority"
		chains[checked] = []nativeScope{
			nativeVerdict("jump", transport.name+"_origin_restore"),
			nativeJoin(
				nativeDynamicDelete(leg.name+"_origin_proof", keyText+" : meta priority", key, guardMeta("priority")),
				nativeDynamicUpdate(leg.name+"_origin_proof", keyText+" : meta priority", key, guardMeta("priority")),
				nativeVerdict("goto", restoreStage)),
			nativeVerdict("drop", ""),
		}
		chains[restoreStage] = []nativeScope{
			nativeVerdict("jump", transport.name+"_export_priority"),
			nativeVerdict("goto", tokenStage),
		}
	} else {
		chains[checked] = []nativeScope{nativeVerdict("goto", tokenStage)}
	}
	tokenText, token := transport.token()
	chains[tokenStage] = []nativeScope{nativeJoin(
		nativeMangle("meta priority set "+tokenText, guardMeta("priority"), token),
		nativeVerdict("goto", record)), nativeVerdict("drop", "")}
	chains[record] = []nativeScope{nativeJoin(
		nativeDynamicDelete(leg.name+"_proof", keyText+" : meta priority", key, guardMeta("priority")),
		nativeDynamicUpdate(leg.name+"_proof", keyText+" : meta priority", key, guardMeta("priority")),
		nativeMangle("meta priority set meta priority map @"+transport.name+"_export_channel", guardMeta("priority"),
			map[string]any{"map": map[string]any{"key": guardMeta("priority"), "data": "@" + transport.name + "_export_channel"}}),
		nativeVerdict("return", "")), nativeVerdict("drop", "")}
	return chains
}

// A returning IPv4 connection already has immutable authorization facts.
// Recover only their priority word after exporting the independent origin;
// restoring the complete facts would overwrite packet-local QoS and priority.
func (transport *nativeNAT64Transport) exportPriorityChain() []nativeScope {
	rules := []nativeScope{
		nativeJoin(nativeFactLabel(nativeFactsValidBit, false), nativeVerdict("drop", "")),
		nativeMangle("meta priority set 0", guardMeta("priority"), "none"),
	}
	for index := uint(0); index < 32; index++ {
		bit := nativeFactBit{field: "priority", mask: uint32(1) << index, label: 64 + index}
		rules = append(rules, nativeJoin(nativeFactLabel(bit.label, true), bit.restore()))
	}
	return append(rules, nativeVerdict("return", ""))
}
