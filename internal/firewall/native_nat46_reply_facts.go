package firewall

// The early reply hook already saved the incoming QoS priority before
// restoring its authorization channel. The late confirmation hook must read
// the immutable connection facts again, preserving those saved priority bits;
// its current meta priority is now an authorization channel, not a new QoS
// value. Current scope, ownership, grants and tuple checks remain mandatory.
func nativeNAT46ReplyConfirmationFacts() map[string][]nativeScope {
	const name = "native_n46_reply_confirm_facts"
	return map[string][]nativeScope{
		name: {
			nativeJoin(nativeMatch("ct direction reply", nativeCT("direction"), "reply"), nativeState("established"), nativeFactsPositiveConnection(), nativeFactLabel(nativeFactsValidBit, true), nativeVerdict("goto", name+"_current")),
			nativeVerdict("drop", ""),
		},
		name + "_current": {
			nativeMangle("meta mark set meta mark & 0x00ff1c00", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint32(0x00ff1c00))),
			nativeMangle("meta priority set 0", guardMeta("priority"), "none"),
			nativeVerdict("jump", "native_translation_facts_restore_copy"),
			nativeVerdict("jump", "native_translation_facts_epoch"),
			nativeVerdict("goto", "native_translation_facts_reply_kind"),
		},
	}
}
