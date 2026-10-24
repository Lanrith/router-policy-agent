package firewall

import (
	"context"
	"errors"
	"fmt"
)

const (
	nativeFactsMask     = uint32(0xff00e3ff)
	nativeFactsValidBit = uint(127)
)

type nativeFactBit struct {
	field string
	mask  uint32
	label uint
}

func nativeFactBits() []nativeFactBit {
	bits := make([]nativeFactBit, 0, 53)
	for bit := uint(0); bit < 32; bit++ {
		mask := uint32(1) << bit
		if mask&nativeFactsMask != 0 {
			bits = append(bits, nativeFactBit{field: "mark", mask: mask, label: 32 + bit})
		}
		bits = append(bits, nativeFactBit{field: "priority", mask: mask, label: 64 + bit})
	}
	return bits
}

// Conntrack label numbers identify bitmap positions, not numeric masks. Keep
// the low 32 bits available for an independent NAT64 allocation identity.
func nativeFactLabel(bit uint, present bool) nativeScope {
	op := "=="
	if !present {
		op = "!="
	}
	return nativeScope{text: fmt.Sprintf("ct label & %d %s %d", bit, op, bit), expressions: []any{
		map[string]any{"match": map[string]any{"op": op, "left": guardBinary("&", nativeCT("label"), bit), "right": bit}},
	}}
}

func (bit nativeFactBit) packet(present bool) nativeScope {
	if bit.field == "mark" {
		value := uint64(0)
		if present {
			value = uint64(bit.mask)
		}
		return nativeMark(uint64(bit.mask), value)
	}
	mask, value := epochClassID(bit.mask), "none"
	if present {
		value = mask
	}
	return nativeMatch("meta priority & "+mask+" == "+value, guardBinary("&", guardMeta("priority"), mask), value)
}

func nativeFactSetLabel(bit uint) nativeScope {
	return nativeMangle(fmt.Sprintf("ct label set ct label | %d", bit), nativeCT("label"), guardBinary("|", nativeCT("label"), bit))
}

func (bit nativeFactBit) restore() nativeScope {
	var mask any = bit.mask
	spelling := fmt.Sprintf("%#x", bit.mask)
	if bit.field == "priority" {
		mask, spelling = epochClassID(bit.mask), epochClassID(bit.mask)
	}
	return nativeMangle("meta "+bit.field+" set meta "+bit.field+" | "+spelling,
		guardMeta(bit.field), guardBinary("|", guardMeta(bit.field), mask))
}

func nativeFactsPositiveConnection() nativeScope {
	return nativeScope{text: "ct mark != 0", expressions: []any{map[string]any{"match": map[string]any{
		"op": "!=", "left": nativeCT("mark"), "right": 0,
	}}}}
}

// These chains preserve immutable authorization facts, not permission. The
// caller must admit each original through its fresh translator tuple, current
// ordered scope, ownership and grant checks before capture. Every reply must
// repeat its current checks after restore and before exporting a fresh tuple.
// No chain installs a hook, accepts traffic or rewrites a connection mark.
func nativeTranslationFacts(ctx context.Context) (map[string][]nativeScope, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing translation facts context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	const prefix = "native_translation_facts"
	chains := map[string][]nativeScope{}
	bits := nativeFactBits()
	originals := []uint64{0xd1000000, 0xd3000000, 0xd5000000, 0xf1000000, 0xf3000000, 0xf5000000}
	// Explicit alternatives preserve the selected metadata namespace.
	for _, tag := range originals {
		chains[prefix+"_capture"] = append(chains[prefix+"_capture"], nativeJoin(
			nativeMatch("ct direction original", nativeCT("direction"), "original"),
			nativeMatch("ct state { established, new }", nativeCT("state"), map[string]any{"set": []string{"established", "new"}}),
			nativeFactsPositiveConnection(), nativeMark(0xff000000, tag), nativeVerdict("goto", prefix+"_capture_current")))
		chains[prefix+"_reply_kind"] = append(chains[prefix+"_reply_kind"], nativeJoin(
			nativeMark(0xff000000, tag), nativeStampKind(tag+0x01000000), nativeVerdict("return", "")))
	}
	chains[prefix+"_capture"] = append(chains[prefix+"_capture"], nativeVerdict("drop", ""))
	chains[prefix+"_reply_kind"] = append(chains[prefix+"_reply_kind"], nativeVerdict("drop", ""))
	chains[prefix+"_capture_current"] = []nativeScope{
		nativeVerdict("jump", prefix+"_epoch"),
		nativeJoin(nativeFactLabel(nativeFactsValidBit, true), nativeVerdict("goto", prefix+"_compare")),
		// Only a private, unconfirmed connection may acquire initial facts.
		// Concurrent first packets have separate unconfirmed objects. A
		// confirmed connection with missing facts cannot bind a later context.
		nativeJoin(nativeScope{text: "ct status confirmed", expressions: []any{map[string]any{"match": map[string]any{
			"op": "in", "left": nativeCT("status"), "right": "confirmed",
		}}}}, nativeVerdict("drop", "")),
		nativeVerdict("jump", prefix+"_empty"), nativeVerdict("jump", prefix+"_copy"),
		nativeFactSetLabel(nativeFactsValidBit), nativeVerdict("goto", prefix+"_compare"),
	}
	chains[prefix+"_compare"] = []nativeScope{nativeJoin(nativeFactLabel(nativeFactsValidBit, false), nativeVerdict("drop", ""))}
	for _, bit := range bits {
		chains[prefix+"_empty"] = append(chains[prefix+"_empty"], nativeJoin(nativeFactLabel(bit.label, true), nativeVerdict("drop", "")))
		chains[prefix+"_copy"] = append(chains[prefix+"_copy"], nativeJoin(bit.packet(true), nativeFactSetLabel(bit.label)))
		chains[prefix+"_compare"] = append(chains[prefix+"_compare"],
			nativeJoin(nativeFactLabel(bit.label, true), bit.packet(false), nativeVerdict("drop", "")),
			nativeJoin(nativeFactLabel(bit.label, false), bit.packet(true), nativeVerdict("drop", "")))
		chains[prefix+"_restore_copy"] = append(chains[prefix+"_restore_copy"], nativeJoin(nativeFactLabel(bit.label, true), bit.restore()))
	}
	for _, suffix := range []string{"_empty", "_copy", "_compare", "_restore_copy"} {
		chains[prefix+suffix] = append(chains[prefix+suffix], nativeVerdict("return", ""))
	}
	chains[prefix+"_restore"] = []nativeScope{nativeJoin(
		nativeMatch("ct direction reply", nativeCT("direction"), "reply"), nativeState("established"),
		nativeFactsPositiveConnection(), nativeFactLabel(nativeFactsValidBit, true),
		nativeVerdict("goto", prefix+"_restore_current")), nativeVerdict("drop", "")}
	chains[prefix+"_restore_current"] = []nativeScope{
		nativeVerdict("jump", "save_owner_priority"),
		nativeMangle("meta mark set meta mark & 0x00ff1c00", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint32(0x00ff1c00))),
		nativeMangle("meta priority set 0", guardMeta("priority"), "none"),
		nativeVerdict("jump", prefix+"_restore_copy"), nativeVerdict("jump", prefix+"_epoch"),
		nativeVerdict("goto", prefix+"_reply_kind"),
	}
	for bit := uint(10); bit < 32; bit++ {
		mask := uint32(1) << bit
		class := epochClassID(mask)
		set := nativeMatch(fmt.Sprintf("ct mark & %#x == %#x", mask, mask), guardBinary("&", nativeCT("mark"), mask), mask)
		zero := nativeMatch(fmt.Sprintf("ct mark & %#x == 0", mask), guardBinary("&", nativeCT("mark"), mask), 0)
		priorityZero := nativeMatch("meta priority & "+class+" == none", guardBinary("&", guardMeta("priority"), class), "none")
		prioritySet := nativeMatch("meta priority & "+class+" == "+class, guardBinary("&", guardMeta("priority"), class), class)
		chains[prefix+"_epoch"] = append(chains[prefix+"_epoch"],
			nativeJoin(set, priorityZero, nativeVerdict("drop", "")), nativeJoin(zero, prioritySet, nativeVerdict("drop", "")))
	}
	chains[prefix+"_epoch"] = append(chains[prefix+"_epoch"], nativeVerdict("return", ""))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return chains, nil
}
