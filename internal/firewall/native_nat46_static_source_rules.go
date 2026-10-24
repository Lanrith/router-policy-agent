package firewall

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
)

func nativeNAT46StaticSourceTag(directory, reply bool) uint64 {
	kind := uint64(0xf1000000)
	if directory {
		kind += 0x04000000
	}
	if reply {
		kind += 0x01000000
	}
	return kind
}

// sourceHandoff consumes an already admitted SOURCE-epoch tuple for a static
// IPv4 client reaching a native NAS target. It cannot consume a NAS client's
// UID or configuration epoch. The target proof and current permission remain
// separate mandatory gates, including after this geometry handoff.
func (sources *nativeNAT46StaticSources) sourceHandoff(ctx context.Context, packetContext nativePacketContext, directory bool) (map[string][]nativeScope, error) {
	_, chains, err := sources.sourceHandoffGroup(ctx, []nativePacketContext{packetContext}, directory)
	return chains, err
}

// Only original contexts on the same ingress may share this lookup. Their
// current root decisions and exact wire client addresses remain independent
// gates. The source map still comes from that original physical attachment.
func (sources *nativeNAT46StaticSources) sourceHandoffGroup(ctx context.Context, originals []nativePacketContext, directory bool) (string, map[string][]nativeScope, error) {
	if sources == nil || ctx == nil || len(originals) == 0 || len(originals) > int(ownershipRuleMask)+1 {
		return "", nil, errors.New("firewall: missing nat46 source context group")
	}
	ids := make([]uint64, 0, len(originals))
	for _, original := range originals {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if original.id > uint64(ownershipRuleMask) || original.family != 0 && original.family != 4 || original.iface != originals[0].iface {
			return "", nil, errors.New("firewall: invalid nat46 original source context group")
		}
		ids = append(ids, original.id)
	}
	slices.Sort(ids)
	if len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return "", nil, errors.New("firewall: duplicate nat46 original source context")
	}
	snapshot, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return "", nil, err
	}
	index, found := slices.BinarySearch(nat46StaticInterfaces(snapshot), originals[0].iface)
	if !found {
		return "", nil, errors.New("firewall: unreachable nat46 source-epoch geometry attachment")
	}
	suffix := "owner"
	kind := nativeTag(false, false)
	if directory {
		suffix = "directory"
		kind = nativeDirectoryTag(false)
	}
	name := fmt.Sprintf("native_n46_source_handoff_%d_%s", ids[0], suffix)
	marker := nativeMark(nativeTagMask, kind|ids[0])
	if len(ids) > 1 {
		text := strings.Builder{}
		for _, id := range ids {
			_, _ = fmt.Fprintf(&text, "%x,", id)
		}
		name = fmt.Sprintf("native_n46_source_group_%d_%s_%x", index, suffix, sha256.Sum256([]byte(text.String())))
		marker = nativeJoin(nativeMark(0xff000000, kind), nativeNAT46IDs(ids))
	}
	chains := map[string][]nativeScope{}
	epoch := nativeMatch("ct mark & 0xfffffc00 @"+ownershipEpochSet, guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+ownershipEpochSet)
	checks := nativeJoin(nativeMatch("ip6 saddr "+snapshot.Prefix.String(), guardPayload("ip6", "saddr"), controllerPrefix(snapshot.Prefix)), marker, nativeMark(uint64(nativeSourceMask), 0), nativeMatch("meta priority & 0x3ff == none", guardBinary("&", guardMeta("priority"), "0:3ff"), "none"), epoch)
	chains[name] = []nativeScope{
		nativeJoin(nativeMatch("ip6 saddr @"+classified6Set, guardPayload("ip6", "saddr"), "@"+classified6Set), nativeVerdict("drop", "")),
		nativeJoin(checks, nativeVerdict("goto", name+"_checked")), nativeVerdict("drop", ""),
	}
	chains[name+"_checked"] = []nativeScope{nativeVerdict("jump", "native_n46_same_epoch"), nativeJoin(nativeMangle(fmt.Sprintf("meta priority set @nh,160,32 map @native_n46_static_ids_%d", index), guardMeta("priority"), map[string]any{"map": map[string]any{"key": nativeRawPayload(160), "data": fmt.Sprintf("@native_n46_static_ids_%d", index)}}), nativeStampKind(nativeNAT46StaticSourceTag(directory, false)), nativeVerdict("goto", "native_n46_source_high")), nativeVerdict("drop", "")}
	for group := uint32(0); group < 8; group++ {
		parts := []nativeScope{nativeMatch(fmt.Sprintf("meta priority & 0x1c00 == %#x", group<<10), guardBinary("&", guardMeta("priority"), "0:1c00"), nativeLowHighClassID(group<<10)), nativeMangle("meta mark set meta mark & 0xffff1fff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xffff1fff)))}
		if group != 0 {
			parts = append(parts, nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", group<<13), guardMeta("mark"), guardBinary("|", guardMeta("mark"), group<<13)))
		}
		chains["native_n46_source_high"] = append(chains["native_n46_source_high"], nativeJoin(append(parts, nativeVerdict("goto", "native_n46_source_low"))...))
	}
	chains["native_n46_source_high"] = append(chains["native_n46_source_high"], nativeVerdict("drop", ""))
	key := map[string]any{"concat": []any{guardBinary("&", nativeCT("mark"), ownershipEpochMask), guardBinary("&", guardMeta("priority"), "0:3ff")}}
	chains["native_n46_source_low"] = []nativeScope{nativeJoin(epoch, nativeMangle("meta priority set (ct mark & 0xfffffc00) . (meta priority & 0x3ff) map @"+nativeNAT46StaticSourceChannel, guardMeta("priority"), map[string]any{"map": map[string]any{"key": key, "data": "@" + nativeNAT46StaticSourceChannel}}), nat46StaticSourceLive(), nativeVerdict("return", "")), nativeVerdict("drop", "")}
	return name, chains, ctx.Err()
}

// A source-epoch GID still identifies the actual static IPv4 client. Client
// NAS history closes this namespace; target NAS history is expected here and
// must instead have the independent current native-target ownership proof.
func nat46StaticSourcePhysical(reply bool) []nativeScope {
	_, epoch := epochChannelNames(false)
	family, client, set := "ip6", "saddr", nativeNAT46StaticBindings6
	text := "(meta mark & 0xe000) . (meta priority & 0x3ff) . ip6 saddr"
	key := []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload("ip6", "saddr")}
	history := classified6Set
	if reply {
		family, client, set, history = "ip", "daddr", nativeNAT46StaticReturn4, classified4Set
		key = []any{guardMeta("oifname"), guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload("ip", "daddr")}
		text = "oifname . (meta mark & 0xe000) . (meta priority & 0x3ff) . ip daddr"
	}
	checks := []nativeScope{nativeJoin(nativeMatch(family+" "+client+" @"+history, guardPayload(family, client), "@"+history), nativeVerdict("drop", ""))}
	for _, directory := range []bool{false, true} {
		checks = append(checks, nativeJoin(nativeMark(0xff000000, nativeNAT46StaticSourceTag(directory, reply)), nativePriorityEpoch(epoch), nat46StaticSourceLive(), nativeMatch(text+" @"+set, map[string]any{"concat": key}, "@"+set), nativeVerdict("return", "")))
	}
	return append(checks, nativeVerdict("drop", ""))
}

func nat46StaticSourceLive() nativeScope {
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("priority"), "ffff:fc00"), guardBinary("&", guardMeta("priority"), "0:3ff")}}
	return nativeMatch("(meta priority & 0xfffffc00) . (meta priority & 0x3ff) @"+nativeNAT46StaticSourceLive, key, "@"+nativeNAT46StaticSourceLive)
}

func nat46StaticSourceWirePhysical(reply bool) []nativeScope {
	if !reply {
		return nat46StaticSourcePhysical(false)
	}
	_, epoch := epochChannelNames(false)
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload("ip6", "daddr")}}
	rules := []nativeScope{nativeJoin(nativeMatch("ip6 daddr @"+classified6Set, guardPayload("ip6", "daddr"), "@"+classified6Set), nativeVerdict("drop", ""))}
	for _, directory := range []bool{false, true} {
		rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeNAT46StaticSourceTag(directory, true)), nativePriorityEpoch(epoch), nat46StaticSourceLive(), nativeMatch("(meta mark & 0xe000) . (meta priority & 0x3ff) . ip6 daddr @"+nativeNAT46StaticBindings6, key, "@"+nativeNAT46StaticBindings6), nativeVerdict("return", "")))
	}
	return append(rules, nativeVerdict("drop", ""))
}
