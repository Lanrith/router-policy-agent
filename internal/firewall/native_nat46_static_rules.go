package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	nativeNAT46StaticBits4     = "native_n46_static_bits4"
	nativeNAT46StaticBindings6 = "native_n46_static_bindings6"
	nativeNAT46StaticReturn4   = "native_n46_static_return4"
)

// F3/F4 are separate from NAS IDs and the legacy C1/C2 translator tags.
func nativeNAT46StaticTag(reply bool) uint64 {
	if reply {
		return 0xf4000000
	}
	return 0xf3000000
}

func nat46StaticInterfaces(snapshot policy.NAT46StaticGeometrySnapshot) []string {
	names := []string{}
	for _, source := range snapshot.Sources {
		names = append(names, source.Interface)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func nat46StaticElements(rows []string) string {
	if len(rows) == 0 {
		return ""
	}
	return "elements={" + strings.Join(rows, ",") + "};"
}

func (sources *nativeNAT46StaticSources) definitions(ctx context.Context, family string) ([]string, error) {
	if sources == nil || ctx == nil {
		return nil, errors.New("firewall: missing static nat46 definitions")
	}
	snapshot, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if family != "inet" && family != "netdev" {
		return nil, errors.New("firewall: unsupported static nat46 family")
	}
	names := nat46StaticInterfaces(snapshot)
	result := []string{}
	if family == "inet" {
		result = append(result, "map "+nativeNAT46StaticChannel+" {type mark . classid : classid;size 1024;}")
		for index, name := range names {
			rows := []string{}
			for _, source := range snapshot.Sources {
				if source.Interface == name {
					bits := source.Original.As4()
					rows = append(rows, fmt.Sprintf("%#x : %s", binary.BigEndian.Uint32(bits[:]), epochClassID(source.ID)))
				}
			}
			result = append(result, fmt.Sprintf("map native_n46_static_ids_%d {typeof @nh,96,32 : meta priority;size %d;elements={%s};}", index, policy.MaximumNAT46StaticSources, strings.Join(rows, ",")))
		}
	}
	embedded, raw, returned := []string{}, []string{}, []string{}
	for _, source := range snapshot.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		high, low := (source.ID>>10)<<13, nativeLowClassID(source.ID)
		bits := source.Original.As4()
		raw = append(raw, fmt.Sprintf("%#x . %s . %#x", high, low, binary.BigEndian.Uint32(bits[:])))
		embedded = append(embedded, fmt.Sprintf("%#x . %s . %s", high, low, source.Embedded))
		returned = append(returned, fmt.Sprintf("%q . %#x . %s . %s", source.Interface, high, low, source.Original))
	}
	result = append(result, fmt.Sprintf("set %s {type mark . classid . ipv6_addr;size %d;%s}", nativeNAT46StaticBindings6, policy.MaximumNAT46StaticSources, nat46StaticElements(embedded)))
	if family == "inet" {
		result = append(result, fmt.Sprintf("set %s {typeof meta mark . meta priority . @nh,96,32;size %d;%s}", nativeNAT46StaticBits4, policy.MaximumNAT46StaticSources, nat46StaticElements(raw)))
	} else {
		result = append(result, fmt.Sprintf("set %s {type ifname . mark . classid . ipv4_addr;size %d;%s}", nativeNAT46StaticReturn4, policy.MaximumNAT46StaticSources, nat46StaticElements(returned)))
	}
	return result, ctx.Err()
}

// handoff consumes an already admitted original metadata snapshot. It changes
// only the translated packet, leaving the original raw/TUN physical checks
// and their NAS namespace intact. It supplies no forwarding verdict or grant.
func (sources *nativeNAT46StaticSources) handoff(ctx context.Context, packetContext nativePacketContext) (map[string][]nativeScope, error) {
	_, chains, err := sources.handoffGroup(ctx, []nativePacketContext{packetContext})
	return chains, err
}

// Identical original attachments may share only the static lookup. Every
// caller retains its own context/mapping, current epoch and permission checks.
func (sources *nativeNAT46StaticSources) handoffGroup(ctx context.Context, originals []nativePacketContext) (string, map[string][]nativeScope, error) {
	if sources == nil || ctx == nil || len(originals) == 0 || len(originals) > int(ownershipRuleMask)+1 {
		return "", nil, errors.New("firewall: missing static nat46 packet context")
	}
	packetContext := originals[0]
	ids := make([]uint64, 0, len(originals))
	for _, original := range originals {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if original.id > uint64(ownershipRuleMask) || original.iface != packetContext.iface || original.family != 0 && original.family != 4 {
			return "", nil, errors.New("firewall: invalid static nat46 context group")
		}
		ids = append(ids, original.id)
	}
	slices.Sort(ids)
	if len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return "", nil, errors.New("firewall: repeated static nat46 context")
	}
	snapshot, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return "", nil, err
	}
	names := nat46StaticInterfaces(snapshot)
	index, found := slices.BinarySearch(names, packetContext.iface)
	if !found {
		return "", nil, errors.New("firewall: static nat46 source attachment is unreachable")
	}
	name := fmt.Sprintf("native_n46_static_handoff_%d", ids[0])
	marker := nativeMark(nativeTagMask, nativeTag(true, false)|ids[0])
	if len(ids) > 1 {
		marker = nativeJoin(nativeMark(0xff000000, nativeTag(true, false)), nativeNAT46IDs(ids))
	}
	chains := map[string][]nativeScope{}
	checks := nativeJoin(nativeMatch("ip6 saddr "+snapshot.Prefix.String(), guardPayload("ip6", "saddr"), controllerPrefix(snapshot.Prefix)), marker, nativeMark(uint64(nativeSourceMask), 0), nativeMatch("meta priority & 0x3ff == none", guardBinary("&", guardMeta("priority"), "0:3ff"), "none"), nativeMatch("ct mark & 0xfffffc00 @"+configurationEpochSet, guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+configurationEpochSet))
	chains[name] = append(chains[name], nativeNAT46StaticHistory("ip6", "saddr", "daddr")...)
	chains[name] = append(chains[name], nativeJoin(checks, nativeVerdict("goto", name+"_checked")), nativeVerdict("drop", ""))
	chains[name+"_checked"] = []nativeScope{nativeVerdict("jump", "native_n46_same_epoch"), nativeJoin(nativeMangle(fmt.Sprintf("meta priority set @nh,160,32 map @native_n46_static_ids_%d", index), guardMeta("priority"), map[string]any{"map": map[string]any{"key": nativeRawPayload(160), "data": fmt.Sprintf("@native_n46_static_ids_%d", index)}}), nativeStampKind(nativeNAT46StaticTag(false)), nativeVerdict("goto", "native_n46_static_high")), nativeVerdict("drop", "")}
	for group := uint32(0); group < 8; group++ {
		parts := []nativeScope{nativeMatch(fmt.Sprintf("meta priority & 0x1c00 == %#x", group<<10), guardBinary("&", guardMeta("priority"), "0:1c00"), nativeLowHighClassID(group<<10)), nativeMangle("meta mark set meta mark & 0xffff1fff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xffff1fff)))}
		if group != 0 {
			parts = append(parts, nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", group<<13), guardMeta("mark"), guardBinary("|", guardMeta("mark"), group<<13)))
		}
		chains["native_n46_static_high"] = append(chains["native_n46_static_high"], nativeJoin(append(parts, nativeVerdict("goto", "native_n46_static_low"))...))
	}
	chains["native_n46_static_high"] = append(chains["native_n46_static_high"], nativeVerdict("drop", ""))
	key := map[string]any{"concat": []any{guardBinary("&", nativeCT("mark"), ownershipEpochMask), guardBinary("&", guardMeta("priority"), "0:3ff")}}
	chains["native_n46_static_low"] = []nativeScope{nativeJoin(nativeMatch("ct mark & 0xfffffc00 @"+configurationEpochSet, guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+configurationEpochSet), nativeMangle("meta priority set (ct mark & 0xfffffc00) . (meta priority & 0x3ff) map @"+nativeNAT46StaticChannel, guardMeta("priority"), map[string]any{"map": map[string]any{"key": key, "data": "@" + nativeNAT46StaticChannel}}), nativeVerdict("return", "")), nativeVerdict("drop", "")}
	return name, chains, ctx.Err()
}

// These are identity fact checks. The caller must also enforce its current
// ordered permission, exact mapped peer/listener and required target ownership.
func nat46StaticPhysical(reply bool) []nativeScope {
	_, epoch := epochChannelNames(true)
	kind := nativeNAT46StaticTag(reply)
	key := []any{guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload("ip6", "saddr")}
	text := "(meta mark & 0xe000) . (meta priority & 0x3ff) . ip6 saddr"
	set := nativeNAT46StaticBindings6
	if reply {
		key = []any{guardMeta("oifname"), guardBinary("&", guardMeta("mark"), nativeSourceMask), guardBinary("&", guardMeta("priority"), "0:3ff"), guardPayload("ip", "daddr")}
		text = "oifname . (meta mark & 0xe000) . (meta priority & 0x3ff) . ip daddr"
		set = nativeNAT46StaticReturn4
	}
	family, client, target := "ip6", "saddr", "daddr"
	if reply {
		family, client, target = "ip", "daddr", "saddr"
	}
	checks := nativeNAT46StaticHistory(family, client, target)
	return append(checks, nativeJoin(nativeMark(0xff000000, kind), nativePriorityEpoch(epoch), nativeMatch(text+" @"+set, map[string]any{"concat": key}, "@"+set), nativeVerdict("return", "")), nativeVerdict("drop", ""))
}

// Configuration-epoch geometry must never stand in for current NAS identity.
// The owned model projects real and translated counterparts into these same
// permanent deny-only sets. NAS targets require their separate source-epoch
// namespace even when their IPv4 alias hides the native IPv6 attachment.
func nativeNAT46StaticHistory(family, client, target string) []nativeScope {
	set := classified6Set
	if family == "ip" {
		set = classified4Set
	}
	return []nativeScope{
		nativeJoin(nativeMatch(family+" "+client+" @"+set, guardPayload(family, client), "@"+set), nativeVerdict("drop", "")),
		nativeJoin(nativeMatch(family+" "+target+" @"+set, guardPayload(family, target), "@"+set), nativeVerdict("drop", "")),
	}
}
