package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
)

const (
	nativeSourceIDs4       = "native_source_ids4"
	nativeSourceAddresses4 = "native_source_addresses4"
	nativeSourceIDs6       = "native_source_ids6"
	nativeSourceAddresses6 = "native_source_addresses6"
)

// Per-address identities distinguish clients on the same association in either
// family. Translation can recover the precise original client without
// repurposing an LSM security label or trusting a mutable address-only hint.
type nativeSourceIP struct {
	nativeSourceIdentity
	address netip.Addr
}

func compareNativeIP(left, right nativeSourceIP) int {
	if order := compareNativeSources(left.nativeSourceIdentity, right.nativeSourceIdentity); order != 0 {
		return order
	}
	return left.address.Compare(right.address)
}

func nativeSourceIsMap(ref objectReference) bool {
	return ref.Name == nativeSourceIDs || ref.Name == nativeSourceIDs4 || ref.Name == nativeSourceIDs6 || ref.Name == nativeSourceAddresses6 || ref.Name == nativeSourceChannel || ref.Name == nativeSourceAddresses4
}

func nativeIPInventory(ctx context.Context, inet *guardTableObservation, epoch uint32, timeout int, macIDs map[nativeSourceIdentity]uint32, isIPv4 bool) (map[nativeSourceIP]uint32, []uint32, error) {
	name := nativeSourceIDs6
	if isIPv4 {
		name = nativeSourceIDs4
	}
	rows, err := nativeSourceMapRows(ctx, inet.sets[name].Elements, maximumCohortSize)
	if err != nil {
		return nil, nil, err
	}
	ids := map[nativeSourceIP]uint32{}
	addresses := map[netip.Addr]bool{}
	identities := []nativeSourceIP{}
	for _, raw := range rows {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil {
			return nil, nil, err
		}
		var key nativeSourceTimed
		if err := decodeNested(pair[0], "elem", &key, []string{"val", "timeout"}); err != nil || len(key.Value.Fields) != 4 || key.Timeout != timeout {
			return nil, nil, errors.New("firewall: per-address inventory escaped its epoch deadline")
		}
		var base uint32
		var iface, mac, address, class string
		if json.Unmarshal(key.Value.Fields[0], &base) != nil || json.Unmarshal(key.Value.Fields[1], &iface) != nil || json.Unmarshal(key.Value.Fields[2], &mac) != nil || json.Unmarshal(key.Value.Fields[3], &address) != nil || json.Unmarshal(pair[1], &class) != nil {
			return nil, nil, errors.New("firewall: malformed per-address source inventory")
		}
		ip, parseErr := netip.ParseAddr(address)
		id, idErr := parseNativeClassID(class)
		identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: iface, mac: mac}, address: ip}
		if parseErr != nil || ip.Is4() != isIPv4 || ip.Is4In6() || ip.Zone() != "" || ip.String() != address || !ip.IsGlobalUnicast() || base != epoch || idErr != nil || id == 0 || id > maximumCohortSize || macIDs[identity.nativeSourceIdentity] == 0 || ids[identity] != 0 || addresses[ip] {
			return nil, nil, errors.New("firewall: ambiguous per-address source inventory identity")
		}
		ids[identity], addresses[ip] = id, true
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, compareNativeIP)
	lows := make([]uint32, 0, len(identities))
	for index, identity := range identities {
		if ids[identity] != uint32(index+1) {
			return nil, nil, errors.New("firewall: per-address source IDs changed their canonical order")
		} // #nosec G115 -- fixed inventory holds at most 4096 entries.
		lows = append(lows, ids[identity]&ownershipRuleMask)
	}
	return ids, lows, ctx.Err()
}
