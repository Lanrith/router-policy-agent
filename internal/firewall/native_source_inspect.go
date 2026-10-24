package firewall

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

type nativeSourceTimed struct {
	Value struct {
		Fields []json.RawMessage `json:"concat"`
	} `json:"val"`
	Timeout int `json:"timeout"`
}

func parseNativeClassID(value string) (uint32, error) {
	if value == "none" {
		return 0, nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[1]) < 1 || len(parts[0]) > 4 || len(parts[1]) > 4 {
		return 0, errors.New("firewall: invalid native source class identifier")
	}
	high, first := strconv.ParseUint(parts[0], 16, 16)
	low, second := strconv.ParseUint(parts[1], 16, 16)
	if first != nil || second != nil {
		return 0, errors.New("firewall: malformed native source class identifier")
	}
	result := uint32(high)<<16 | uint32(low) // #nosec G115 -- both halves are bounded to 16 bits by ParseUint.
	if result == 0 || epochClassID(result) != value {
		return 0, errors.New("firewall: noncanonical native source class identifier")
	}
	return result, nil
}

func nativeSourceSchema(schema *guardTableSchema, family string) {
	// The translated physical check reads the same 32 bits at IPv6 offset 160.
	// typeof fixes the raw datatype, while each predicate pins its own offset.
	rawType := map[string]any{"typeof": map[string]any{"concat": []any{guardMeta("mark"), guardMeta("priority"),
		map[string]any{"payload": map[string]any{"base": "nh", "offset": 96, "len": 32}}}}}
	rawHeader := guardSetHeader(family, nativeSourceBits4, rawType, maximumTupleCount)
	rawHeader["flags"], rawHeader["timeout"] = []string{"timeout"}, 90
	schema.sets[nativeSourceBits4] = rawHeader
	if family == "inet" {
		schema.sets[nativeSource4] = guardLeaseHeader(family, nativeSource4, []string{"mark", "classid", "ipv4_addr"})
		schema.sets[nativeSource6] = guardLeaseHeader(family, nativeSource6, []string{"mark", "classid", "ipv6_addr"})
		schema.sets[nativeSourceLive4] = guardLeaseHeader(family, nativeSourceLive4, []string{"mark", "classid"})
		schema.sets[nativeSourceLive6] = guardLeaseHeader(family, nativeSourceLive6, []string{"mark", "classid"})
		for _, item := range []struct {
			name string
			keys []string
			size int
		}{{nativeSourceIDs, []string{"mark", "ifname", "ether_addr"}, maximumCohortSize},
			{nativeSourceIDs4, []string{"mark", "ifname", "ether_addr", "ipv4_addr"}, maximumCohortSize},
			{nativeSourceIDs6, []string{"mark", "ifname", "ether_addr", "ipv6_addr"}, maximumCohortSize},
			{nativeSourceChannel, []string{"mark", "classid"}, 1024}} {
			header := guardSetHeader(family, item.name, item.keys, item.size)
			header["map"], header["flags"], header["timeout"] = "classid", []string{"timeout"}, 90
			schema.maps[item.name] = header
		}
	} else {
		schema.sets[nativeSourceEpoch6] = guardLeaseHeader(family, nativeSourceEpoch6, []string{"classid", "ipv6_addr"})
		for _, item := range []struct{ inverse, live, address string }{
			{nativeSourceAddresses4, nativeSourceLive4, "ipv4_addr"},
			{nativeSourceAddresses6, nativeSourceLive6, "ipv6_addr"},
		} {
			schema.sets[item.live] = guardLeaseHeader(family, item.live, []string{"mark", "classid"})
			header := guardSetHeader(family, item.inverse, []string{"mark", "classid"}, maximumCohortSize)
			header["map"], header["flags"], header["timeout"] = item.address, []string{"timeout"}, 90
			schema.maps[item.inverse] = header
		}
		for _, item := range []struct{ name, address string }{{classified4Set, "ipv4_addr"}, {classified6Set, "ipv6_addr"}} {
			schema.sets[item.name] = guardSetHeader(family, item.name, item.address, maximumTupleCount)
		}
		for _, item := range []struct{ name, address string }{{nativeSource4, "ipv4_addr"}, {nativeSource6, "ipv6_addr"}} {
			schema.sets[item.name] = guardLeaseHeader(family, item.name, []string{"mark", "classid", item.address})
		}
	}
}

func nativeSourceMapRows(ctx context.Context, raw []json.RawMessage, capacity int) ([]json.RawMessage, error) {
	if len(raw) > capacity {
		return nil, errors.New("firewall: native source map capacity exceeded")
	}
	result := make([]json.RawMessage, 0, len(raw))
	for _, row := range raw {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var pair []json.RawMessage
		if err := json.Unmarshal(row, &pair); err != nil || len(pair) != 2 {
			return nil, errors.New("firewall: invalid native source map pair")
		}
		keys, err := listedGuardLeases(ctx, pair[:1])
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal([]json.RawMessage{keys[0], pair[1]})
		if err != nil {
			return nil, errors.New("firewall: native source map normalization failed")
		}
		result = append(result, encoded)
	}
	return result, nil
}

// inspectNativeSources checks relationships only. An observed inventory or
// channel can never be used as a source proof or renew a positive deadline.
func (layout *guardLayout) inspectNativeSources(ctx context.Context, inet, netdev *guardTableObservation) error {
	epochs, err := listedGuardLeases(ctx, inet.sets[ownershipEpochSet].Elements)
	if err != nil {
		return err
	}
	if len(epochs) == 0 {
		for _, ref := range nativeSourceReferences() {
			observation := inet
			if ref.Family == "netdev" {
				observation = netdev
			}
			if len(observation.sets[ref.Name].Elements) != 0 {
				return errors.New("firewall: native source metadata lacks its ownership epoch")
			}
		}
		return ctx.Err()
	}
	var epoch struct {
		Value   uint32 `json:"val"`
		Timeout int    `json:"timeout"`
	}
	if len(epochs) != 1 || decodeNested(epochs[0], "elem", &epoch, []string{"val", "timeout"}) != nil ||
		epoch.Value == 0 || epoch.Value&ownershipRuleMask != 0 || epoch.Value>>policy.OwnershipRuleBits > policy.MaximumOwnershipEpoch {
		return errors.New("firewall: native source epoch observation differs")
	}
	rows, err := nativeSourceMapRows(ctx, inet.sets[nativeSourceIDs].Elements, maximumCohortSize)
	if err != nil {
		return err
	}
	ids := map[nativeSourceIdentity]uint32{}
	macs := map[string]bool{}
	identities := []nativeSourceIdentity{}
	for _, raw := range rows {
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil {
			return err
		}
		var key nativeSourceTimed
		if err := decodeNested(pair[0], "elem", &key, []string{"val", "timeout"}); err != nil || len(key.Value.Fields) != 3 || key.Timeout != epoch.Timeout {
			return errors.New("firewall: native source inventory escaped its epoch deadline")
		}
		var base uint32
		var iface, mac, class string
		if json.Unmarshal(key.Value.Fields[0], &base) != nil || json.Unmarshal(key.Value.Fields[1], &iface) != nil ||
			json.Unmarshal(key.Value.Fields[2], &mac) != nil || json.Unmarshal(pair[1], &class) != nil {
			return errors.New("firewall: malformed native source inventory identity")
		}
		id, parseErr := parseNativeClassID(class)
		canonical, macErr := policy.CanonicalMAC(mac)
		if parseErr != nil || macErr != nil || canonical != mac || base != epoch.Value || id == 0 || id > maximumCohortSize ||
			!slices.Contains(layout.managedInterfaces, iface) || macs[mac] {
			return errors.New("firewall: ambiguous native source inventory identity")
		}
		identity := nativeSourceIdentity{iface: iface, mac: mac}
		ids[identity], macs[mac] = id, true
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, compareNativeSources)
	lows := []uint32{}
	for index, identity := range identities {
		if ids[identity] != uint32(index+1) { // #nosec G115 -- the inventory is bounded to 4096 entries.
			return errors.New("firewall: native source inventory IDs changed their canonical order")
		}
		lows = append(lows, ids[identity]&ownershipRuleMask)
	}
	addressIDs := map[nativeSourceIP]uint32{}
	for _, isIPv4 := range []bool{true, false} {
		familyIDs, familyLows, err := nativeIPInventory(ctx, inet, epoch.Value, epoch.Timeout, ids, isIPv4)
		if err != nil {
			return err
		}
		for address, id := range familyIDs {
			addressIDs[address] = id
		}
		lows = append(lows, familyLows...)
	}
	slices.Sort(lows)
	lows = slices.Compact(lows)
	expected := []json.RawMessage{}
	for _, low := range lows {
		row, err := json.Marshal([]any{nativeTimedValue(map[string]any{"concat": []any{epoch.Value, nativeLowClassID(low)}}, epoch.Timeout), epochClassID(epoch.Value | low)})
		if err != nil {
			return err
		}
		expected = append(expected, row)
	}
	actual, err := nativeSourceMapRows(ctx, inet.sets[nativeSourceChannel].Elements, 1024)
	if err != nil {
		return err
	}
	if err := sameGuardElements(ctx, actual, expected); err != nil {
		return err
	}
	seenAddresses := map[string]bool{}
	for _, family := range []struct{ original, output, inverse, live string }{
		{ownership4Set, nativeSource4, nativeSourceAddresses4, nativeSourceLive4},
		{ownership6Set, nativeSource6, nativeSourceAddresses6, nativeSourceLive6},
	} {
		bindings, err := listedGuardLeases(ctx, inet.sets[family.original].Elements)
		if err != nil {
			return err
		}
		expected := []json.RawMessage{}
		addresses := []json.RawMessage{}
		live := []json.RawMessage{}
		raw4 := []json.RawMessage{}
		epoch6 := []json.RawMessage{}
		for _, raw := range bindings {
			var binding struct {
				Value struct {
					Fields []string `json:"concat"`
				} `json:"val"`
				Timeout int `json:"timeout"`
			}
			if err := decodeNested(raw, "elem", &binding, []string{"val", "timeout"}); err != nil || len(binding.Value.Fields) != 3 {
				return errors.New("firewall: invalid native source ownership observation")
			}
			fields := binding.Value.Fields
			if seenAddresses[fields[2]] {
				return errors.New("firewall: ambiguous physical source address ownership")
			}
			seenAddresses[fields[2]] = true
			address, err := netip.ParseAddr(fields[2])
			if err != nil || address.Is4In6() || address.Zone() != "" || address.Is4() != (family.output == nativeSource4) {
				return errors.New("firewall: source ownership changed address family")
			}
			id := addressIDs[nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: fields[0], mac: fields[1]}, address: address}]
			if id == 0 {
				return errors.New("firewall: source ownership lacks its epoch-scoped identity")
			}
			identityKey := map[string]any{"concat": []any{(id >> 10) << 13, nativeLowClassID(id)}}
			inverse, err := json.Marshal([]any{nativeTimedValue(identityKey, min(binding.Timeout, epoch.Timeout)), fields[2]})
			if err != nil {
				return err
			}
			addresses = append(addresses, inverse)
			liveRow, err := json.Marshal(nativeTimedValue(identityKey, min(binding.Timeout, epoch.Timeout)))
			if err != nil {
				return err
			}
			live = append(live, liveRow)
			key := map[string]any{"concat": []any{(id >> 10) << 13, nativeLowClassID(id), fields[2]}}
			row, err := json.Marshal(nativeTimedValue(key, min(binding.Timeout, epoch.Timeout)))
			if err != nil {
				return err
			}
			expected = append(expected, row)
			if family.output == nativeSource4 {
				bits := address.As4()
				key := map[string]any{"concat": []any{(id >> 10) << 13, nativeLowClassID(id), binary.BigEndian.Uint32(bits[:])}}
				row, err := json.Marshal(nativeTimedValue(key, min(binding.Timeout, epoch.Timeout)))
				if err != nil {
					return err
				}
				raw4 = append(raw4, row)
			} else {
				key := map[string]any{"concat": []any{epochClassID(epoch.Value), fields[2]}}
				row, err := json.Marshal(nativeTimedValue(key, min(binding.Timeout, epoch.Timeout)))
				if err != nil {
					return err
				}
				epoch6 = append(epoch6, row)
			}
		}
		actual, err := listedGuardLeases(ctx, netdev.sets[family.output].Elements)
		if err != nil {
			return err
		}
		if err := sameGuardElements(ctx, actual, expected); err != nil {
			return err
		}
		beforeNAT, err := listedGuardLeases(ctx, inet.sets[family.output].Elements)
		if err != nil {
			return err
		}
		if err := sameGuardElements(ctx, beforeNAT, expected); err != nil {
			return err
		}
		if family.output == nativeSource4 {
			for _, observation := range []*guardTableObservation{inet, netdev} {
				actual, err := listedGuardLeases(ctx, observation.sets[nativeSourceBits4].Elements)
				if err != nil {
					return err
				}
				if err := sameGuardElements(ctx, actual, raw4); err != nil {
					return err
				}
			}
		} else {
			actual, err := listedGuardLeases(ctx, netdev.sets[nativeSourceEpoch6].Elements)
			if err != nil {
				return err
			}
			if err := sameGuardElements(ctx, actual, epoch6); err != nil {
				return err
			}
		}
		for _, observation := range []*guardTableObservation{inet, netdev} {
			actualLive, err := listedGuardLeases(ctx, observation.sets[family.live].Elements)
			if err != nil {
				return err
			}
			if err := sameGuardElements(ctx, actualLive, live); err != nil {
				return err
			}
		}
		actualAddresses, err := nativeSourceMapRows(ctx, netdev.sets[family.inverse].Elements, maximumCohortSize)
		if err != nil {
			return err
		}
		if err := sameGuardElements(ctx, actualAddresses, addresses); err != nil {
			return err
		}
	}
	return ctx.Err()
}
