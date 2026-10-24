package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
)

// This checks an observation against the already checked logical grants and
// canonical source inventory. It can reject a writer result; it never creates
// a receipt, renews a timeout, or supplies data for a positive transaction.
func inspectNativeIDGrants(ctx context.Context, logical guardChanges, inet, netdev *guardTableObservation) (int, error) {
	epochs, err := listedGuardLeases(ctx, inet.sets[ownershipEpochSet].Elements)
	if err != nil {
		return 0, err
	}
	var base uint32
	var epochTimeout int
	ids := map[nativeSourceIP]uint32{}
	if len(epochs) > 0 {
		var epoch struct {
			Value   uint32 `json:"val"`
			Timeout int    `json:"timeout"`
		}
		if len(epochs) != 1 || decodeNested(epochs[0], "elem", &epoch, []string{"val", "timeout"}) != nil {
			return 0, errors.New("firewall: invalid source epoch for ID grant observation")
		}
		base = epoch.Value
		epochTimeout = epoch.Timeout
		rows, err := nativeSourceMapRows(ctx, inet.sets[nativeSourceIDs4].Elements, maximumCohortSize)
		if err != nil {
			return 0, err
		}
		for _, raw := range rows {
			var pair []json.RawMessage
			if json.Unmarshal(raw, &pair) != nil || len(pair) != 2 {
				return 0, errors.New("firewall: invalid ID grant source inventory")
			}
			var key nativeSourceTimed
			if decodeNested(pair[0], "elem", &key, []string{"val", "timeout"}) != nil || len(key.Value.Fields) != 4 {
				return 0, errors.New("firewall: invalid ID grant source key")
			}
			var epochKey uint32
			var iface, mac, address, class string
			if json.Unmarshal(key.Value.Fields[0], &epochKey) != nil || epochKey != base || json.Unmarshal(key.Value.Fields[1], &iface) != nil || json.Unmarshal(key.Value.Fields[2], &mac) != nil || json.Unmarshal(key.Value.Fields[3], &address) != nil || json.Unmarshal(pair[1], &class) != nil {
				return 0, errors.New("firewall: ID grant source inventory changed epoch or identity")
			}
			ip, err := netip.ParseAddr(address)
			if err != nil || !ip.Is4() {
				return 0, errors.New("firewall: ID grant observation requires original IPv4")
			}
			id, err := parseNativeClassID(class)
			if err != nil {
				return 0, err
			}
			identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: iface, mac: mac}, address: ip}
			if ids[identity] != 0 {
				return 0, errors.New("firewall: duplicate ID grant source observation")
			}
			ids[identity] = id
		}
	}
	owned, err := nativeIDOwnedDeadlines(ctx, inet)
	if err != nil {
		return 0, err
	}
	expected := map[string]map[string]int{}
	for _, ref := range nativeIDLeaseRefs() {
		expected[ref.Name] = map[string]int{}
	}
	if base != 0 {
		for _, command := range logical.Commands {
			if command.Add == nil {
				continue
			}
			element := command.Add.Element
			if element.Family != "inet" || element.Table != ownedTable || !isGrantSet(element.Name) || !ipv4Set(element.Name) {
				continue
			}
			for _, raw := range element.Values {
				if err := ctx.Err(); err != nil {
					return 0, err
				}
				tuple, err := validateLeasedTuple(raw, true)
				if err != nil {
					return 0, err
				}
				identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: tuple.interfaceName, mac: tuple.mac}, address: tuple.device}
				id := ids[identity]
				if id == 0 || owned[identity] == 0 {
					continue
				}
				key, err := nativeIDGrantKey(base, id, tuple.peer, tuple.port)
				if err != nil {
					return 0, err
				}
				var lease struct {
					Element struct {
						Timeout int `json:"timeout"`
					} `json:"elem"`
				}
				if err := json.Unmarshal(raw, &lease); err != nil {
					return 0, err
				}
				name := "native_id_" + element.Name
				timeout := min(lease.Element.Timeout, owned[identity], epochTimeout)
				expected[name][string(key)] = max(expected[name][string(key)], timeout)
			}
		}
	}
	count := 0
	for _, ref := range nativeIDLeaseRefs() {
		observation := netdev
		if ref.Family == "inet" {
			observation = inet
		}
		actual, err := listedGuardLeases(ctx, observation.sets[ref.Name].Elements)
		if err != nil {
			return 0, err
		}
		if len(actual) > maximumTupleCount {
			return 0, errors.New("firewall: ID grant observation exceeds capacity")
		}
		seen := map[string]bool{}
		for _, raw := range actual {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			var lease struct {
				Value   json.RawMessage `json:"val"`
				Timeout int             `json:"timeout"`
			}
			if err := decodeNested(raw, "elem", &lease, []string{"val", "timeout"}); err != nil {
				return 0, err
			}
			key, err := canonicalGuardJSON(lease.Value)
			if err != nil {
				return 0, err
			}
			identity := string(key)
			if seen[identity] || expected[ref.Name][identity] == 0 || lease.Timeout > expected[ref.Name][identity] {
				return 0, errors.New("firewall: ID grant lacks its current source epoch and full logical permission")
			}
			seen[identity] = true
			if ref.Family == "netdev" {
				count++
			}
		}
	}
	return count, ctx.Err()
}

// The per-address inventory deliberately survives individual expiry to keep
// IDs stable. It cannot substitute for that address's current ownership lease.
func nativeIDOwnedDeadlines(ctx context.Context, inet *guardTableObservation) (map[nativeSourceIP]int, error) {
	leases, err := listedGuardLeases(ctx, inet.sets[ownership4Set].Elements)
	if err != nil {
		return nil, err
	}
	if len(leases) > maximumCohortSize {
		return nil, errors.New("firewall: ID grant ownership observation exceeds capacity")
	}
	owned := map[nativeSourceIP]int{}
	for _, raw := range leases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var lease struct {
			Value struct {
				Fields []string `json:"concat"`
			} `json:"val"`
			Timeout int `json:"timeout"`
		}
		if decodeNested(raw, "elem", &lease, []string{"val", "timeout"}) != nil || len(lease.Value.Fields) != 3 {
			return nil, errors.New("firewall: malformed ID grant ownership observation")
		}
		fields := lease.Value.Fields
		address, err := netip.ParseAddr(fields[2])
		if err != nil || !address.Is4() {
			return nil, errors.New("firewall: ID grant ownership requires original IPv4")
		}
		identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: fields[0], mac: fields[1]}, address: address}
		if owned[identity] != 0 {
			return nil, errors.New("firewall: duplicate ID grant ownership observation")
		}
		owned[identity] = lease.Timeout
	}
	return owned, nil
}
