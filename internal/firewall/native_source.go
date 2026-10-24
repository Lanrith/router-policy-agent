package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	nativeSourceIDs     = "native_source_ids"
	nativeSourceChannel = "native_source_epoch_channel"
	nativeSource4       = "native_source_bindings4"
	nativeSource6       = "native_source_bindings6"
	nativeSourceLive4   = "native_source_live4"
	nativeSourceLive6   = "native_source_live6"
	nativeSourceBits4   = "native_source_bits4"
	nativeSourceEpoch6  = "native_source_epoch6"
	nativeSourceMask    = uint32(7 << 13)
)

// Native metadata belongs only to the separate, inspected native layout.
// Publication requires the immutable ownership proof and typed writer fence.
func nativeSourceDefinitions(family string) []string {
	if family == "inet" {
		return []string{
			fmt.Sprintf("map %s { type mark . ifname . ether_addr : classid; flags timeout; timeout 90s; size %d; }", nativeSourceIDs, maximumCohortSize),
			fmt.Sprintf("map %s { type mark . ifname . ether_addr . ipv4_addr : classid; flags timeout; timeout 90s; size %d; }", nativeSourceIDs4, maximumCohortSize),
			fmt.Sprintf("map %s { type mark . ifname . ether_addr . ipv6_addr : classid; flags timeout; timeout 90s; size %d; }", nativeSourceIDs6, maximumCohortSize),
			fmt.Sprintf("map %s { type mark . classid : classid; flags timeout; timeout 90s; size 1024; }", nativeSourceChannel),
			guardSetDefinition(nativeSource4, "mark . classid . ipv4_addr"),
			guardSetDefinition(nativeSource6, "mark . classid . ipv6_addr"),
			guardSetDefinition(nativeSourceLive4, "mark . classid"),
			guardSetDefinition(nativeSourceLive6, "mark . classid"),
			fmt.Sprintf("set %s { typeof meta mark . meta priority . @nh,96,32; flags timeout; timeout 90s; size %d; }", nativeSourceBits4, maximumTupleCount),
		}
	}
	if family == "netdev" {
		return []string{fmt.Sprintf("map %s { type mark . classid : ipv4_addr; flags timeout; timeout 90s; size %d; }", nativeSourceAddresses4, maximumCohortSize),
			guardSetDefinition(nativeSourceEpoch6, "classid . ipv6_addr"),
			fmt.Sprintf("map %s { type mark . classid : ipv6_addr; flags timeout; timeout 90s; size %d; }", nativeSourceAddresses6, maximumCohortSize),
			fmt.Sprintf("set %s { typeof meta mark . meta priority . @nh,96,32; flags timeout; timeout 90s; size %d; }", nativeSourceBits4, maximumTupleCount),
			guardSetDefinition(nativeSource4, "mark . classid . ipv4_addr"),
			guardSetDefinition(nativeSourceLive4, "mark . classid"),
			guardSetDefinition(nativeSourceLive6, "mark . classid"),
			guardSetDefinition(nativeSource6, "mark . classid . ipv6_addr")}
	}
	return nil
}

func nativeSourceReferences() []objectReference {
	return []objectReference{
		{Family: "inet", Table: ownedTable, Name: nativeSourceIDs},
		{Family: "inet", Table: ownedTable, Name: nativeSourceIDs4},
		{Family: "inet", Table: ownedTable, Name: nativeSourceIDs6},
		{Family: "netdev", Table: ownedTable, Name: nativeSourceAddresses4},
		{Family: "netdev", Table: ownedTable, Name: nativeSourceAddresses6},
		{Family: "inet", Table: ownedTable, Name: nativeSourceChannel},
		{Family: "inet", Table: ownedTable, Name: nativeSource4},
		{Family: "inet", Table: ownedTable, Name: nativeSource6},
		{Family: "inet", Table: ownedTable, Name: nativeSourceBits4},
		{Family: "inet", Table: ownedTable, Name: nativeSourceLive4},
		{Family: "inet", Table: ownedTable, Name: nativeSourceLive6},
		{Family: "netdev", Table: ownedTable, Name: nativeSourceBits4},
		{Family: "netdev", Table: ownedTable, Name: nativeSource4},
		{Family: "netdev", Table: ownedTable, Name: nativeSourceLive4},
		{Family: "netdev", Table: ownedTable, Name: nativeSourceLive6},
		{Family: "netdev", Table: ownedTable, Name: nativeSource6},
		{Family: "netdev", Table: ownedTable, Name: nativeSourceEpoch6},
	}
}

func nativeLowClassID(id uint32) string {
	if id&ownershipRuleMask == 0 {
		return "none"
	}
	return fmt.Sprintf("0:%x", id&ownershipRuleMask)
}

type nativeSourceIdentity struct {
	iface, mac string
}

// nativeSourceChanges derives metadata only; it supplies no directory grant
// or packet verdict. The inventory lives for the original epoch deadline so
// IDs do not shift when an individual IP expires. Actual IP bindings keep the
// shorter original address deadline. Prepared application must rederive this
// from the helper-local Ownership proof, never from a diagnostic snapshot.
func nativeSourceChanges(ctx context.Context, snapshot policy.OwnershipSnapshot, timeouts []int, epochTimeout int) ([]any, error) {
	if ctx == nil || len(snapshot.Addresses) != len(timeouts) || len(timeouts) > maximumTupleCount {
		return nil, errors.New("firewall: invalid native source metadata dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operations := make([]any, 0, len(nativeSourceReferences()))
	for _, ref := range nativeSourceReferences() {
		kind := "set"
		if nativeSourceIsMap(ref) {
			kind = "map"
		}
		operations = append(operations, map[string]any{"flush": map[string]any{kind: ref}})
	}
	if snapshot.Epoch == 0 && epochTimeout == 0 && len(timeouts) == 0 {
		return operations, nil
	}
	if snapshot.Epoch == 0 || snapshot.Epoch > policy.MaximumOwnershipEpoch || epochTimeout < 1 || epochTimeout > maximumElementLifetime {
		return nil, errors.New("firewall: invalid native source epoch or deadline")
	}
	identities := []nativeSourceIdentity{}
	seen := map[nativeSourceIdentity]bool{}
	addresses := map[netip.Addr]bool{}
	macs := map[string]string{}
	for index, address := range snapshot.Addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		canonical, err := policy.CanonicalMAC(address.MAC)
		otherInterface, knownMAC := macs[address.MAC]
		if err != nil || canonical != address.MAC || !interfaceName.MatchString(address.Interface) ||
			knownMAC && otherInterface != address.Interface || !address.Address.IsGlobalUnicast() ||
			address.Address.Is4In6() || address.Address.Zone() != "" || addresses[address.Address] ||
			timeouts[index] < 1 || timeouts[index] > maximumElementLifetime {
			return nil, errors.New("firewall: ambiguous native source identity or lifetime")
		}
		addresses[address.Address], macs[address.MAC] = true, address.Interface
		identity := nativeSourceIdentity{iface: address.Interface, mac: address.MAC}
		if !seen[identity] {
			seen[identity] = true
			identities = append(identities, identity)
		}
	}
	if len(identities) > maximumCohortSize {
		return nil, errors.New("firewall: native source identity capacity exceeded")
	}
	slices.SortFunc(identities, compareNativeSources)
	base := snapshot.Epoch << policy.OwnershipRuleBits
	values := map[string][]any{}
	lows := []uint32{}
	for index, identity := range identities {
		id := uint32(index + 1) // #nosec G115 -- at most 4096 qualified MAC identities; zero is reserved.
		lows = append(lows, id&ownershipRuleMask)
		key := map[string]any{"concat": []any{base, identity.iface, identity.mac}}
		values[nativeSourceIDs] = append(values[nativeSourceIDs], []any{
			nativeTimedValue(key, epochTimeout), epochClassID(id),
		})
	}

	addressIDs := map[nativeSourceIP]uint32{}
	for _, family := range []struct {
		isIPv4 bool
		name   string
	}{{true, nativeSourceIDs4}, {false, nativeSourceIDs6}} {
		inventory := []nativeSourceIP{}
		for _, address := range snapshot.Addresses {
			if address.Address.Is4() == family.isIPv4 {
				inventory = append(inventory, nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address})
			}
		}
		if len(inventory) > maximumCohortSize {
			return nil, errors.New("firewall: per-address source identity capacity exceeded")
		}
		slices.SortFunc(inventory, compareNativeIP)
		for index, identity := range inventory {
			id := uint32(index + 1) // #nosec G115 -- each family's inventory is bounded to 4096; zero is reserved.
			addressIDs[identity] = id
			lows = append(lows, id&ownershipRuleMask)
			key := map[string]any{"concat": []any{base, identity.iface, identity.mac, identity.address.String()}}
			values[family.name] = append(values[family.name], []any{nativeTimedValue(key, epochTimeout), epochClassID(id)})
		}
	}
	slices.Sort(lows)
	lows = slices.Compact(lows)
	for _, low := range lows {
		key := map[string]any{"concat": []any{base, nativeLowClassID(low)}}
		values[nativeSourceChannel] = append(values[nativeSourceChannel], []any{
			nativeTimedValue(key, epochTimeout), epochClassID(base | low),
		})
	}
	for index, address := range snapshot.Addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := addressIDs[nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}]
		name, inverse, live := nativeSource6, nativeSourceAddresses6, nativeSourceLive6
		if address.Address.Is4() {
			name, inverse, live = nativeSource4, nativeSourceAddresses4, nativeSourceLive4
			raw := address.Address.As4()
			key := map[string]any{"concat": []any{(id >> 10) << 13, nativeLowClassID(id), binary.BigEndian.Uint32(raw[:])}}
			values[nativeSourceBits4] = append(values[nativeSourceBits4], nativeTimedValue(key, min(timeouts[index], epochTimeout)))
		} else {
			key := map[string]any{"concat": []any{epochClassID(base), address.Address.String()}}
			values[nativeSourceEpoch6] = append(values[nativeSourceEpoch6], nativeTimedValue(key, min(timeouts[index], epochTimeout)))
		}
		identityKey := map[string]any{"concat": []any{(id >> 10) << 13, nativeLowClassID(id)}}
		values[inverse] = append(values[inverse], []any{nativeTimedValue(identityKey, min(timeouts[index], epochTimeout)), address.Address.String()})
		values[live] = append(values[live], nativeTimedValue(identityKey, min(timeouts[index], epochTimeout)))
		key := map[string]any{"concat": []any{(id >> 10) << 13, nativeLowClassID(id), address.Address.String()}}
		values[name] = append(values[name], nativeTimedValue(key, min(timeouts[index], epochTimeout)))
	}
	for _, ref := range nativeSourceReferences() {
		if len(values[ref.Name]) != 0 {
			operations = append(operations, map[string]any{"add": map[string]any{"element": map[string]any{
				"family": ref.Family, "table": ref.Table, "name": ref.Name, "elem": values[ref.Name],
			}}})
		}
	}
	return operations, ctx.Err()
}

func nativeTimedValue(value any, timeout int) any {
	return map[string]any{"elem": map[string]any{"val": value, "timeout": timeout}}
}

func ownershipPreparedData(ctx context.Context, snapshot policy.OwnershipSnapshot, timeouts []int, epochTimeout int, native bool) ([]byte, error) {
	data, err := ownershipChanges(ctx, snapshot, timeouts, epochTimeout)
	if err != nil || !native {
		return data, err
	}
	extra, err := nativeSourceChanges(ctx, snapshot, timeouts, epochTimeout)
	if err != nil {
		return nil, err
	}
	var batch struct {
		Operations []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, errors.New("firewall: native ownership metadata decoding failed")
	}
	if snapshot.Epoch == 0 && len(snapshot.Addresses) == 0 && len(timeouts) == 0 && epochTimeout == 0 {
		for _, command := range clearNativeIDGrants() {
			extra = append(extra, command)
		}
	}
	for _, operation := range extra {
		encoded, err := json.Marshal(operation)
		if err != nil {
			return nil, errors.New("firewall: native ownership metadata encoding failed")
		}
		batch.Operations = append(batch.Operations, encoded)
	}
	data, err = json.Marshal(batch)
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: native ownership metadata exceeds transaction capacity")
	}
	return data, ctx.Err()
}

// prepareNativeOwnership preserves the original evidence, preparation budget
// and per-address deadlines. No runtime interface accepts this mode or data
// independently of the private, immutable ownership preparation.
func (renderer *renderer) prepareNativeOwnership(ctx context.Context, evidence policy.Ownership, now time.Time) (*preparedOwnership, error) {
	prepared, err := renderer.prepareOwnership(ctx, evidence, now)
	if err != nil {
		return nil, err
	}
	snapshot, err := evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	data, err := ownershipPreparedData(ctx, snapshot, prepared.timeouts, prepared.epochTimeout, true)
	if err != nil {
		return nil, err
	}
	prepared.batch.data, prepared.digest, prepared.nativeSources = data, sha256.Sum256(data), true
	return prepared, nil
}

func prepareNativeOwnershipClear(ctx context.Context) (*preparedOwnership, error) {
	data, err := ownershipPreparedData(ctx, policy.OwnershipSnapshot{}, nil, 0, true)
	if err != nil {
		return nil, err
	}
	return &preparedOwnership{batch: preparedBatch{data: data}, digest: sha256.Sum256(data), clear: true, nativeSources: true}, nil
}

func compareNativeSources(left, right nativeSourceIdentity) int {
	if left.mac < right.mac || left.mac == right.mac && left.iface < right.iface {
		return -1
	}
	if left == right {
		return 0
	}
	return 1
}
