package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeIDLeaseRefs() []objectReference {
	refs := []objectReference{}
	for _, family := range []string{"inet", "netdev"} {
		for _, name := range grantSets {
			if ipv4Set(name) {
				refs = append(refs, objectReference{Family: family, Table: ownedTable, Name: "native_id_" + name})
			}
		}
	}
	return refs
}

func nativeGrantRefs() []objectReference {
	refs := append([]objectReference{}, nativeLeaseRefs()...)
	return append(refs, nativeIDLeaseRefs()...)
}

func clearNativeIDGrants() []change {
	commands := []change{}
	for _, ref := range nativeIDLeaseRefs() {
		commands = append(commands, change{Flush: &setChange{Set: ref}})
	}
	return commands
}

func nativeIDGrantDefinitions(family string) []string {
	definitions := []string{}
	for _, ref := range nativeIDLeaseRefs() {
		if ref.Family == family {
			definitions = append(definitions, guardSetDefinition(ref.Name, "classid . mark . ipv4_addr . inet_service"))
		}
	}
	return definitions
}

func nativeIDGrantSchema(schema *guardTableSchema, family string) {
	for _, ref := range nativeIDLeaseRefs() {
		if ref.Family == family {
			schema.sets[ref.Name] = guardLeaseHeader(family, ref.Name, []string{"classid", "mark", "ipv4_addr", "inet_service"})
		}
	}
}

// ID projections retain the original source epoch as well as the canonical
// per-address ID. Reusing an ID in a later ownership episode cannot transfer a
// grant. Both the logical grant and the original published source deadline
// bound each projection. No kernel listing supplies positive evidence here.
func projectNativeIPv4GrantIDs(ctx context.Context, logical guardChanges, publication *nativeSourcePublication, baselineHash string, utc, anchor time.Time) ([]change, error) {
	if ctx == nil || publication == nil || utc.IsZero() || anchor.IsZero() || anchor.Before(publication.startedAt) || time.Since(anchor) < 0 {
		return nil, errors.New("firewall: missing native grant source publication")
	}
	snapshot, err := publication.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot.BaselineHash != baselineHash || snapshot.Epoch == 0 || snapshot.Epoch > policy.MaximumOwnershipEpoch || len(snapshot.Addresses) != len(publication.timeouts) {
		return nil, errors.New("firewall: native grant source publication changed")
	}
	if _, err := publication.evidence.EpochRemaining(utc); err != nil {
		return nil, err
	}
	inventory := []nativeSourceIP{}
	indexes := map[nativeSourceIP]int{}
	for index, address := range snapshot.Addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !address.Address.Is4() {
			continue
		}
		identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}
		if _, exists := indexes[identity]; exists {
			return nil, errors.New("firewall: duplicate native source publication identity")
		}
		indexes[identity] = index
		inventory = append(inventory, identity)
	}
	if len(inventory) > maximumCohortSize {
		return nil, errors.New("firewall: native grant source inventory exceeds its bound")
	}
	slices.SortFunc(inventory, compareNativeIP)
	ids := map[nativeSourceIP]uint32{}
	for index, identity := range inventory {
		ids[identity] = uint32(index + 1)
	} // #nosec G115 -- inventory is bounded to 4096 entries; zero is reserved.
	values := map[string]map[string]int{}
	for _, ref := range nativeIDLeaseRefs() {
		values[ref.Name] = map[string]int{}
	}
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
				return nil, err
			}
			tuple, err := validateLeasedTuple(raw, true)
			if err != nil {
				return nil, err
			}
			identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: tuple.interfaceName, mac: tuple.mac}, address: tuple.device}
			id := ids[identity]
			if id == 0 {
				continue
			}
			sourceIndex := indexes[identity]
			remaining, err := publication.remaining(ctx, sourceIndex, anchor)
			if err != nil {
				continue
			}
			proofRemaining, err := publication.evidence.Remaining(sourceIndex, utc)
			if err != nil {
				continue
			}
			remaining = min(remaining, proofRemaining)
			timeout := int((remaining - preparationBudget - commandBudget) / time.Second)
			if timeout < 1 {
				continue
			}
			var lease struct {
				Element struct {
					Timeout int `json:"timeout"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &lease); err != nil {
				return nil, err
			}
			timeout = min(timeout, lease.Element.Timeout)
			key, err := nativeIDGrantKey(snapshot.Epoch<<policy.OwnershipRuleBits, id, tuple.peer, tuple.port)
			if err != nil {
				return nil, err
			}
			name := "native_id_" + element.Name
			values[name][string(key)] = max(values[name][string(key)], timeout)
			if len(values[name]) > maximumTupleCount {
				return nil, errors.New("firewall: native ID grant capacity exceeded")
			}
		}
	}
	commands := []change{}
	for _, ref := range nativeIDLeaseRefs() {
		commands = append(commands, change{Flush: &setChange{Set: ref}})
		keys := []string{}
		for key := range values[ref.Name] {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		elements := []json.RawMessage{}
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			encoded, err := json.Marshal(map[string]any{"elem": map[string]any{"val": json.RawMessage(key), "timeout": values[ref.Name][key]}})
			if err != nil {
				return nil, err
			}
			elements = append(elements, encoded)
		}
		if len(elements) > 0 {
			commands = append(commands, guardAdd(ref.Family, ref.Name, elements))
		}
	}
	if len(commands) > 2*len(nativeIDLeaseRefs()) {
		return nil, errors.New("firewall: native ID grant command capacity exceeded")
	}
	return commands, ctx.Err()
}

func nativeIDGrantKey(epochBase, id uint32, peer netip.Addr, port uint16) (json.RawMessage, error) {
	if epochBase == 0 || epochBase&ownershipRuleMask != 0 || epochBase>>policy.OwnershipRuleBits > policy.MaximumOwnershipEpoch || id == 0 || id > maximumCohortSize || !peer.Is4() || port == 0 {
		return nil, errors.New("firewall: invalid source identity grant key")
	}
	return json.Marshal(map[string]any{"concat": []any{epochClassID(epochBase | id&ownershipRuleMask), (id >> 10) << 13, peer.String(), port}})
}

func validateNativeIDGrantDeadlines(ctx context.Context, prepared *preparedGuardBatch) error {
	publication := prepared.sourcePublication
	if publication == nil {
		return nil
	}
	snapshot, err := publication.evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	inventory := []nativeSourceIP{}
	indexes := map[nativeSourceIP]int{}
	for index, address := range snapshot.Addresses {
		if !address.Address.Is4() {
			continue
		}
		identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}
		inventory = append(inventory, identity)
		indexes[identity] = index
	}
	slices.SortFunc(inventory, compareNativeIP)
	changes, err := decodeGuardChanges(prepared.batch.data)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, command := range changes.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if !slices.Contains(nativeIDLeaseRefs(), objectReference{Family: element.Family, Table: element.Table, Name: element.Name}) {
			continue
		}
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return err
			}
			var lease struct {
				Value struct {
					Fields []json.RawMessage `json:"concat"`
				} `json:"val"`
				Timeout int `json:"timeout"`
			}
			if decodeNested(raw, "elem", &lease, []string{"val", "timeout"}) != nil || len(lease.Value.Fields) != 4 {
				return errors.New("firewall: invalid prepared source ID grant")
			}
			var priority string
			var high uint32
			if json.Unmarshal(lease.Value.Fields[0], &priority) != nil || json.Unmarshal(lease.Value.Fields[1], &high) != nil {
				return errors.New("firewall: malformed prepared source ID")
			}
			value, err := parseNativeClassID(priority)
			if err != nil {
				return err
			}
			id := (high >> 3) | (value & ownershipRuleMask)
			if high&^nativeSourceMask != 0 || value&ownershipEpochMask != snapshot.Epoch<<policy.OwnershipRuleBits || id == 0 || int(id) > len(inventory) {
				return errors.New("firewall: prepared source ID changed its ownership episode")
			}
			index := indexes[inventory[id-1]]
			remaining, err := publication.remaining(ctx, index, now)
			if err != nil {
				return err
			}
			proofRemaining, err := publication.evidence.Remaining(index, prepared.sourceUTC)
			if err != nil {
				return err
			}
			if lease.Timeout < 1 || time.Duration(lease.Timeout)*time.Second+commandBudget > min(remaining, proofRemaining) {
				return errors.New("firewall: native ID grant escaped its published source deadline")
			}
		}
	}
	return ctx.Err()
}
