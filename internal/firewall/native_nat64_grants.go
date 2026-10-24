package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeNAT64GrantRefs() []objectReference {
	refs := make([]objectReference, 0, 8)
	for _, family := range []string{"inet", "netdev"} {
		for _, protocol := range []string{"tcp", "udp"} {
			for _, version := range []int{4, 6} {
				refs = append(refs, objectReference{Family: family, Table: ownedTable, Name: fmt.Sprintf("native_n64_from%d_%s", version, protocol)})
			}
		}
	}
	return refs
}

func nativeNAT64GrantDefinitions(family string) []string {
	definitions := []string{}
	for _, ref := range nativeNAT64GrantRefs() {
		if ref.Family != family {
			continue
		}
		address := "ipv4_addr"
		if ref.Name == "native_n64_from6_tcp" || ref.Name == "native_n64_from6_udp" {
			address = "ipv6_addr"
		}
		definitions = append(definitions, guardSetDefinition(ref.Name, "classid . mark . "+address+" . inet_service"))
	}
	return definitions
}

func nativeNAT64GrantSchema(schema *guardTableSchema, family string) {
	for _, ref := range nativeNAT64GrantRefs() {
		if ref.Family != family {
			continue
		}
		address := "ipv4_addr"
		if ref.Name == "native_n64_from6_tcp" || ref.Name == "native_n64_from6_udp" {
			address = "ipv6_addr"
		}
		schema.sets[ref.Name] = guardLeaseHeader(family, ref.Name, []string{"classid", "mark", address, "inet_service"})
	}
}

func (transport *nativeNAT64Transport) projectGrants(
	ctx context.Context,
	logical guardChanges,
	publication *nativeSourcePublication,
	utc, anchor time.Time,
) ([]change, error) {
	if ctx == nil || transport == nil || transport.geometry == nil || !generationHash(transport.baselineHash) ||
		publication == nil || utc.IsZero() || anchor.IsZero() || anchor.Before(publication.startedAt) || time.Since(anchor) < 0 {
		return nil, errors.New("firewall: missing NAT64 grant publication")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := publication.evidence.Snapshot(ctx)
	if err != nil || snapshot.BaselineHash != transport.baselineHash || snapshot.Epoch == 0 ||
		snapshot.Epoch > policy.MaximumOwnershipEpoch || len(snapshot.Addresses) != len(publication.timeouts) {
		return nil, errors.New("firewall: NAT64 grant source publication changed")
	}
	if _, err := publication.evidence.EpochRemaining(utc); err != nil {
		return nil, err
	}
	ids := nativeNAT64IPv6SourceIDs(snapshot)
	indexes := map[nativeSourceIP]int{}
	for index, address := range snapshot.Addresses {
		if !address.Address.Is6() {
			continue
		}
		identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}
		if _, duplicate := indexes[identity]; duplicate {
			return nil, errors.New("firewall: ambiguous NAT64 grant source identity")
		}
		indexes[identity] = index
	}
	mappings := map[netip.Addr]policy.NAT64SourceMapping{}
	for _, mapping := range transport.mappings {
		mappings[mapping.Source] = mapping
	}
	values := map[string]map[string]int{}
	for _, ref := range nativeNAT64GrantRefs() {
		values[ref.Name] = map[string]int{}
	}
	for _, command := range logical.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family != "inet" || element.Table != ownedTable || element.Name != "lease_from6_tcp" && element.Name != "lease_from6_udp" {
			continue
		}
		protocol := "tcp"
		if element.Name == "lease_from6_udp" {
			protocol = "udp"
		}
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			tuple, err := validateLeasedTuple(raw, false)
			if err != nil {
				return nil, err
			}
			identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: tuple.interfaceName, mac: tuple.mac}, address: tuple.device}
			id, found := ids[identity]
			mapping, mapped := mappings[tuple.device]
			index, published := indexes[identity]
			peer4 := nativeNAT64IPv4Prefix(transport.prefix, netip.PrefixFrom(tuple.peer, 128))
			if !found || !mapped || !published || !peer4.IsValid() || peer4.Bits() != 32 {
				continue
			}
			if mapping.Alias == transport.pool.Addr() || !transport.pool.Contains(mapping.Alias) {
				return nil, errors.New("firewall: NAT64 grant mapping escaped its source pool")
			}
			remaining, err := publication.remaining(ctx, index, anchor)
			if err != nil {
				continue
			}
			proofRemaining, err := publication.evidence.Remaining(index, utc)
			if err != nil {
				continue
			}
			timeout := int((min(remaining, proofRemaining) - preparationBudget - commandBudget) / time.Second)
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
			channel := snapshot.Epoch<<policy.OwnershipRuleBits | id&ownershipRuleMask
			high := (id >> policy.OwnershipRuleBits) << 13
			for _, version := range []int{4, 6} {
				peer := peer4.Addr()
				if version == 6 {
					peer = tuple.peer
				}
				key, err := json.Marshal(map[string]any{"concat": []any{epochClassID(channel), high, peer.String(), tuple.port}})
				if err != nil {
					return nil, err
				}
				name := fmt.Sprintf("native_n64_from%d_%s", version, protocol)
				values[name][string(key)] = max(values[name][string(key)], timeout)
				if len(values[name]) > maximumTupleCount {
					return nil, errors.New("firewall: NAT64 grant capacity exceeded")
				}
			}
		}
	}
	commands := []change{}
	for _, ref := range nativeNAT64GrantRefs() {
		commands = append(commands, change{Flush: &setChange{Set: ref}})
		keys := make([]string, 0, len(values[ref.Name]))
		for key := range values[ref.Name] {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		elements := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			encoded, err := json.Marshal(map[string]any{"elem": map[string]any{"val": json.RawMessage(key), "timeout": values[ref.Name][key]}})
			if err != nil {
				return nil, err
			}
			elements = append(elements, encoded)
		}
		if len(elements) != 0 {
			commands = append(commands, guardAdd(ref.Family, ref.Name, elements))
		}
	}
	return commands, ctx.Err()
}

func expandNativeNAT64Grants(
	ctx context.Context,
	data []byte,
	publication *nativeSourcePublication,
	transports []*nativeNAT64Transport,
	utc, anchor time.Time,
) ([]byte, error) {
	if ctx == nil || len(transports) == 0 {
		return nil, errors.New("firewall: missing NAT64 grant geometry")
	}
	changes, err := decodeGuardChanges(data)
	if err != nil {
		return nil, err
	}
	type timedGrant struct {
		value   json.RawMessage
		timeout int
	}
	values := map[string]map[string]timedGrant{}
	for _, ref := range nativeNAT64GrantRefs() {
		values[ref.Name] = map[string]timedGrant{}
	}
	baselineHash := transports[0].baselineHash
	for _, transport := range transports {
		if transport == nil || !generationHash(transport.baselineHash) || transport.baselineHash != baselineHash {
			return nil, errors.New("firewall: inconsistent NAT64 grant geometry")
		}
		if publication == nil {
			continue
		}
		projected, projectErr := transport.projectGrants(ctx, changes, publication, utc, anchor)
		if projectErr != nil {
			return nil, projectErr
		}
		for _, command := range projected {
			if command.Add == nil {
				continue
			}
			for _, raw := range command.Add.Element.Values {
				var lease struct {
					Value   json.RawMessage `json:"val"`
					Timeout int             `json:"timeout"`
				}
				if decodeNested(raw, "elem", &lease, []string{"val", "timeout"}) != nil || len(lease.Value) == 0 || lease.Timeout < 1 {
					return nil, errors.New("firewall: invalid projected NAT64 grant")
				}
				key := string(lease.Value)
				prior := values[command.Add.Element.Name][key]
				if lease.Timeout > prior.timeout {
					values[command.Add.Element.Name][key] = timedGrant{value: slices.Clone(lease.Value), timeout: lease.Timeout}
				}
			}
		}
	}
	extra := []change{}
	for _, ref := range nativeNAT64GrantRefs() {
		extra = append(extra, change{Flush: &setChange{Set: ref}})
		keys := make([]string, 0, len(values[ref.Name]))
		for key := range values[ref.Name] {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		elements := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			entry := values[ref.Name][key]
			encoded, encodeErr := json.Marshal(map[string]any{"elem": map[string]any{"val": entry.value, "timeout": entry.timeout}})
			if encodeErr != nil {
				return nil, encodeErr
			}
			elements = append(elements, encoded)
		}
		if len(elements) != 0 {
			extra = append(extra, guardAdd(ref.Family, ref.Name, elements))
		}
	}
	changes.Commands = append(changes.Commands, extra...)
	encoded, err := json.Marshal(changes)
	if err != nil || len(encoded) > maximumBatch {
		return nil, errors.New("firewall: NAT64 grant transaction exceeds capacity")
	}
	return encoded, ctx.Err()
}

func prepareNativeNAT64Guards(
	ctx context.Context,
	source *preparedGuardBatch,
	publication *nativeSourcePublication,
	transport *nativeNAT64Transport,
	utc time.Time,
) (*preparedGuardBatch, error) {
	return prepareNativeNAT64AggregateGuards(ctx, source, publication, []*nativeNAT64Transport{transport}, utc)
}

func preparedNativeNAT64Transports(prepared *preparedGuardBatch) ([]*nativeNAT64Transport, error) {
	if prepared == nil {
		return nil, errors.New("firewall: missing NAT64 grant preparation")
	}
	transports := slices.Clone(prepared.nat64Transports)
	switch {
	case len(transports) == 0 && prepared.nat64Transport == nil:
		return nil, nil
	case len(transports) == 0:
		return []*nativeNAT64Transport{prepared.nat64Transport}, nil
	case len(transports) == 1 && prepared.nat64Transport != transports[0]:
		return nil, errors.New("firewall: singular NAT64 grant selector changed")
	case len(transports) > 1 && prepared.nat64Transport != nil:
		return nil, errors.New("firewall: aggregate NAT64 grants acquired a singular selector")
	}
	return transports, nil
}

func prepareNativeNAT64AggregateGuards(
	ctx context.Context,
	source *preparedGuardBatch,
	publication *nativeSourcePublication,
	transports []*nativeNAT64Transport,
	utc time.Time,
) (*preparedGuardBatch, error) {
	if ctx == nil || len(transports) == 0 || transports[0] == nil || !generationHash(transports[0].baselineHash) {
		return nil, errors.New("firewall: missing NAT64 guard model")
	}
	baselineHash := transports[0].baselineHash
	for _, transport := range transports {
		if transport == nil || transport.baselineHash != baselineHash {
			return nil, errors.New("firewall: inconsistent NAT64 guard model")
		}
	}
	hash := ""
	if publication != nil {
		hash = baselineHash
	} else if !utc.IsZero() {
		return nil, errors.New("firewall: NAT64 seal cannot carry an authorization clock")
	}
	prepared, err := prepareNativeGuardsWithSource(ctx, source, publication, hash, utc)
	if err != nil {
		return nil, err
	}
	return attachNativeNAT64Grants(ctx, prepared, publication, transports)
}

func attachNativeNAT64Grants(
	ctx context.Context,
	prepared *preparedGuardBatch,
	publication *nativeSourcePublication,
	transports []*nativeNAT64Transport,
) (*preparedGuardBatch, error) {
	if ctx == nil || prepared == nil || !prepared.native || prepared.sourcePublication != publication ||
		prepared.nat64Transport != nil || len(prepared.nat64Transports) != 0 || len(transports) == 0 {
		return nil, errors.New("firewall: invalid NAT64 grant attachment")
	}
	baselineHash := transports[0].baselineHash
	for _, transport := range transports {
		if transport == nil || !generationHash(transport.baselineHash) || transport.baselineHash != baselineHash {
			return nil, errors.New("firewall: inconsistent NAT64 guard model")
		}
	}
	if publication != nil && prepared.sourceBaselineHash != baselineHash {
		return nil, errors.New("firewall: NAT64 grant attachment changed source baseline")
	}
	data, err := expandNativeNAT64Grants(ctx, prepared.batch.data, publication, transports, prepared.sourceUTC, prepared.sourceAnchor)
	if err != nil {
		return nil, err
	}
	next := *prepared
	next.batch.data = data
	next.nat64Transports = slices.Clone(transports)
	if len(transports) == 1 {
		next.nat64Transport = transports[0]
	}
	return &next, nil
}

func validateNAT64GrantDeadlines(ctx context.Context, prepared *preparedGuardBatch) error {
	transports, err := preparedNativeNAT64Transports(prepared)
	if err != nil {
		return err
	}
	if len(transports) == 0 || prepared.sourcePublication == nil {
		return ctx.Err()
	}
	publication := prepared.sourcePublication
	snapshot, err := publication.evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	inventory := []nativeSourceIP{}
	indexes := map[nativeSourceIP]int{}
	for index, address := range snapshot.Addresses {
		if !address.Address.Is6() {
			continue
		}
		identity := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}
		inventory = append(inventory, identity)
		indexes[identity] = index
	}
	slices.SortFunc(inventory, compareNativeIP)
	mapped := map[netip.Addr]bool{}
	for _, transport := range transports {
		for _, mapping := range transport.mappings {
			mapped[mapping.Source] = true
		}
	}
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
		if !slices.Contains(nativeNAT64GrantRefs(), objectReference{Family: element.Family, Table: element.Table, Name: element.Name}) {
			continue
		}
		for _, raw := range element.Values {
			var lease struct {
				Value struct {
					Fields []json.RawMessage `json:"concat"`
				} `json:"val"`
				Timeout int `json:"timeout"`
			}
			if decodeNested(raw, "elem", &lease, []string{"val", "timeout"}) != nil || len(lease.Value.Fields) != 4 {
				return errors.New("firewall: invalid prepared NAT64 grant")
			}
			var class string
			var high uint32
			if json.Unmarshal(lease.Value.Fields[0], &class) != nil || json.Unmarshal(lease.Value.Fields[1], &high) != nil {
				return errors.New("firewall: malformed prepared NAT64 source identity")
			}
			channel, err := parseNativeClassID(class)
			if err != nil {
				return err
			}
			id := (high >> 3) | (channel & ownershipRuleMask)
			if high&^nativeSourceMask != 0 || channel&ownershipEpochMask != snapshot.Epoch<<policy.OwnershipRuleBits ||
				id == 0 || int(id) > len(inventory) || !mapped[inventory[id-1].address] {
				return errors.New("firewall: prepared NAT64 grant changed its source episode")
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
				return errors.New("firewall: NAT64 grant escaped its original source deadline")
			}
		}
	}
	return ctx.Err()
}
