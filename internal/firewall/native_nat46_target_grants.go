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

// Both address representations have named nft datatypes. A wire IPv6 lookup
// uses the actual embedded client; raw IPv4 uses the original peer. Deriving
// both from the same logical tuple avoids treating untyped payload bits as an
// ipv4_addr, and keeps the static client namespace separate from NAS IPv4 IDs.
func nativeNAT46TargetGrantRefs() []objectReference {
	refs := []objectReference{}
	for _, family := range []string{"inet", "netdev"} {
		for _, protocol := range []string{"tcp", "udp"} {
			for _, version := range []int{4, 6} {
				refs = append(refs, objectReference{Family: family, Table: ownedTable, Name: fmt.Sprintf("native_n46_to%d_%s", version, protocol)})
			}
		}
	}
	return refs
}

func nativeNAT46TargetGrantDefinitions(family string) []string {
	definitions := []string{}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		if ref.Family != family {
			continue
		}
		address := "ipv4_addr"
		if ref.Name == "native_n46_to6_tcp" || ref.Name == "native_n46_to6_udp" {
			address = "ipv6_addr"
		}
		definitions = append(definitions, guardSetDefinition(ref.Name, "classid . ipv4_addr . "+address+" . inet_service"))
	}
	return definitions
}

func nativeNAT46TargetGrantSchema(schema *guardTableSchema, family string) {
	for _, ref := range nativeNAT46TargetGrantRefs() {
		if ref.Family != family {
			continue
		}
		address := "ipv4_addr"
		if ref.Name == "native_n46_to6_tcp" || ref.Name == "native_n46_to6_udp" {
			address = "ipv6_addr"
		}
		schema.sets[ref.Name] = guardLeaseHeader(family, ref.Name, []string{"classid", "ipv4_addr", address, "inet_service"})
	}
}

// projectTargetGrants is a data projection for a future typed writer path.
// It installs no hook or forwarding verdict. The caller must supply already
// validated full logical grants and later independently rederive the complete
// transaction from the original receipt and this compiler-owned model. Generic
// guarded mutation does not admit these collections.
func (model *nativeNAT46Model) projectTargetGrants(ctx context.Context, logical guardChanges, publication *nativeSourcePublication, utc, anchor time.Time) ([]change, error) {
	if ctx == nil || model == nil || !generationHash(model.baselineHash) || publication == nil || utc.IsZero() || anchor.IsZero() || anchor.Before(publication.startedAt) || time.Since(anchor) < 0 {
		return nil, errors.New("firewall: missing nat46 target grant publication")
	}
	if !model.prefix.IsValid() || !model.prefix.Addr().Is6() || model.prefix.Bits() != 96 {
		return nil, errors.New("firewall: missing nat46 target grant prefix")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := publication.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot.BaselineHash != model.baselineHash || snapshot.Epoch == 0 || snapshot.Epoch > policy.MaximumOwnershipEpoch || len(snapshot.Addresses) != len(publication.timeouts) {
		return nil, errors.New("firewall: nat46 target grant source publication changed")
	}
	if _, err := publication.evidence.EpochRemaining(utc); err != nil {
		return nil, err
	}
	targets := map[netip.Addr]int{}
	for index, address := range snapshot.Addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !address.Address.Is6() {
			continue
		}
		if _, duplicate := targets[address.Address]; duplicate {
			return nil, errors.New("firewall: ambiguous nat46 target ownership")
		}
		targets[address.Address] = index
	}
	mappings := map[netip.Addr]nativeNAT46Mapping{}
	for _, mapping := range model.mappings {
		mappings[mapping.alias] = mapping
	}
	values := map[string]map[string]int{}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		values[ref.Name] = map[string]int{}
	}
	for _, command := range logical.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family != "inet" || element.Table != ownedTable || element.Name != "lease_to4_tcp" && element.Name != "lease_to4_udp" {
			continue
		}
		protocol := "tcp"
		if element.Name == "lease_to4_udp" {
			protocol = "udp"
		}
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			tuple, err := validateLeasedTuple(raw, true)
			if err != nil {
				return nil, err
			}
			mapping, found := mappings[tuple.device]
			if !found {
				continue
			}
			index, found := targets[mapping.target]
			if !found {
				continue
			}
			target := snapshot.Addresses[index]
			if target.Interface != mapping.targetInterface || target.Interface != tuple.interfaceName || target.MAC != tuple.mac {
				continue
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
			for _, version := range []int{4, 6} {
				peer := tuple.peer
				if version == 6 {
					peer = nativeNAT46SourcePrefix(model.prefix, netip.PrefixFrom(peer, 32)).Addr()
				}
				key, err := json.Marshal(map[string]any{"concat": []any{epochClassID(snapshot.Epoch << policy.OwnershipRuleBits), mapping.alias.String(), peer.String(), tuple.port}})
				if err != nil {
					return nil, err
				}
				name := fmt.Sprintf("native_n46_to%d_%s", version, protocol)
				values[name][string(key)] = max(values[name][string(key)], timeout)
				if len(values[name]) > maximumTupleCount {
					return nil, errors.New("firewall: nat46 target grant capacity exceeded")
				}
			}
		}
	}
	commands := []change{}
	for _, ref := range nativeNAT46TargetGrantRefs() {
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
			raw, err := json.Marshal(map[string]any{"elem": map[string]any{"val": json.RawMessage(key), "timeout": values[ref.Name][key]}})
			if err != nil {
				return nil, err
			}
			elements = append(elements, raw)
		}
		if len(elements) > 0 {
			commands = append(commands, guardAdd(ref.Family, ref.Name, elements))
		}
	}
	return commands, ctx.Err()
}

// targetGrant retains a current destination-device grant after either packet
// representation. The epoch base is separate from the client's UID or static
// GID. A caller must independently prove that client's current exact identity
// and the native target, enforce ordered scope, and validate translator facts.
func (leg nativeNAT46Leg) targetGrant(wire bool) []nativeScope {
	if leg.protocol != "tcp" && leg.protocol != "udp" {
		return []nativeScope{nativeVerdict("drop", "")}
	}
	family, version, target, client, port := "ip", 4, "daddr", "saddr", "dport"
	address := leg.mapping.alias
	if wire {
		family, version, address = "ip6", 6, leg.mapping.target
	}
	if leg.reply {
		target, client, port = "saddr", "daddr", "sport"
	}
	set := fmt.Sprintf("native_n46_to%d_%s", version, leg.protocol)
	key := map[string]any{"concat": []any{guardBinary("&", guardMeta("priority"), "ffff:fc00"), leg.mapping.alias.String(), guardPayload(family, client), guardPayload(leg.protocol, port)}}
	geometry := nativeMatch(family+" "+target+" "+address.String(), guardPayload(family, target), address.String())
	if wire {
		geometry = nativeJoin(geometry, nativeMatch(family+" "+client+" "+leg.prefix.String(), guardPayload(family, client), controllerPrefix(leg.prefix)))
	}
	proof := nativeMatch(fmt.Sprintf("(meta priority & 0xfffffc00) . %s . %s %s . %s %s @%s", leg.mapping.alias, family, client, leg.protocol, port, set), key, "@"+set)
	static := uint64(0xf5000000)
	if leg.reply {
		static += 0x01000000
	}
	return []nativeScope{
		nativeJoin(nativeMark(0xff000000, nativeDirectoryTag(leg.reply)), geometry, proof, nativeVerdict("return", "")),
		nativeJoin(nativeMark(0xff000000, static), geometry, proof, nativeVerdict("return", "")),
		nativeVerdict("drop", ""),
	}
}
