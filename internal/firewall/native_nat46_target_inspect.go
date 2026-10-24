package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// This checks observations against current native target ownership and the
// complete logical permission. It never creates a receipt or a positive batch;
// publication still requires the original compiler proof and source receipt.
func (model *nativeNAT46Model) inspectTargetGrants(ctx context.Context, logical guardChanges, inet, netdev *guardTableObservation) (int, error) {
	if ctx == nil || model == nil || !generationHash(model.baselineHash) || inet == nil || netdev == nil {
		return 0, errors.New("firewall: missing nat46 target observation dependencies")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	base, epochTimeout, err := nativeNAT46ObservedSourceEpoch(ctx, inet)
	if err != nil {
		return 0, err
	}
	owned, err := nativeNAT46ObservedTargets(ctx, inet)
	if err != nil {
		return 0, err
	}
	expected, err := model.expectedTargetGrantObservation(ctx, logical, owned, base, epochTimeout)
	if err != nil {
		return 0, err
	}
	count := 0
	mirrors := map[string][]json.RawMessage{}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		observation := inet
		if ref.Family == "netdev" {
			observation = netdev
		}
		set, present := observation.sets[ref.Name]
		if !present {
			return 0, errors.New("firewall: missing fixed nat46 target grant collection")
		}
		actual, err := listedGuardLeases(ctx, set.Elements)
		if err != nil {
			return 0, err
		}
		if len(actual) > maximumTupleCount {
			return 0, errors.New("firewall: nat46 target observation exceeds capacity")
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
				return 0, errors.New("firewall: nat46 target grant lacks current ownership and full logical permission")
			}
			seen[identity] = true
		}
		if ref.Family == "inet" {
			mirrors[ref.Name] = actual
		} else {
			if err := sameGuardElements(ctx, actual, mirrors[ref.Name]); err != nil {
				return 0, err
			}
			count += len(actual)
		}
	}
	return count, ctx.Err()
}

func nativeNAT46ObservedSourceEpoch(ctx context.Context, inet *guardTableObservation) (uint32, int, error) {
	epochs, err := listedGuardLeases(ctx, inet.sets[ownershipEpochSet].Elements)
	if err != nil {
		return 0, 0, err
	}
	if len(epochs) == 0 {
		return 0, 0, ctx.Err()
	}
	var epoch struct {
		Value   uint32 `json:"val"`
		Timeout int    `json:"timeout"`
	}
	if len(epochs) != 1 || decodeNested(epochs[0], "elem", &epoch, []string{"val", "timeout"}) != nil || epoch.Value == 0 || epoch.Value&ownershipRuleMask != 0 || epoch.Value>>policy.OwnershipRuleBits > policy.MaximumOwnershipEpoch {
		return 0, 0, errors.New("firewall: invalid nat46 target source epoch")
	}
	return epoch.Value, epoch.Timeout, ctx.Err()
}

func nativeNAT46ObservedTargets(ctx context.Context, inet *guardTableObservation) (map[nativeSourceIP]int, error) {
	leases, err := listedGuardLeases(ctx, inet.sets[ownership6Set].Elements)
	if err != nil {
		return nil, err
	}
	if len(leases) > maximumCohortSize {
		return nil, errors.New("firewall: nat46 target ownership observation exceeds capacity")
	}
	owned := map[nativeSourceIP]int{}
	seen := map[netip.Addr]bool{}
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
			return nil, errors.New("firewall: malformed nat46 target ownership observation")
		}
		fields := lease.Value.Fields
		address, err := netip.ParseAddr(fields[2])
		if err != nil || !address.Is6() || address.Is4In6() || address.String() != fields[2] || seen[address] {
			return nil, errors.New("firewall: invalid or ambiguous nat46 target ownership")
		}
		seen[address] = true
		owned[nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: fields[0], mac: fields[1]}, address: address}] = lease.Timeout
	}
	return owned, ctx.Err()
}

func (model *nativeNAT46Model) expectedTargetGrantObservation(ctx context.Context, logical guardChanges, owned map[nativeSourceIP]int, base uint32, epochTimeout int) (map[string]map[string]int, error) {
	expected := map[string]map[string]int{}
	for _, ref := range nativeNAT46TargetGrantRefs() {
		expected[ref.Name] = map[string]int{}
	}
	if base == 0 {
		return expected, ctx.Err()
	}
	mappings := map[netip.Addr]nativeNAT46Mapping{}
	for _, mapping := range model.mappings {
		mappings[mapping.alias] = mapping
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
			mapping, present := mappings[tuple.device]
			if !present || mapping.targetInterface != tuple.interfaceName {
				continue
			}
			target := nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: tuple.interfaceName, mac: tuple.mac}, address: mapping.target}
			if owned[target] == 0 {
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
			for _, version := range []int{4, 6} {
				peer := tuple.peer
				if version == 6 {
					peer = nativeNAT46SourcePrefix(model.prefix, netip.PrefixFrom(peer, 32)).Addr()
				}
				key, err := json.Marshal(map[string]any{"concat": []any{epochClassID(base), mapping.alias.String(), peer.String(), tuple.port}})
				if err != nil {
					return nil, err
				}
				name := fmt.Sprintf("native_n46_to%d_%s", version, protocol)
				timeout := min(lease.Element.Timeout, owned[target], epochTimeout)
				expected[name][string(key)] = max(expected[name][string(key)], timeout)
				if len(expected[name]) > maximumTupleCount {
					return nil, errors.New("firewall: nat46 target observation projection exceeds capacity")
				}
			}
		}
	}
	return expected, ctx.Err()
}
