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

func nativeNAT64TargetTag(directory, reply bool) uint64 {
	tag := uint64(0xd7000000)
	if directory {
		tag = 0xd9000000
	}
	if reply {
		tag += 0x01000000
	}
	return tag
}

// The source context and final rule are compiler identities. Target rows come
// only from the current ownership receipt, never from a request or a listing.
type nativeNAT64TargetBinding struct {
	rule, context uint32
	iface         string
	peer          netip.Addr
	state         nativeNAT64TokenState
}

type nativeNAT64TargetEntry struct {
	nativeNAT64TargetBinding
	token uint32
}

func (origin *nativeNAT64TokenOrigin) targetStates(ctx context.Context, utc time.Time, allocations []policy.NAT64Allocation, configurationEpoch uint32) ([]nativeNAT64TargetBinding, error) {
	if origin.sources == nil {
		return nil, ctx.Err()
	}
	snapshot, err := origin.sources.evidence.Snapshot(ctx)
	if err != nil || snapshot.BaselineHash != origin.access.baselineHash || snapshot.Epoch == 0 || snapshot.Epoch > policy.MaximumOwnershipEpoch || len(snapshot.Addresses) != len(origin.sources.timeouts) {
		return nil, errors.New("firewall: NAT64 target ownership differs from ordered access")
	}
	inventory := []nativeSourceIP{}
	eligible := map[int]bool{}
	for index, address := range snapshot.Addresses {
		if address.Address.Is4() {
			inventory = append(inventory, nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address})
			allowed, err := origin.transport.geometry.EligibleTarget(ctx, origin.transport.component, address.Address)
			if err != nil {
				return nil, err
			}
			eligible[index] = allowed
		}
	}
	if len(inventory) != 0 && snapshot.Epoch <= configurationEpoch {
		return nil, errors.New("firewall: NAT64 target ownership predates configuration")
	}
	slices.SortFunc(inventory, compareNativeIP)
	ids := map[nativeSourceIP]uint32{}
	for index, identity := range inventory {
		ids[identity] = uint32(index + 1)
	} // #nosec G115 -- verified ownership is bounded to 4096 addresses.
	paths, err := nativeNAT64EgressPolicies(ctx, origin.access.ruleSet, origin.transport)
	if err != nil {
		return nil, err
	}
	byInterface := map[string]*nativeRuleSet{}
	for _, path := range paths {
		byInterface[path.iface] = path.raw
	}
	states := []nativeNAT64TargetBinding{}
	seen := map[nativeNAT64TargetBinding]bool{}
	work := &nativeNAT64PathStates{}
	base := snapshot.Epoch << policy.OwnershipRuleBits
	for rawIndex, raw := range origin.access.ruleSet.rules {
		if !nativeNAT64RuleEligible(raw, origin.transport) {
			continue
		}
		for _, packet := range origin.access.contexts[rawIndex] {
			if packet.family != 0 && packet.family != 6 || packet.source != nil {
				continue
			}
			for _, allocation := range allocations {
				if err := work.step(ctx); err != nil {
					return nil, err
				}
				if !nativeNAT64AllocationReady(allocation, origin.transport) || !nativeNAT64AddressIn(allocation.Source, origin.transport.sourceNetworks[packet.iface]) || !nativeNAT64SourceSelector(raw.From, packet.iface, packet.mac, allocation.Source) {
					continue
				}
				for addressIndex, target := range snapshot.Addresses {
					if err := work.step(ctx); err != nil {
						return nil, err
					}
					projected := byInterface[target.Interface]
					if !eligible[addressIndex] || projected == nil {
						continue
					}
					if _, err := origin.sources.remaining(ctx, addressIndex, utc); err != nil {
						return nil, err
					}
					id := ids[nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: target.Interface, mac: target.MAC}, address: target.Address}]
					if id == 0 {
						return nil, errors.New("firewall: NAT64 target lost canonical ownership identity")
					}
					for actual, rule := range origin.access.ruleSet.rules {
						if err := work.step(ctx); err != nil {
							return nil, err
						}
						if !nativeNAT64RuleEligible(rule, origin.transport) || !nativeNAT64SourceSelector(rule.From, packet.iface, packet.mac, allocation.Source) {
							continue
						}
						matches := false
						for _, endpoint := range projected.rules[actual].To {
							for _, prefix := range endpoint.Addresses {
								decoded := nativeNAT64IPv4Prefix(origin.transport.prefix, prefix)
								matches = matches || decoded.IsValid() && decoded.Contains(target.Address)
							}
						}
						if !matches {
							continue
						}
						directory := rule.Authorization == "directory" || rule.Authorization == "inherit" && (slices.Contains(origin.access.managed, packet.iface) || slices.Contains(origin.access.managed, target.Interface))
						for _, reply := range []bool{false, true} {
							binding := nativeNAT64TargetBinding{rule: uint32(actual * 2), context: uint32(packet.id), iface: target.Interface, peer: target.Address, // #nosec G115 -- compiler rule and context indices are bounded to 1023.
								state: nativeNAT64TokenState{epoch: base | uint32(actual), context: uint32(nativeNAT64TargetTag(directory, reply)) | uint32(packet.id) | (id>>policy.OwnershipRuleBits)<<13, channel: base | id&ownershipRuleMask, origin: configurationEpoch<<policy.OwnershipRuleBits | uint32(rawIndex)}} // #nosec G115 -- compiler IDs and metadata tags fit uint32.
							if reply {
								binding.rule++
							}
							if !seen[binding] {
								if len(states) >= maximumNAT64Tokens {
									return nil, errors.New("firewall: NAT64 target registry exceeds capacity")
								}
								seen[binding] = true
								states = append(states, binding)
							}
						}
					}
				}
			}
		}
	}
	return states, ctx.Err()
}

func (tokens *nativeNAT64Tokens) bindTargets(ctx context.Context, bindings []nativeNAT64TargetBinding) error {
	byState := make(map[nativeNAT64TokenState]uint32, len(tokens.entries))
	for _, entry := range tokens.entries {
		byState[entry.nativeNAT64TokenState] = entry.token
	}
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return err
		}
		token := byState[binding.state]
		if token == 0 {
			return errors.New("firewall: NAT64 target lacks its compiler-derived token")
		}
		tokens.targets = append(tokens.targets, nativeNAT64TargetEntry{nativeNAT64TargetBinding: binding, token: token})
	}
	slices.SortFunc(tokens.targets, func(a, b nativeNAT64TargetEntry) int {
		if a.rule != b.rule {
			return compareUint32(a.rule, b.rule)
		}
		if a.context != b.context {
			return compareUint32(a.context, b.context)
		}
		if a.iface != b.iface {
			if a.iface < b.iface {
				return -1
			}
			return 1
		}
		return a.peer.Compare(b.peer)
	})
	for index, entry := range tokens.targets {
		if index > 0 {
			before := tokens.targets[index-1]
			if entry.rule == before.rule && entry.context == before.context && entry.iface == before.iface && entry.peer == before.peer {
				return errors.New("firewall: ambiguous NAT64 target lookup")
			}
		}
	}
	return ctx.Err()
}

func (tokens *nativeNAT64Tokens) targetElements(ctx context.Context) ([]json.RawMessage, error) {
	rows := make([]json.RawMessage, 0, len(tokens.targets))
	for _, target := range tokens.targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !target.peer.Is4() || !interfaceName.MatchString(target.iface) || target.context > ownershipRuleMask || target.rule >= uint32(tokens.transport.ruleCount*2) {
			return nil, errors.New("firewall: invalid NAT64 target token key")
		} // #nosec G115 -- validated rule count is bounded to 1024.
		raw, err := json.Marshal([]any{map[string]any{"concat": []any{nativeLowClassID(target.rule), target.context, target.iface, target.peer.String()}}, epochClassID(target.token)})
		if err != nil {
			return nil, err
		}
		rows = append(rows, raw)
	}
	return rows, ctx.Err()
}

// The final physical check consumes target authority first, then restores the
// independent configuration epoch. Source epochs follow their configuration
// in the durable sequence, so an old key cannot adopt a newer origin.
func (tokens *nativeNAT64Tokens) targetOriginElements(ctx context.Context) ([]json.RawMessage, error) {
	rows := []json.RawMessage{}
	seen := map[string]uint32{}
	for _, entry := range tokens.targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		state := entry.state
		key, err := json.Marshal(map[string]any{"concat": []any{state.context, epochClassID(state.channel)}})
		if err != nil {
			return nil, err
		}
		origin := state.originMarker() & ownershipEpochMask
		if prior, exists := seen[string(key)]; exists {
			if prior != origin {
				return nil, errors.New("firewall: ambiguous NAT64 physical configuration origin")
			}
			continue
		}
		seen[string(key)] = origin
		row, err := json.Marshal([]any{json.RawMessage(key), epochClassID(origin)})
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, ctx.Err()
}
