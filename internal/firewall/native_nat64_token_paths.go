package firewall

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

type nativeNAT64PathStates struct {
	states []nativeNAT64TokenState
	seen   map[nativeNAT64TokenState]bool
	work   int
}

func (plan *nativeNAT64PathStates) step(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	plan.work++
	if plan.work > 1<<22 {
		return errors.New("firewall: NAT64 token path expansion exceeds capacity")
	}
	return nil
}

func (plan *nativeNAT64PathStates) add(state nativeNAT64TokenState) error {
	if plan.seen[state] {
		return nil
	}
	if len(plan.states) >= maximumNAT64Tokens {
		return errors.New("firewall: NAT64 token path registry exceeds capacity")
	}
	plan.seen[state] = true
	plan.states = append(plan.states, state)
	return nil
}

func (origin *nativeNAT64TokenOrigin) pathStates(ctx context.Context, utc time.Time, allocations []policy.NAT64Allocation, epoch uint32) ([]nativeNAT64TokenState, error) {
	plan := &nativeNAT64PathStates{seen: map[nativeNAT64TokenState]bool{}}
	base := epoch << policy.OwnershipRuleBits
	for index, rule := range origin.access.ruleSet.rules {
		if !nativeNAT64RuleEligible(rule, origin.transport) {
			continue
		}
		for _, packet := range origin.access.contexts[index] {
			if packet.family != 0 && packet.family != 6 || packet.source != nil {
				continue
			}
			for _, allocation := range allocations {
				if err := plan.step(ctx); err != nil {
					return nil, err
				}
				if !nativeNAT64AllocationReady(allocation, origin.transport) || !nativeNAT64AddressIn(allocation.Source, origin.transport.sourceNetworks[packet.iface]) ||
					!nativeNAT64SourceSelector(rule.From, packet.iface, packet.mac, allocation.Source) {
					continue
				}
				marker := base | uint32(index)                                                                                                                             // #nosec G115 -- rule indices are validated to 0..1023.
				if err := plan.add(nativeNAT64TokenState{epoch: marker, context: uint32(nativeTag(true, false) | packet.id), channel: base, origin: marker}); err != nil { // #nosec G115 -- context IDs are validated to 0..1023.
					return nil, err
				}
				for actual, target := range origin.access.ruleSet.rules {
					if err := plan.step(ctx); err != nil {
						return nil, err
					}
					if !nativeNAT64RuleEligible(target, origin.transport) || target.Authorization == "directory" ||
						!nativeNAT64SourceSelector(target.From, packet.iface, packet.mac, allocation.Source) {
						continue
					}
					if err := plan.add(nativeNAT64TokenState{epoch: base | uint32(actual), context: uint32(nativeTag(true, true) | packet.id), channel: base, origin: marker}); err != nil { // #nosec G115 -- rule and context indices are validated to 0..1023.
						return nil, err
					}
				}
			}
		}
	}
	if origin.sources != nil {
		if err := origin.addOwnedPathStates(ctx, utc, allocations, plan); err != nil {
			return nil, err
		}
	}
	return compactNAT64TokenStates(plan.states), ctx.Err()
}

func (origin *nativeNAT64TokenOrigin) addOwnedPathStates(ctx context.Context, utc time.Time, allocations []policy.NAT64Allocation, plan *nativeNAT64PathStates) error {
	receipt := origin.sources
	if receipt == nil || receipt.evidence == (policy.Ownership{}) {
		return errors.New("firewall: missing NAT64 source publication")
	}
	snapshot, err := receipt.evidence.Snapshot(ctx)
	if err != nil || snapshot.BaselineHash != origin.access.baselineHash || snapshot.Epoch == 0 ||
		snapshot.Epoch > policy.MaximumOwnershipEpoch || len(snapshot.Addresses) != len(receipt.timeouts) {
		return errors.New("firewall: NAT64 source publication differs from ordered access")
	}
	ids := nativeNAT64IPv6SourceIDs(snapshot)
	selected := make(map[netip.Addr]bool, len(allocations))
	for _, allocation := range allocations {
		if nativeNAT64AllocationReady(allocation, origin.transport) {
			selected[allocation.Source] = true
		}
	}
	base := snapshot.Epoch << policy.OwnershipRuleBits
	for addressIndex, address := range snapshot.Addresses {
		if err := plan.step(ctx); err != nil {
			return err
		}
		if !selected[address.Address] || !address.Address.Is6() {
			continue
		}
		if _, err := receipt.remaining(ctx, addressIndex, utc); err != nil {
			return err
		}
		id := ids[nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}]
		if id == 0 {
			return errors.New("firewall: NAT64 source publication lost its canonical address identity")
		}
		for index, rule := range origin.access.ruleSet.rules {
			if !nativeNAT64RuleEligible(rule, origin.transport) || !nativeNAT64SourceSelector(rule.From, address.Interface, address.MAC, address.Address) {
				continue
			}
			for _, packet := range origin.access.contexts[index] {
				if !nativeNAT64OwnedContext(packet, origin.access.ruleSet, address) {
					continue
				}
				channel := base | id&ownershipRuleMask
				contextID := uint32(packet.id) | (id>>policy.OwnershipRuleBits)<<13                                                                                            // #nosec G115 -- context and source IDs are compiler bounded.
				marker := base | uint32(index)                                                                                                                                 // #nosec G115 -- validated rule index is at most 1023.
				if err := plan.add(nativeNAT64TokenState{epoch: marker, context: uint32(nativeTag(false, false)) | contextID, channel: channel, origin: marker}); err != nil { // #nosec G115 -- native metadata tags fit uint32.
					return err
				}
				for actual, target := range origin.access.ruleSet.rules {
					if err := plan.step(ctx); err != nil {
						return err
					}
					if !nativeNAT64RuleEligible(target, origin.transport) || !nativeNAT64SourceSelector(target.From, address.Interface, address.MAC, address.Address) {
						continue
					}
					for _, directory := range []bool{false, true} {
						if directory && target.Authorization == "owner" || !directory && target.Authorization == "directory" {
							continue
						}
						kind := nativeTag(false, true)
						if directory {
							kind = nativeDirectoryTag(true)
						}
						if err := plan.add(nativeNAT64TokenState{epoch: base | uint32(actual), context: uint32(kind) | contextID, channel: channel, origin: marker}); err != nil { // #nosec G115 -- validated rule indices and metadata tags fit uint32.
							return err
						}
					}
				}
			}
		}
	}
	return ctx.Err()
}
