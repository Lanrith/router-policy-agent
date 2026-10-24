package firewall

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// nativeNAT64TokenOrigin keeps the original non-serializable objects from
// which a bounded token registry was derived. It is deliberately not a copy of
// normalized configuration. Every privileged publication replays this
// derivation so a package-local synthetic state list cannot reach nftables.
type nativeNAT64TokenOrigin struct {
	transport     *nativeNAT64Transport
	access        *nativeAccess
	ledger        *policy.NAT64AllocationLedger
	configuration policy.OwnerConfiguration
	sources       *nativeSourcePublication
}

func deriveNativeNAT64Tokens(
	ctx context.Context,
	transport *nativeNAT64Transport,
	access *nativeAccess,
	ledger *policy.NAT64AllocationLedger,
	configuration policy.OwnerConfiguration,
	sources *nativeSourcePublication,
	utc time.Time,
) (*nativeNAT64Tokens, error) {
	origin := &nativeNAT64TokenOrigin{transport: transport, access: access, ledger: ledger, configuration: configuration, sources: sources}
	tokens, err := origin.deriveAt(ctx, utc)
	if err != nil {
		return nil, err
	}
	if !tokens.clear {
		tokens.origin = origin
	}
	return tokens, nil
}

func (origin *nativeNAT64TokenOrigin) derive(ctx context.Context) (*nativeNAT64Tokens, error) {
	return origin.deriveAt(ctx, time.Now().UTC())
}

func (origin *nativeNAT64TokenOrigin) deriveAt(ctx context.Context, utc time.Time) (*nativeNAT64Tokens, error) {
	if ctx == nil || origin == nil || origin.transport == nil || origin.access == nil || origin.access.ruleSet == nil ||
		origin.ledger == nil || utc.IsZero() || utc.Location() != time.UTC {
		return nil, errors.New("firewall: missing NAT64 token compiler dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	transport, access := origin.transport, origin.access
	if transport.geometry == nil || transport.baselineHash == "" || access.baselineHash == "" ||
		transport.baselineHash != access.baselineHash || access.ruleSet.baselineHash != access.baselineHash ||
		transport.ruleCount != len(access.ruleSet.rules) {
		return nil, errors.New("firewall: NAT64 token geometry differs from ordered access")
	}
	allocations, err := transport.geometry.ValidateLedger(ctx, transport.component, origin.ledger)
	if err != nil || len(allocations) == 0 {
		return nil, errors.New("firewall: NAT64 token registry requires its original allocation ledger")
	}
	configuration, err := origin.configuration.Snapshot(ctx)
	if err != nil || configuration.BaselineHash != access.baselineHash || configuration.Epoch == 0 || configuration.Epoch > policy.MaximumOwnershipEpoch {
		return nil, errors.New("firewall: NAT64 token registry requires matching owner configuration")
	}

	states := make([]nativeNAT64TokenState, 0, len(allocations)*4)
	configurationBase := configuration.Epoch << policy.OwnershipRuleBits
	for index, rule := range access.ruleSet.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !nativeNAT64RuleEligible(rule, transport) {
			continue
		}
		for _, packet := range access.contexts[index] {
			if !nativeNAT64ContextEligible(rule, packet, allocations, transport) {
				continue
			}
			if rule.Authorization != "directory" {
				for _, reply := range []bool{false, true} {
					states = append(states, nativeNAT64TokenState{
						epoch:   configurationBase | uint32(index),          // #nosec G115 -- validated rule count is at most 1024.
						context: uint32(nativeTag(true, reply) | packet.id), // #nosec G115 -- packet IDs are bounded by the rule mask.
						channel: configurationBase,
					})
				}
			}
		}
	}

	if origin.sources != nil {
		_, sourceStates, err := origin.sourceStates(ctx, utc, allocations)
		if err != nil {
			return nil, err
		}
		states = append(states, sourceStates...)
	}
	states = compactNAT64TokenStates(states)
	if len(states) == 0 {
		return prepareNativeNAT64TokenClear(ctx, transport)
	}
	return newNativeNAT64Tokens(ctx, transport, states)
}

func (origin *nativeNAT64TokenOrigin) sourceStates(ctx context.Context, utc time.Time, allocations []policy.NAT64Allocation) (bool, []nativeNAT64TokenState, error) {
	receipt := origin.sources
	if receipt == nil || receipt.evidence == (policy.Ownership{}) {
		return false, nil, errors.New("firewall: missing NAT64 source publication")
	}
	snapshot, err := receipt.evidence.Snapshot(ctx)
	if err != nil || snapshot.BaselineHash != origin.access.baselineHash || snapshot.Epoch == 0 ||
		snapshot.Epoch > policy.MaximumOwnershipEpoch || len(snapshot.Addresses) != len(receipt.timeouts) {
		return false, nil, errors.New("firewall: NAT64 source publication differs from ordered access")
	}
	ids := nativeNAT64IPv6SourceIDs(snapshot)
	selected := make(map[netip.Addr]bool, len(allocations))
	for _, allocation := range allocations {
		if nativeNAT64AllocationReady(allocation, origin.transport) {
			selected[allocation.Source] = true
		}
	}
	base := snapshot.Epoch << policy.OwnershipRuleBits
	found := false
	states := []nativeNAT64TokenState{}
	for addressIndex, address := range snapshot.Addresses {
		if err := ctx.Err(); err != nil {
			return false, nil, err
		}
		if !selected[address.Address] || !address.Address.Is6() {
			continue
		}
		if _, err := receipt.remaining(ctx, addressIndex, utc); err != nil {
			return false, nil, err
		}
		id := ids[nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address}]
		if id == 0 {
			return false, nil, errors.New("firewall: NAT64 source publication lost its canonical address identity")
		}
		found = true
		for index, rule := range origin.access.ruleSet.rules {
			if !nativeNAT64RuleEligible(rule, origin.transport) || !nativeNAT64SourceSelector(rule.From, address.Interface, address.MAC, address.Address) {
				continue
			}
			for _, packet := range origin.access.contexts[index] {
				if !nativeNAT64OwnedContext(packet, origin.access.ruleSet, address) {
					continue
				}
				channel := base | id&ownershipRuleMask
				contextID := uint32(packet.id) | (id>>policy.OwnershipRuleBits)<<13 // #nosec G115 -- both IDs are compiler bounded.
				for _, reply := range []bool{false, true} {
					if rule.Authorization != "directory" {
						states = append(states, nativeNAT64TokenState{epoch: base | uint32(index), context: uint32(nativeTag(false, reply)) | contextID, channel: channel}) // #nosec G115 -- validated rule count is at most 1024.
					}
					if rule.Authorization != "owner" {
						states = append(states, nativeNAT64TokenState{epoch: base | uint32(index), context: uint32(nativeDirectoryTag(reply)) | contextID, channel: channel}) // #nosec G115 -- validated rule count is at most 1024.
					}
				}
			}
		}
	}
	return found, states, ctx.Err()
}

func nativeNAT64IPv6SourceIDs(snapshot policy.OwnershipSnapshot) map[nativeSourceIP]uint32 {
	inventory := []nativeSourceIP{}
	for _, address := range snapshot.Addresses {
		if address.Address.Is6() {
			inventory = append(inventory, nativeSourceIP{nativeSourceIdentity: nativeSourceIdentity{iface: address.Interface, mac: address.MAC}, address: address.Address})
		}
	}
	slices.SortFunc(inventory, compareNativeIP)
	result := make(map[nativeSourceIP]uint32, len(inventory))
	for index, source := range inventory {
		result[source] = uint32(index + 1) // #nosec G115 -- a verified source publication is bounded to 4096 entries.
	}
	return result
}

func nativeNAT64RuleEligible(rule policy.NetworkRule, transport *nativeNAT64Transport) bool {
	if rule.Action != "allow" || rule.Family == 4 || !slices.Contains([]string{"any", "tcp", "udp", "icmpv6"}, rule.Protocol) {
		return false
	}
	for _, target := range rule.To {
		if target.Interface != "" && target.Interface != transport.component {
			continue
		}
		if len(target.Addresses) == 0 {
			return true
		}
		for _, prefix := range target.Addresses {
			if prefix.Addr().Is6() && prefix.Overlaps(transport.prefix) {
				return true
			}
		}
	}
	return false
}

func nativeNAT64ContextEligible(rule policy.NetworkRule, packet nativePacketContext, allocations []policy.NAT64Allocation, transport *nativeNAT64Transport) bool {
	if packet.family != 0 && packet.family != 6 || packet.source != nil {
		return false
	}
	networks := transport.sourceNetworks[packet.iface]
	for _, allocation := range allocations {
		if !nativeNAT64AllocationReady(allocation, transport) || !nativeNAT64AddressIn(allocation.Source, networks) ||
			!nativeNAT64SourceSelector(rule.From, packet.iface, packet.mac, allocation.Source) {
			continue
		}
		return true
	}
	return false
}

func nativeNAT64AllocationReady(allocation policy.NAT64Allocation, transport *nativeNAT64Transport) bool {
	if transport == nil {
		return false
	}
	for _, mapping := range transport.mappings {
		if mapping.Source == allocation.Source {
			return mapping.Ready && mapping.Alias == allocation.Alias
		}
	}
	// Allocator-created mappings are not part of the build-time retained list.
	// Their ledger still needs a live supervisor proof and current owner or
	// directory authority before any token can be published.
	return true
}

func nativeNAT64OwnedContext(packet nativePacketContext, set *nativeRuleSet, address policy.OwnedAddress) bool {
	if packet.iface != address.Interface || packet.family != 0 && packet.family != 6 || packet.source != nil {
		return false
	}
	if packet.mac != "" {
		return packet.mac == address.MAC
	}
	return !slices.Contains(nativeContextMACs(set, packet.iface), address.MAC)
}

func nativeNAT64SourceSelector(selectors []policy.NetworkSelector, iface, mac string, address netip.Addr) bool {
	for _, source := range selectors {
		if source.Interface != "" && source.Interface != iface || source.MAC != "" && source.MAC != mac {
			continue
		}
		if len(source.Addresses) == 0 || nativeNAT64AddressIn(address, source.Addresses) {
			return true
		}
	}
	return false
}

func nativeNAT64AddressIn(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func compactNAT64TokenStates(states []nativeNAT64TokenState) []nativeNAT64TokenState {
	slices.SortFunc(states, compareNAT64TokenState)
	return slices.Compact(states)
}
