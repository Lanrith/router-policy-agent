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
	if err != nil {
		return nil, errors.New("firewall: NAT64 token registry requires its original allocation ledger")
	}
	// A live translator can start before its first client. A validated empty
	// ledger reaches the same clear-only publication as any no-permit plan;
	// missing or foreign ledgers still reject above, and configuration below
	// remains mandatory before deriving any state.
	configuration, err := origin.configuration.Snapshot(ctx)
	if err != nil || configuration.BaselineHash != access.baselineHash || configuration.Epoch == 0 || configuration.Epoch > policy.MaximumOwnershipEpoch {
		return nil, errors.New("firewall: NAT64 token registry requires matching owner configuration")
	}

	states, err := origin.pathStates(ctx, utc, allocations, configuration.Epoch)
	if err != nil {
		return nil, err
	}
	if len(states) == 0 {
		return prepareNativeNAT64TokenClear(ctx, transport)
	}
	return newNativeNAT64Tokens(ctx, transport, states)
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
	if transport == nil || rule.Action != "allow" || rule.Family == 4 ||
		!slices.Contains([]string{"any", "tcp", "udp", "icmp", "icmpv6"}, rule.Protocol) {
		return false
	}
	for _, target := range rule.To {
		if target.Interface != "" && target.Interface != transport.component && !slices.Contains(transport.destinations, target.Interface) {
			continue
		}
		if len(target.Addresses) == 0 {
			return true
		}
		for _, prefix := range target.Addresses {
			if prefix.Addr().Is6() && prefix.Overlaps(transport.prefix) && (target.Interface == "" || target.Interface == transport.component) ||
				prefix.Addr().Is4() && target.Interface != transport.component {
				return true
			}
		}
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
