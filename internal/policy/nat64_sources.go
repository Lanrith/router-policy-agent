package policy

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// NAT64SourceMapping retains the IPv4 representation of a native IPv6 source.
// These allocations belong to NAT64, independently of NAT46 destination maps.
// Ready is root-owned mapping state and never supplies forwarding permission.
type NAT64SourceMapping struct {
	Source netip.Addr `json:"source"`
	Alias  netip.Addr `json:"alias"`
	Ready  bool       `json:"ready"`
}

func validateNAT64Sources(b Baseline) error {
	pools := []netip.Prefix{}
	count := 0
	for _, component := range b.NAT64 {
		if component.SourcePool == nil {
			if len(component.SourceMappings) != 0 {
				return errors.New("policy: NAT64 source mappings need their owned pool")
			}
			continue
		}
		pool := *component.SourcePool
		if b.NetworkModel == nil || !pool.IsValid() || !pool.Addr().Is4() || pool != pool.Masked() ||
			pool.Bits() < 16 || pool.Bits() > 30 || !validAddress(pool.Addr()) {
			return errors.New("policy: invalid named NAT64 source pool")
		}
		for _, other := range append(pools, b.NAT46Pools...) {
			if pool.Overlaps(other) {
				return errors.New("policy: NAT64 source pools overlap another translator")
			}
		}
		for _, zone := range b.Zones {
			for _, other := range zone.Networks {
				if pool.Overlaps(other) {
					return errors.New("policy: NAT64 source pool overlaps a native network")
				}
			}
		}
		pools = append(pools, pool)
		seenSource, seenAlias := map[netip.Addr]bool{}, map[netip.Addr]bool{}
		for _, mapping := range component.SourceMappings {
			count++
			if count > 4096 || !mapping.Source.Is6() || !validAddress(mapping.Source) ||
				!mapping.Alias.Is4() || !validAddress(mapping.Alias) || !pool.Contains(mapping.Alias) ||
				seenSource[mapping.Source] || seenAlias[mapping.Alias] ||
				mapping.Alias == pool.Addr() || mapping.Alias == pool.Addr().Next() ||
				mapping.Alias == lastPoolAddress(pool) {
				return errors.New("policy: invalid or duplicate NAT64 source allocation")
			}
			for _, translator := range b.NAT64 {
				if translator.Prefix.Contains(mapping.Source) {
					return errors.New("policy: NAT64 source identity must be native IPv6")
				}
			}
			if wellKnownPrefix.Contains(mapping.Source) {
				return errors.New("policy: NAT64 source identity cannot be a translation prefix")
			}
			seenSource[mapping.Source], seenAlias[mapping.Alias] = true, true
		}
	}
	return nil
}

func lastPoolAddress(pool netip.Prefix) netip.Addr {
	address := pool.Addr().As4()
	value := binary.BigEndian.Uint32(address[:])
	value |= ^uint32(0) >> pool.Bits()
	binary.BigEndian.PutUint32(address[:], value)
	return netip.AddrFrom4(address)
}

func sourcePoolContains(b Baseline, address netip.Addr) bool {
	for _, component := range b.NAT64 {
		if component.SourcePool != nil && component.SourcePool.Contains(address) {
			return true
		}
	}
	return false
}
