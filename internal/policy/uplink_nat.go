package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// UplinkNAT is generated source translation geometry, not permission. Sources
// remain behind the ordered access program and current source/grant guards.
// An empty Addresses list records dynamic WAN addressing without inventing
// positive address evidence; runtime activation requires a qualified producer.
type UplinkNAT struct {
	Interface string         `json:"interface"`
	Sources   []netip.Prefix `json:"sources"`
	Addresses []netip.Addr   `json:"addresses"`
}

func decodeUplinkNAT(raw []json.RawMessage) error {
	for _, path := range raw {
		if err := strictjson.Object(path, []string{"interface", "sources", "addresses"}, nil, 2<<20); err != nil {
			return err
		}
	}
	return nil
}

func validateUplinkNAT(b Baseline) error {
	paths := b.NetworkModel.UplinkNAT
	if len(paths) > 64 {
		return errors.New("policy: uplink source NAT capacity exceeded")
	}
	seen := map[string]bool{}
	var expected []netip.Addr
	count := 0
	for index, path := range paths {
		if !safeInterface(path.Interface) || path.Interface == b.NetworkModel.UplinkInterface || seen[path.Interface] || len(path.Sources) == 0 || len(path.Sources) > 256 || len(path.Addresses) > 8 {
			return errors.New("policy: invalid uplink source NAT attachment")
		}
		seen[path.Interface] = true
		addresses := slices.Clone(path.Addresses)
		slices.SortFunc(addresses, netip.Addr.Compare)
		if index == 0 {
			expected = addresses
		} else if !slices.Equal(expected, addresses) {
			return errors.New("policy: ambiguous uplink source NAT addresses")
		}
		for i, address := range addresses {
			protected := false
			for _, block := range b.ProtectedNetworks {
				if block.ProtectionID == "P01" {
					for _, prefix := range block.Networks {
						protected = protected || prefix.Bits() == 32 && prefix.Contains(address)
					}
				}
			}
			if !validAddress(address) || !address.Is4() || !protected || i > 0 && addresses[i-1] == address {
				return errors.New("policy: source NAT requires exact IPv4 uplink addresses")
			}
			for _, zone := range b.Zones {
				if inPrefixes(address, zone.Networks) {
					return errors.New("policy: uplink source NAT address overlaps a client allocation")
				}
			}
			for _, block := range b.ProtectedNetworks {
				if block.ProtectionID == "P03" && inPrefixes(address, block.Networks) {
					return errors.New("policy: uplink source NAT address overlaps a protected service allocation")
				}
			}
		}
		sources := slices.Clone(path.Sources)
		slices.SortFunc(sources, func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		for i, prefix := range sources {
			if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 || i > 0 && sources[i-1].Overlaps(prefix) {
				return errors.New("policy: invalid or overlapping uplink source NAT scopes")
			}
			attached := false
			for _, zone := range b.Zones {
				if !slices.Contains(zone.Interfaces, path.Interface) {
					continue
				}
				for _, network := range zone.Networks {
					attached = attached || network.Addr().Is4() && network.Bits() <= prefix.Bits() && network.Contains(prefix.Addr())
				}
			}
			if !attached {
				return errors.New("policy: uplink source NAT scope is outside its ordinary attachment")
			}
			count++
			if count > 1024 {
				return errors.New("policy: expanded uplink source NAT capacity exceeded")
			}
		}
	}
	return nil
}
