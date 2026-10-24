package policy

import "errors"

// The generated source prefix is geometry, never a permission. Keeping it in
// the immutable model avoids deriving wire identities from a reader request or
// assuming another router's ULA. Older contract-only models may omit it; an
// enforcing translator must require the complete generated geometry.
func validateNAT46Geometry(b Baseline) error {
	selected := b.NetworkModel.NAT46Prefix
	if selected == nil {
		return nil
	}
	prefix := *selected
	if len(b.NAT46Pools) != 1 || len(b.NAT46) == 0 || !prefix.IsValid() ||
		!prefix.Addr().Is6() || prefix.Addr().Is4In6() || !prefix.Addr().IsPrivate() ||
		prefix.Addr().Zone() != "" || prefix.Bits() != 96 || prefix != prefix.Masked() {
		return errors.New("policy: invalid or disabled nat46 source geometry")
	}
	pool := b.NAT46Pools[0]
	for _, zone := range b.Zones {
		for _, other := range zone.Networks {
			if prefix.Overlaps(other) || pool.Overlaps(other) {
				return errors.New("policy: nat46 allocation overlaps a native attachment")
			}
		}
	}
	for _, other := range b.NetworkModel.ServicePrefixes {
		if prefix.Overlaps(other) || pool.Overlaps(other) {
			return errors.New("policy: nat46 allocation overlaps managed services")
		}
	}
	for _, component := range b.NAT64 {
		if prefix.Overlaps(component.Prefix) {
			return errors.New("policy: nat46 source prefix overlaps nat64")
		}
		for _, mapping := range component.SourceMappings {
			if prefix.Contains(mapping.Source) {
				return errors.New("policy: nat64 source would chain nat46 translation")
			}
		}
	}
	for _, mapping := range b.NAT46 {
		if prefix.Contains(mapping.Target) {
			return errors.New("policy: nat46 target would chain translation")
		}
	}
	for _, block := range b.ProtectedNetworks {
		if block.ProtectionID == "P01" {
			for _, other := range block.Networks {
				if prefix.Overlaps(other) || pool.Overlaps(other) {
					return errors.New("policy: nat46 allocation overlaps router or management")
				}
			}
		}
	}
	return nil
}
