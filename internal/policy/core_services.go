package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// CoreService is immutable generated core-service connectivity. Its listeners and
// client attachments do not grant directory capabilities or other services.
// The native packet program must independently enforce this exact geometry.
type CoreService struct {
	Kind      string            `json:"kind"`
	Interface string            `json:"interface"`
	Addresses []netip.Addr      `json:"addresses"`
	Clients   []NetworkSelector `json:"clients"`
}

func decodeCoreServices(raw []json.RawMessage) error {
	for _, service := range raw {
		if err := strictjson.Object(service, []string{"kind", "interface", "addresses", "clients"}, nil, 2<<20); err != nil {
			return err
		}
		var fields struct {
			Clients []json.RawMessage `json:"clients"`
		}
		if err := json.Unmarshal(service, &fields); err != nil {
			return err
		}
		for _, client := range fields.Clients {
			if err := strictjson.Object(client, []string{"interface", "addresses"}, nil, 2<<20); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCoreServices(b Baseline, interfaces map[string]bool) error {
	services := b.NetworkModel.CoreServices
	if len(services) > 6 {
		return errors.New("policy: core service capacity exceeded")
	}
	kinds := map[string]bool{}
	listeners := map[netip.Addr]bool{}
	link := ""
	clauses := 0
	for _, service := range services {
		if !slices.Contains([]string{"dns", "ntp", "authoritative", "discovery", "metrics", "radius"}, service.Kind) || kinds[service.Kind] || !safeInterface(service.Interface) || interfaces[service.Interface] || link != "" && link != service.Interface || len(service.Addresses) == 0 || len(service.Addresses) > 3 || len(service.Clients) == 0 || len(service.Clients) > 128 {
			return errors.New("policy: invalid or ambiguous core service geometry")
		}
		kinds[service.Kind], link = true, service.Interface
		for _, address := range service.Addresses {
			if listeners[address] {
				return errors.New("policy: duplicate core listener")
			}
			if err := validateCoreAddress(b, address); err != nil {
				return err
			}
			listeners[address] = true
		}
		sources := map[coreClientKey]bool{}
		for _, client := range service.Clients {
			if client.MAC != "" || client.Interface == "" || client.Interface == service.Interface || len(client.Addresses) == 0 || len(client.Addresses) > 256 {
				return errors.New("policy: core client requires a bounded ordinary attachment")
			}
			for _, prefix := range client.Addresses {
				if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
					return errors.New("policy: invalid core client prefix")
				}
				key := coreClientKey{iface: client.Interface, prefix: prefix}
				if sources[key] {
					return errors.New("policy: duplicate core client scope")
				}
				sources[key] = true
				attached := false
				for _, zone := range b.Zones {
					if !slices.Contains(zone.Interfaces, client.Interface) {
						continue
					}
					for _, network := range zone.Networks {
						attached = attached || network.Addr().BitLen() == prefix.Addr().BitLen() && network.Bits() <= prefix.Bits() && network.Contains(prefix.Addr())
					}
				}
				reachable := false
				for _, address := range service.Addresses {
					reachable = reachable || address.Is4() == prefix.Addr().Is4()
				}
				if !attached || !reachable {
					return errors.New("policy: core client is outside its declared attachment or listener family")
				}
				clauses++
				if clauses > 1024 {
					return errors.New("policy: expanded core service capacity exceeded")
				}
			}
		}
	}
	return nil
}

type coreClientKey struct {
	iface  string
	prefix netip.Prefix
}

func validateCoreAddress(b Baseline, address netip.Addr) error {
	protected := false
	for _, block := range b.ProtectedNetworks {
		if !inPrefixes(address, block.Networks) {
			continue
		}
		if block.ProtectionID == "P01" {
			return errors.New("policy: core listener overlaps router or management protection")
		}
		protected = protected || block.ProtectionID == "P03"
	}
	if !validAddress(address) || address.Is4In6() || address.Zone() != "" || !protected {
		return errors.New("policy: core listener requires its protected service allocation")
	}
	for _, zone := range b.Zones {
		if inPrefixes(address, zone.Networks) {
			return errors.New("policy: core listener overlaps client geometry")
		}
	}
	for _, translator := range b.NAT64 {
		if translator.Prefix.Contains(address) || translator.SourcePool != nil && translator.SourcePool.Contains(address) {
			return errors.New("policy: core listener overlaps translation geometry")
		}
	}
	if inPrefixes(address, b.NAT46Pools) {
		return errors.New("policy: core listener overlaps NAT46 geometry")
	}
	return nil
}

// Service allocation geometry is distinct from delegation ceilings. Both may
// occur in P03, but only the declared service ranges exclude physical sources.
func validateServicePrefixes(b Baseline) error {
	prefixes := b.NetworkModel.ServicePrefixes
	if len(prefixes) > 8 {
		return errors.New("policy: service allocation capacity exceeded")
	}
	addresses := []netip.Addr{}
	for _, service := range b.NetworkModel.CoreServices {
		addresses = append(addresses, service.Addresses...)
	}
	for _, path := range b.NetworkModel.CoreEgress {
		addresses = append(addresses, path.Address)
	}
	for index, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return errors.New("policy: invalid service allocation")
		}
		for _, other := range prefixes[:index] {
			if prefix.Overlaps(other) {
				return errors.New("policy: overlapping service allocations")
			}
		}
		declared := false
		for _, block := range b.ProtectedNetworks {
			if block.ProtectionID == "P03" {
				declared = declared || slices.Contains(block.Networks, prefix)
			}
		}
		if !declared {
			return errors.New("policy: service allocation requires an exact protected range")
		}
		for _, zone := range b.Zones {
			for _, network := range zone.Networks {
				if prefix.Overlaps(network) {
					return errors.New("policy: service allocation overlaps an ordinary attachment")
				}
			}
		}
		for _, component := range b.NAT64 {
			if prefix.Overlaps(component.Prefix) || component.SourcePool != nil && prefix.Overlaps(*component.SourcePool) {
				return errors.New("policy: service allocation overlaps translation")
			}
		}
		for _, pool := range b.NAT46Pools {
			if prefix.Overlaps(pool) {
				return errors.New("policy: service allocation overlaps NAT46")
			}
		}
	}
	if len(prefixes) != 0 {
		for _, address := range addresses {
			if !inPrefixes(address, prefixes) {
				return errors.New("policy: component outside declared service allocations")
			}
		}
	}
	return nil
}
