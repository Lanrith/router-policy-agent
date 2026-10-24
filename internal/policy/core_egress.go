package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// CoreEgress describes a generated service dependency, never an owner access
// rule. Kind fixes the protocol and listener: recursive DNS (TCP/UDP 53), NTP
// (UDP 123), NTP's numeric DNS fallback (TCP/UDP 53), RADIUS proxying
// (UDP 1812), or log export (TCP 443).
// TranslatedAddresses are exact immutable uplink addresses when Masquerade is
// true. An empty list represents dynamic uplink addressing; activating that
// geometry additionally requires a qualified live uplink-address producer.
type CoreEgress struct {
	Kind                 string         `json:"kind"`
	Interface            string         `json:"interface"`
	DestinationInterface string         `json:"destination_interface,omitempty"`
	Address              netip.Addr     `json:"address"`
	Destinations         []netip.Prefix `json:"destinations"`
	Masquerade           bool           `json:"masquerade"`
	TranslatedAddresses  []netip.Addr   `json:"translated_addresses,omitempty"`
}

func decodeCoreEgress(raw []json.RawMessage) error {
	for _, path := range raw {
		if err := strictjson.Object(path, []string{"kind", "interface", "address", "destinations", "masquerade"}, []string{"destination_interface", "translated_addresses"}, 2<<20); err != nil {
			return err
		}
	}
	return nil
}

func validateCoreEgress(b Baseline, interfaces map[string]bool) error {
	paths := b.NetworkModel.CoreEgress
	if len(paths) > 32 {
		return errors.New("policy: core dependency capacity exceeded")
	}
	link := ""
	for _, service := range b.NetworkModel.CoreServices {
		link = service.Interface
	}
	seen := map[struct {
		kind    string
		address netip.Addr
	}]bool{}
	sourceKinds := map[netip.Addr]string{}
	count := 0
	for _, path := range paths {
		key := struct {
			kind    string
			address netip.Addr
		}{path.Kind, path.Address}
		component := path.Kind
		switch component {
		case "ntp_dns":
			component = "ntp"
		case "radius_proxy":
			component = "radius"
		case "logs":
			component = "logs"
		}
		isInternal := path.Kind == "radius_proxy" || path.Kind == "logs"
		if !slices.Contains([]string{"dns", "ntp", "ntp_dns", "radius_proxy", "logs"}, path.Kind) || seen[key] || !safeInterface(path.Interface) || interfaces[path.Interface] || link != "" && path.Interface != link || len(path.Destinations) == 0 || len(path.Destinations) > 16 || len(path.TranslatedAddresses) > 8 || !path.Masquerade && len(path.TranslatedAddresses) != 0 || isInternal != (path.DestinationInterface != "") || isInternal && (!safeInterface(path.DestinationInterface) || !interfaces[path.DestinationInterface] || path.Masquerade) {
			return errors.New("policy: invalid or ambiguous core dependency")
		}
		seen[key], link = true, path.Interface
		if err := validateCoreAddress(b, path.Address); err != nil {
			return err
		}
		if previous, exists := sourceKinds[path.Address]; exists && previous != component {
			return errors.New("policy: core components share a source identity")
		}
		sourceKinds[path.Address] = component
		for _, service := range b.NetworkModel.CoreServices {
			if slices.Contains(service.Addresses, path.Address) && service.Kind != component {
				return errors.New("policy: dependency borrows another core listener")
			}
			if service.Kind == component && !slices.Contains(service.Addresses, path.Address) {
				return errors.New("policy: dependency source is outside its component allocation")
			}
		}
		destinations := map[netip.Prefix]bool{}
		for _, prefix := range path.Destinations {
			exactDestination := path.Kind == "ntp_dns" || isInternal
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().BitLen() != path.Address.BitLen() || destinations[prefix] || exactDestination && prefix.Bits() != prefix.Addr().BitLen() || !exactDestination && prefix.Bits() != 0 {
				return errors.New("policy: invalid core dependency destination")
			}
			if path.Kind == "ntp_dns" {
				if !validAddress(prefix.Addr()) {
					return errors.New("policy: invalid numeric NTP resolver")
				}
				for _, zone := range b.Zones {
					if inPrefixes(prefix.Addr(), zone.Networks) {
						return errors.New("policy: fallback resolver requires uplink reachability")
					}
				}
				for _, block := range b.ProtectedNetworks {
					if inPrefixes(prefix.Addr(), block.Networks) {
						return errors.New("policy: fallback resolver overlaps a protected allocation")
					}
				}
			}
			if isInternal {
				attached := false
				for _, zone := range b.Zones {
					if slices.Contains(zone.Interfaces, path.DestinationInterface) && inPrefixes(prefix.Addr(), zone.Networks) {
						attached = true
					}
				}
				if !attached {
					return errors.New("policy: internal service target is outside its declared attachment")
				}
			}
			destinations[prefix] = true
		}
		translated := map[netip.Addr]bool{}
		for _, address := range path.TranslatedAddresses {
			protected := false
			for _, block := range b.ProtectedNetworks {
				if block.ProtectionID == "P01" {
					for _, prefix := range block.Networks {
						protected = protected || prefix.Bits() == address.BitLen() && prefix.Contains(address)
					}
				}
			}
			if !validAddress(address) || address.Is4In6() || address.Zone() != "" || address.Is4() != path.Address.Is4() || translated[address] || !protected {
				return errors.New("policy: translated core source requires an exact router uplink address")
			}
			for _, zone := range b.Zones {
				if inPrefixes(address, zone.Networks) {
					return errors.New("policy: translated core source overlaps a client allocation")
				}
			}
			for _, block := range b.ProtectedNetworks {
				if block.ProtectionID == "P03" && inPrefixes(address, block.Networks) {
					return errors.New("policy: translated core source overlaps a service allocation")
				}
			}
			translated[address] = true
		}
		count += len(path.Destinations) * max(1, len(path.TranslatedAddresses))
		if count > 256 {
			return errors.New("policy: expanded core dependency capacity exceeded")
		}
	}
	return nil
}
