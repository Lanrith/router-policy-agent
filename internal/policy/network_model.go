package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// NetworkModel opts into named network geometry and an ordered router-owned
// ceiling. It never supplies a directory grant or a live address binding.
// ControllerInitiators are deliberately incompatible: partial owner rules must
// remain in the router's ordered access program, not become whole-zone rights.
type NetworkModel struct {
	SchemaVersion     int               `json:"schema_version"`
	ManagedNetworks   []Role            `json:"managed_networks"`
	UplinkInterface   string            `json:"uplink_interface"`
	Rules             []NetworkRule     `json:"rules"`
	CoreServices      []CoreService     `json:"core_services,omitempty"`
	CoreEgress        []CoreEgress      `json:"core_egress,omitempty"`
	AsymmetricReplies []AsymmetricReply `json:"asymmetric_replies,omitempty"`
	UplinkNAT         []UplinkNAT       `json:"uplink_nat,omitempty"`
	ServicePrefixes   []netip.Prefix    `json:"service_prefixes,omitempty"`
	NAT46Prefix       *netip.Prefix     `json:"nat46_prefix,omitempty"`
}

// NetworkSelector contains expanded interface and address constraints. Empty
// addresses select either family. A MAC constraint applies to sources only.
type NetworkSelector struct {
	Interface string         `json:"interface,omitempty"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	MAC       string         `json:"mac,omitempty"`
}

// NetworkRule retains first-match action, authorization, endpoint and transport
// scope. Display names are excluded. Runtime packet rules remain independently
// mandatory, including on translator legs and stateful replies.
type NetworkRule struct {
	Action        string            `json:"action"`
	Authorization string            `json:"authorization"`
	From          []NetworkSelector `json:"from"`
	To            []NetworkSelector `json:"to"`
	Protocol      string            `json:"protocol"`
	Ports         []uint16          `json:"ports,omitempty"`
	Family        int               `json:"family,omitempty"`
}

var networkName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

func validNetworkName(name Role) bool {
	return networkName.MatchString(string(name)) && name != Internet && name != Unknown && name != "any" && name != "uplink"
}

func decodeNetworkModel(data []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	raw, exists := object["network_model"]
	if !exists {
		return nil
	}
	if err := strictjson.Object(raw, []string{"schema_version", "managed_networks", "uplink_interface", "rules"}, []string{"core_services", "core_egress", "asymmetric_replies", "uplink_nat", "service_prefixes", "nat46_prefix"}, 2<<20); err != nil {
		return err
	}
	var model struct {
		Rules             []json.RawMessage `json:"rules"`
		CoreServices      []json.RawMessage `json:"core_services"`
		CoreEgress        []json.RawMessage `json:"core_egress"`
		AsymmetricReplies []json.RawMessage `json:"asymmetric_replies"`
		UplinkNAT         []json.RawMessage `json:"uplink_nat"`
	}
	if err := json.Unmarshal(raw, &model); err != nil {
		return err
	}
	if err := decodeCoreServices(model.CoreServices); err != nil {
		return err
	}
	if err := decodeCoreEgress(model.CoreEgress); err != nil {
		return err
	}
	if err := decodeAsymmetricReplies(model.AsymmetricReplies); err != nil {
		return err
	}
	if err := decodeUplinkNAT(model.UplinkNAT); err != nil {
		return err
	}
	for _, rule := range model.Rules {
		if err := strictjson.Object(rule, []string{"action", "authorization", "from", "to", "protocol"}, []string{"ports", "family"}, 2<<20); err != nil {
			return err
		}
		var endpoints struct {
			From []json.RawMessage `json:"from"`
			To   []json.RawMessage `json:"to"`
		}
		if err := json.Unmarshal(rule, &endpoints); err != nil {
			return err
		}
		for _, entries := range [][]json.RawMessage{endpoints.From, endpoints.To} {
			for _, entry := range entries {
				if err := strictjson.Object(entry, nil, []string{"interface", "addresses", "mac"}, 2<<20); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateNetworkModel(b Baseline) error {
	m := b.NetworkModel
	if m == nil {
		return nil
	}
	if m.SchemaVersion != 1 || m.ManagedNetworks == nil || len(m.ManagedNetworks) > 64 ||
		len(m.Rules) > 1024 || !safeInterface(m.UplinkInterface) || len(b.ControllerInitiators) != 0 {
		return errors.New("policy: invalid named network model or controller-wide permissions")
	}
	interfaces := map[string]bool{m.UplinkInterface: true}
	roles := map[Role]bool{}
	for _, zone := range b.Zones {
		roles[zone.Role] = true
		for _, name := range zone.Interfaces {
			if name == m.UplinkInterface {
				return errors.New("policy: uplink overlaps a named network")
			}
			interfaces[name] = true
		}
	}
	// In the shared model NAT64 IDs are their image-owned TUN names. NAT46 is
	// a single independently selected component with exact destination maps.
	for _, component := range b.NAT64 {
		if !safeInterface(component.ID) || interfaces[component.ID] {
			return errors.New("policy: ambiguous named translator interface")
		}
		interfaces[component.ID] = true
	}
	if len(b.NAT46Pools) != 0 {
		if interfaces["nat46"] {
			return errors.New("policy: ambiguous NAT46 interface")
		}
		interfaces["nat46"] = true
	}
	if err := validateCoreServices(b, interfaces); err != nil {
		return err
	}
	if err := validateCoreEgress(b, interfaces); err != nil {
		return err
	}
	if err := validateAsymmetricReplies(b, interfaces); err != nil {
		return err
	}
	if err := validateServicePrefixes(b); err != nil {
		return err
	}
	if err := validateNAT46Geometry(b); err != nil {
		return err
	}
	if err := validateUplinkNAT(b); err != nil {
		return err
	}
	managed := map[Role]bool{}
	for _, role := range m.ManagedNetworks {
		if !roles[role] || managed[role] {
			return errors.New("policy: unknown or duplicate managed network")
		}
		managed[role] = true
	}
	generated := 0
	for _, rule := range m.Rules {
		if rule.Action != "allow" && rule.Action != "deny" ||
			!slices.Contains([]string{"owner", "directory", "inherit"}, rule.Authorization) ||
			!slices.Contains([]string{"any", "tcp", "udp", "sctp", "icmp", "icmpv6", "gre", "esp", "ah"}, rule.Protocol) ||
			rule.Family != 0 && rule.Family != 4 && rule.Family != 6 || len(rule.Ports) > 64 {
			return errors.New("policy: invalid ordered network rule")
		}
		ports := map[uint16]bool{}
		for _, port := range rule.Ports {
			if port == 0 || ports[port] || !slices.Contains([]string{"tcp", "udp", "sctp"}, rule.Protocol) {
				return errors.New("policy: invalid ordered network ports")
			}
			ports[port] = true
		}
		for direction, entries := range [][]NetworkSelector{rule.From, rule.To} {
			if len(entries) == 0 || len(entries) > 256 {
				return errors.New("policy: ordered endpoint capacity outside bounds")
			}
			for _, endpoint := range entries {
				if endpoint.Interface != "" && !interfaces[endpoint.Interface] || len(endpoint.Addresses) > 256 {
					return errors.New("policy: undeclared ordered endpoint interface or capacity")
				}
				seen := map[netip.Prefix]bool{}
				for _, prefix := range endpoint.Addresses {
					if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || seen[prefix] {
						return errors.New("policy: invalid ordered endpoint prefix")
					}
					seen[prefix] = true
				}
				if endpoint.MAC != "" {
					mac, err := CanonicalMAC(endpoint.MAC)
					if err != nil || mac != endpoint.MAC || direction != 0 {
						return errors.New("policy: invalid ordered source MAC")
					}
				}
			}
		}
		generated += len(rule.From) * len(rule.To)
		if generated > 4096 {
			return errors.New("policy: expanded ordered network rule capacity exceeded")
		}
	}
	return nil
}

// DirectoryManaged reports the networks whose inherited permissions require
// a fresh grant. Explicit directory rules are independent of this selection.
func (b Baseline) DirectoryManaged(role Role) bool {
	if b.NetworkModel == nil {
		return role == Untrusted
	}
	return slices.Contains(b.NetworkModel.ManagedNetworks, role)
}

// DirectoryGrantNetwork reports the independently declared geometry on which
// a directory identity can supply grants. In the named model an explicit
// directory rule can select any declared network; the ordered ceiling still
// decides whether that particular flow needs a grant.
func (b Baseline) DirectoryGrantNetwork(role Role) bool {
	if b.NetworkModel == nil {
		return role == Untrusted
	}
	for _, zone := range b.Zones {
		if zone.Role == role {
			return true
		}
	}
	return false
}

func (compiler *Compiler) bindingRole(record binding.Record) Role {
	for _, zone := range compiler.baseline.Zones {
		if compiler.baseline.DirectoryGrantNetwork(zone.Role) && compiler.validBinding(record, zone.Role) {
			return zone.Role
		}
	}
	return Unknown
}

// ParseGroup validates named placements against this immutable baseline. The
// package-level parser retains the legacy wire contract for legacy callers.
func (compiler *Compiler) ParseGroup(raw string) (Document, error) {
	if compiler == nil {
		return Document{}, errors.New("policy: missing group compiler")
	}
	document, err := parseGroup(raw, compiler.baseline.NetworkModel != nil)
	if err != nil || compiler.baseline.NetworkModel == nil {
		return document, err
	}
	for _, zone := range compiler.baseline.Zones {
		if zone.Role == document.VLANRole {
			return document, nil
		}
	}
	return Document{}, errors.New("policy: directory group references an undeclared network")
}

type networkFlow struct {
	source, destination netip.Addr
	incoming, outgoing  string
	logicalDestination  netip.Addr
	logicalOutgoing     string
	mac                 string
}

func (b Baseline) peerInterface(address netip.Addr) string {
	for _, component := range b.NAT64 {
		if component.SourcePool != nil && component.SourcePool.Contains(address) {
			return component.ID
		}
		if component.Prefix.Contains(address) {
			return component.ID
		}
	}
	if inPrefixes(address, b.NAT46Pools) {
		return "nat46"
	}
	for _, zone := range b.Zones {
		if inPrefixes(address, zone.Networks) {
			// Shared model generation emits one actual interface per network.
			// Ambiguous multi-interface peers cannot authorize a named flow.
			if len(zone.Interfaces) == 1 {
				return zone.Interfaces[0]
			}
			return ""
		}
	}
	return b.NetworkModel.UplinkInterface
}

func matchesNetworkEndpoint(entries []NetworkSelector, address, logical netip.Addr, iface, logicalInterface, mac string, deny bool) bool {
	for _, endpoint := range entries {
		// A translator's attachment cannot borrow the address from the native
		// representation, or vice versa. Each alternative is one whole frame.
		if !matchesNetworkAttachment(endpoint, address, iface) &&
			!matchesNetworkAttachment(endpoint, logical, logicalInterface) {
			continue
		}
		if endpoint.MAC != "" && endpoint.MAC != mac {
			// A remote peer's Ethernet identity is unavailable to the logical
			// compiler. A conditional deny remains conservative; a conditional
			// permit cannot be established without that identity.
			if mac != "" || !deny {
				continue
			}
		}
		return true
	}
	return false
}

func matchesNetworkAttachment(endpoint NetworkSelector, address netip.Addr, iface string) bool {
	return address.IsValid() && (endpoint.Interface == "" || endpoint.Interface == iface) &&
		(len(endpoint.Addresses) == 0 || inPrefixes(address, endpoint.Addresses))
}

func (b Baseline) networkPermission(flow networkFlow, protocol string, port uint16) bool {
	family := 6
	if flow.source.Is4() {
		family = 4
	}
	for _, rule := range b.NetworkModel.Rules {
		deny := rule.Action == "deny"
		if rule.Protocol != "any" && rule.Protocol != protocol ||
			rule.Family != 0 && rule.Family != family ||
			len(rule.Ports) != 0 && !slices.Contains(rule.Ports, port) ||
			!matchesNetworkEndpoint(rule.From, flow.source, flow.source, flow.incoming, flow.incoming, flow.mac, deny) ||
			!matchesNetworkEndpoint(rule.To, flow.destination, flow.logicalDestination, flow.outgoing, flow.logicalOutgoing, "", deny) {
			continue
		}
		// A matched owner permission stays static; a delegated grant cannot
		// turn it into a second capability or fall through a terminal deny.
		if deny || rule.Authorization == "owner" {
			return false
		}
		return rule.Authorization == "directory" ||
			b.DirectoryManaged(roleFor(b, flow.source)) || b.DirectoryManaged(roleFor(b, flow.logicalDestination))
	}
	return false
}

func (compiler *Compiler) networkFloor(flow floorFlow, incoming string) string {
	b := compiler.baseline
	device, err := resolveEndpoint(b, flow.device)
	if err != nil {
		return "invalid_device_alias"
	}
	peer, err := resolveEndpoint(b, flow.peer)
	if err != nil {
		return "invalid_peer_alias"
	}
	// Grants describe real identities. An eligible original packet still
	// needs an ordered permission for its actual family and translator path.
	// Other representations are checked again by the router packet program.
	if flow.rule.Direction == FromDevice {
		for _, target := range peer.Variants {
			if target.Is4() == flow.device.Is4() && b.networkPermission(networkFlow{
				source: flow.device, destination: target, incoming: incoming,
				outgoing: b.peerInterface(target), mac: flow.mac,
				logicalDestination: flow.peer, logicalOutgoing: b.peerInterface(flow.peer),
			}, flow.rule.Protocol, flow.port) {
				return ""
			}
		}
	} else {
		for _, target := range device.Variants {
			if target.Is4() == flow.peer.Is4() && b.networkPermission(networkFlow{
				source: flow.peer, destination: target, incoming: b.peerInterface(flow.peer),
				outgoing:           b.peerInterface(target),
				logicalDestination: flow.device, logicalOutgoing: incoming,
			}, flow.rule.Protocol, flow.port) {
				return ""
			}
		}
	}
	return "no_ordered_directory_permission"
}

// A dual-stack policy describes reachable address pairs. An IPv4-only leg has
// no IPv6 packet to authorize unless the selected translator supplies that
// representation. Incompatible pairs must not discard valid native grants.
// Every compatible pair still passes all ordered rules and security guards.
func networkFamilyCompatible(device, peer Endpoint, direction Direction) bool {
	target, source := device, peer.Real
	if direction == FromDevice {
		target, source = peer, device.Real
	}
	for _, variant := range target.Variants {
		if variant.Is4() == source.Is4() {
			return true
		}
	}
	return false
}
