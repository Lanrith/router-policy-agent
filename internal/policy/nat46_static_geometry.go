package policy

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
)

// MaximumNAT46StaticSources bounds the exact translated source identity field.
const MaximumNAT46StaticSources = 8191

// NAT46StaticSource is possible connectivity for one immutable source address.
// It is not a live binding or a grant.
type NAT46StaticSource struct {
	Interface string     `json:"interface"`
	Original  netip.Addr `json:"original"`
	Embedded  netip.Addr `json:"embedded"`
	ID        uint32     `json:"id"`
}

// NAT46StaticGeometrySnapshot describes possible source addresses independently
// of NAS or directory availability. Snapshots cannot publish configuration.
type NAT46StaticGeometrySnapshot struct {
	BaselineHash string              `json:"baseline_hash"`
	Prefix       netip.Prefix        `json:"prefix"`
	Sources      []NAT46StaticSource `json:"sources"`
}

// NAT46StaticGeometry owns a bounded projection of the validated compiler
// baseline. It supplies neither packet evidence nor permission. Publication
// also requires a matching current helper-local epoch proof. It cannot supply
// a configuration or source-ownership epoch itself.
type NAT46StaticGeometry struct{ data *NAT46StaticGeometrySnapshot }

// Snapshot returns an independent diagnostic copy, never positive evidence.
func (geometry NAT46StaticGeometry) Snapshot(ctx context.Context) (NAT46StaticGeometrySnapshot, error) {
	if ctx == nil || geometry.data == nil {
		return NAT46StaticGeometrySnapshot{}, errors.New("policy: missing static nat46 source geometry")
	}
	if err := ctx.Err(); err != nil {
		return NAT46StaticGeometrySnapshot{}, err
	}
	result := *geometry.data
	result.Sources = slices.Clone(result.Sources)
	return result, nil
}

// MarshalJSON rejects transport or persistence of the helper-local geometry.
func (geometry NAT46StaticGeometry) MarshalJSON() ([]byte, error) {
	return nil, errors.New("policy: static nat46 geometry evidence cannot be serialized")
}

type nativeIPv4Span struct{ first, last uint64 }

func nativeIPv4PrefixSpan(prefix netip.Prefix) nativeIPv4Span {
	raw := prefix.Addr().As4()
	first := uint64(binary.BigEndian.Uint32(raw[:]))
	return nativeIPv4Span{first: first, last: first + uint64(1)<<(32-prefix.Bits())}
}

func nativeIPv4Union(spans []nativeIPv4Span) []nativeIPv4Span {
	slices.SortFunc(spans, func(a, b nativeIPv4Span) int {
		if a.first < b.first {
			return -1
		}
		if a.first > b.first {
			return 1
		}
		if a.last < b.last {
			return -1
		}
		if a.last > b.last {
			return 1
		}
		return 0
	})
	result := []nativeIPv4Span{}
	for _, span := range spans {
		if span.first >= span.last {
			continue
		}
		if len(result) == 0 || result[len(result)-1].last < span.first {
			result = append(result, span)
		} else {
			result[len(result)-1].last = max(result[len(result)-1].last, span.last)
		}
	}
	return result
}

func nativeIPv4Subtract(spans, blocked []nativeIPv4Span) []nativeIPv4Span {
	result := []nativeIPv4Span{}
	for _, span := range spans {
		position := span.first
		for _, deny := range blocked {
			if deny.last <= position {
				continue
			}
			if deny.first >= span.last {
				break
			}
			if position < deny.first {
				result = append(result, nativeIPv4Span{first: position, last: min(deny.first, span.last)})
			}
			position = max(position, deny.last)
			if position >= span.last {
				break
			}
		}
		if position < span.last {
			result = append(result, nativeIPv4Span{first: position, last: span.last})
		}
	}
	return result
}

// CompileNAT46StaticGeometry bounds the possible source universe before
// enumerating addresses. Source/destination alternatives retain their actual
// attachments. This operation does not change access decisions or collect NAS
// evidence; the root helper must independently admit every packet.
func (compiler *Compiler) CompileNAT46StaticGeometry(ctx context.Context) (NAT46StaticGeometry, error) {
	if ctx == nil || compiler == nil || compiler.baseline.NetworkModel == nil || compiler.baseline.NetworkModel.NAT46Prefix == nil {
		return NAT46StaticGeometry{}, errors.New("policy: missing static nat46 source context or generated prefix")
	}
	if err := ctx.Err(); err != nil {
		return NAT46StaticGeometry{}, err
	}
	b := compiler.baseline
	attachments := map[string][]nativeIPv4Span{}
	owned := []nativeIPv4Span{}
	for _, zone := range b.Zones {
		for _, prefix := range zone.Networks {
			if !prefix.Addr().Is4() {
				continue
			}
			span := nativeIPv4PrefixSpan(prefix)
			owned = append(owned, span)
			if !b.DirectoryManaged(zone.Role) {
				for _, iface := range zone.Interfaces {
					attachments[iface] = append(attachments[iface], span)
				}
			}
		}
	}
	for _, prefix := range b.NetworkModel.ServicePrefixes {
		if prefix.Addr().Is4() {
			owned = append(owned, nativeIPv4PrefixSpan(prefix))
		}
	}
	for _, service := range b.NetworkModel.CoreServices {
		for _, address := range service.Addresses {
			if address.Is4() {
				owned = append(owned, nativeIPv4PrefixSpan(netip.PrefixFrom(address, 32)))
			}
		}
	}
	for _, path := range b.NetworkModel.CoreEgress {
		if path.Address.Is4() {
			owned = append(owned, nativeIPv4PrefixSpan(netip.PrefixFrom(path.Address, 32)))
		}
	}
	owned = nativeIPv4Union(owned)
	common := []nativeIPv4Span{}
	for _, raw := range []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"} {
		common = append(common, nativeIPv4PrefixSpan(netip.MustParsePrefix(raw)))
	}
	for _, block := range b.ProtectedNetworks {
		if block.ProtectionID == "P01" {
			for _, prefix := range block.Networks {
				if prefix.Addr().Is4() {
					common = append(common, nativeIPv4PrefixSpan(prefix))
				}
			}
		}
	}
	common = nativeIPv4Union(common)
	attachments[b.NetworkModel.UplinkInterface] = nativeIPv4Subtract([]nativeIPv4Span{{first: 0, last: 1 << 32}}, owned)
	eligible := map[string][]nativeIPv4Span{}
	for _, rule := range b.NetworkModel.Rules {
		if err := ctx.Err(); err != nil {
			return NAT46StaticGeometry{}, err
		}
		if rule.Action != "allow" || rule.Family == 6 || rule.Protocol == "icmpv6" {
			continue
		}
		reachable := false
		for _, mapping := range b.NAT46 {
			if mapping.Ready {
				logical := b.peerInterface(mapping.Target)
				for _, service := range b.NetworkModel.CoreServices {
					if slices.Contains(service.Addresses, mapping.Target) {
						logical = service.Interface
					}
				}
				reachable = reachable || matchesNetworkEndpoint(rule.To, mapping.Alias, mapping.Target, "nat46", logical, "", false)
			}
		}
		if !reachable {
			continue
		}
		for _, source := range rule.From {
			for iface, geometry := range attachments {
				if source.Interface != "" && source.Interface != iface {
					continue
				}
				for _, prefix := range nat46IPv4Alternatives(source.Addresses) {
					selected := nativeIPv4Span{first: 0, last: 1 << 32}
					if prefix.IsValid() {
						selected = nativeIPv4PrefixSpan(prefix)
					}
					for _, attachment := range geometry {
						span := nativeIPv4Span{first: max(selected.first, attachment.first), last: min(selected.last, attachment.last)}
						if span.first < span.last {
							eligible[iface] = append(eligible[iface], span)
						}
					}
				}
			}
		}
	}
	interfaces := []string{}
	count := uint64(0)
	for iface, spans := range eligible {
		spans = nativeIPv4Subtract(nativeIPv4Union(spans), common)
		eligible[iface] = spans
		interfaces = append(interfaces, iface)
		for _, span := range spans {
			count += span.last - span.first
			if count > MaximumNAT46StaticSources {
				return NAT46StaticGeometry{}, errors.New("policy: static nat46 source geometry exceeds identity capacity")
			}
		}
	}
	slices.Sort(interfaces)
	result := NAT46StaticGeometrySnapshot{BaselineHash: compiler.hash, Prefix: *b.NetworkModel.NAT46Prefix}
	// The exact union has been bounded before allocating individual identities.
	for _, iface := range interfaces {
		for _, span := range eligible[iface] {
			for value := span.first; value < span.last; value++ {
				if err := ctx.Err(); err != nil {
					return NAT46StaticGeometry{}, err
				}
				var raw [4]byte
				binary.BigEndian.PutUint32(raw[:], uint32(value)) // #nosec G115 -- IPv4 spans are half-open inside [0, 2^32).
				address := netip.AddrFrom4(raw)
				embedded := result.Prefix.Addr().As16()
				copy(embedded[12:], raw[:])
				result.Sources = append(result.Sources, NAT46StaticSource{Interface: iface, Original: address, Embedded: netip.AddrFrom16(embedded), ID: uint32(len(result.Sources) + 1)}) // #nosec G115 -- the union is bounded to 8191 addresses before this loop.
			}
		}
	}
	return NAT46StaticGeometry{data: &result}, ctx.Err()
}

func nat46IPv4Alternatives(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return []netip.Prefix{{}}
	}
	result := []netip.Prefix{}
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			result = append(result, prefix)
		}
	}
	return result
}
