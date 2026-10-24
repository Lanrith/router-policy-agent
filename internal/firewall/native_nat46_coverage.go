package firewall

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

type nativeNAT46Span struct{ first, end uint64 }

func nativeNAT46SpanOf(prefix netip.Prefix) nativeNAT46Span {
	if !prefix.IsValid() {
		return nativeNAT46Span{end: uint64(1) << 32}
	}
	address := prefix.Masked().Addr().As4()
	first := uint64(binary.BigEndian.Uint32(address[:]))
	return nativeNAT46Span{first: first, end: first + uint64(1)<<(32-prefix.Bits())}
}

func nativeNAT46SourceSpans(rule policy.NetworkRule, original nativePacketContext) []nativeNAT46Span {
	result := []nativeNAT46Span{}
	for _, source := range rule.From {
		if source.Interface != "" && source.Interface != original.iface || source.MAC != "" && source.MAC != original.mac {
			continue
		}
		for _, prefix := range nativePrefixAlternatives(source.Addresses, 4) {
			result = append(result, nativeNAT46SpanOf(prefix))
		}
	}
	return result
}

// Remove only contexts whose complete source/listener product is already
// terminal under earlier rules for this exact mapping, ingress, MAC class and
// protocol. A directory requirement is terminal even without a grant. Partial
// coverage never removes a context; the runtime still evaluates every scope.
func (model *nativeNAT46Model) contextCovered(ctx context.Context, index, mapping int, original nativePacketContext, protocol string) (bool, error) {
	rule := model.rules.rules[index]
	sources := nativeNAT46SourceSpans(rule, original)
	ports := rule.Ports
	if len(ports) == 0 {
		// Zero represents the entire listener universe here. For this case
		// only earlier unrestricted listeners can prove full coverage.
		ports = []uint16{0}
	}
	for _, port := range ports {
		covered := []nativeNAT46Span{}
		for earlier := 0; earlier < index; earlier++ {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			prior := model.rules.rules[earlier]
			if prior.Family == 6 || prior.Protocol != "any" && prior.Protocol != protocol ||
				len(prior.Ports) != 0 && (port == 0 || !slices.Contains(prior.Ports, port)) ||
				!nativeNAT46Destination(prior.To, model.mappings[mapping], false) {
				continue
			}
			covered = append(covered, nativeNAT46SourceSpans(prior, original)...)
		}
		slices.SortFunc(covered, func(left, right nativeNAT46Span) int {
			if left.first < right.first {
				return -1
			}
			if left.first > right.first {
				return 1
			}
			if left.end < right.end {
				return -1
			}
			if left.end > right.end {
				return 1
			}
			return 0
		})
		for _, source := range sources {
			position := source.first
			for _, span := range covered {
				if span.first > position {
					break
				}
				if span.end > position {
					position = span.end
				}
				if position >= source.end {
					break
				}
			}
			if position < source.end {
				return false, nil
			}
		}
	}
	return len(sources) != 0, ctx.Err()
}
