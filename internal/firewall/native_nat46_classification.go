package firewall

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/state"
)

// translatedClassification extends only deny history, using this model's owned
// root geometry. The original persisted history is unchanged. A real IPv4
// identity also closes its embedded IPv6 representation; a classified mapped
// IPv6 target closes its alias and that alias's embedded representation. None
// of these entries supplies current ownership, a source ID or a grant.
func (model *nativeNAT46Model) translatedClassification(ctx context.Context, history state.Classification) (state.Classification, error) {
	if ctx == nil || model == nil || !model.prefix.IsValid() || !model.prefix.Addr().Is6() || model.prefix.Bits() != 96 {
		return state.Classification{}, errors.New("firewall: missing nat46 classification geometry")
	}
	if err := ctx.Err(); err != nil {
		return state.Classification{}, err
	}
	owned, err := state.CloneClassification(history)
	if err != nil {
		return state.Classification{}, err
	}
	for _, mapping := range model.mappings {
		if err := ctx.Err(); err != nil {
			return state.Classification{}, err
		}
		if _, found := slices.BinarySearch(owned.IPv6, mapping.target.String()); found {
			owned.IPv4 = append(owned.IPv4, mapping.alias.String())
		}
	}
	slices.Sort(owned.IPv4)
	owned.IPv4 = slices.Compact(owned.IPv4)
	for _, raw := range owned.IPv4 {
		if err := ctx.Err(); err != nil {
			return state.Classification{}, err
		}
		source, err := netip.ParseAddr(raw)
		if err != nil || !source.Is4() {
			return state.Classification{}, errors.New("firewall: invalid nat46 classification source")
		}
		embedded := nativeNAT46SourcePrefix(model.prefix, netip.PrefixFrom(source, 32)).Addr()
		owned.IPv6 = append(owned.IPv6, embedded.String())
	}
	slices.Sort(owned.IPv6)
	owned.IPv6 = slices.Compact(owned.IPv6)
	// Recheck the final per-family bounds, canonical order and cohort anchor.
	return state.CloneClassification(owned)
}
