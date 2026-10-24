package firewall

import (
	"context"
	"errors"
	"os"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// refreshOwnership shares the complete floor/writer/executor fence with grant
// updates. It does not read a directory, restore a snapshot or renew a grant.
// A failed observation leaves no positive ownership evidence in the kernel.
func (b *guardedBackend) refreshOwnership(ctx context.Context, evidence policy.Ownership) (result error) {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing named ownership backend")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	if !b.options.profile.layout.ownership {
		return errors.New("firewall: ownership refresh requires named model")
	}
	defer func() {
		if result != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*commandTimeout)
			defer cancel()
			result = errors.Join(result, b.clearOwnership(cleanup))
		}
	}()
	var post []byte
	var publication *nativeSourcePublication
	if err := b.options.generation.with(ctx, b.options.expected, func(bounded context.Context) error {
		p := b.options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		observation, err := p.observeProfile(bounded, b.options.profile)
		if err != nil {
			return err
		}
		prepare := b.options.profile.renderer.prepareOwnership
		if b.options.profile.layout.native != nil {
			prepare = b.options.profile.renderer.prepareNativeOwnership
		}
		prepared, err := prepare(bounded, evidence, b.options.clock())
		if err != nil {
			return err
		}
		if b.options.profile.layout.native != nil {
			if sources := b.options.profile.layout.nat46Sources(); sources != nil {
				prepared, err = prepareNativeNAT46SourceRefresh(bounded, prepared, b.nativeOwnership, observation.guards.sourceEpoch, sources.model)
				if err == nil {
					if transports := b.options.profile.layout.native.selectedNAT64Transports(); len(transports) != 0 {
						prepared, err = attachNativeNAT64SourceMode(bounded, prepared, transports)
					}
				}
			} else if transports := b.options.profile.layout.native.selectedNAT64Transports(); len(transports) != 0 {
				prepared, err = prepareNativeNAT64AggregateSourceRefresh(bounded, prepared, b.nativeOwnership, observation.guards.sourceEpoch, transports)
			} else {
				prepared, err = prepareNativeSourceRefresh(bounded, prepared, b.nativeOwnership, observation.guards.sourceEpoch)
			}
			if err != nil {
				return err
			}
			// Do not let an intervening grant update use the previous, possibly
			// longer source deadline while the new observation is unverified.
			b.nativeOwnership, b.pendingNativeOwnership = nil, nil
		}
		if _, err := p.run(bounded, commandInput{op: applyOwnership, ownership: prepared}); err != nil {
			return err
		}
		post, err = p.run(bounded, commandInput{op: inspectWholeRuleset})
		if err != nil {
			return err
		}
		if b.options.profile.layout.native != nil {
			publication, err = nativeSourceReceipt(bounded, prepared)
			if err != nil {
				return err
			}
			b.pendingNativeOwnership = publication
		}
		return nil
	}); err != nil {
		return err
	}
	// The listing was captured under the full writer/executor fence. Parsing
	// that immutable snapshot does not need to consume the writer's deadline.
	// No positive source receipt is available to grant writers during parsing.
	if _, err := b.options.profile.ruleset.inspect(ctx, b.options.profile.layout, post); err != nil {
		return err
	}
	if publication != nil {
		if err := b.options.generation.with(ctx, b.options.expected, func(bounded context.Context) error {
			if b.pendingNativeOwnership != publication {
				return errors.New("firewall: source publication changed during verification")
			}
			// A source clear or another publication invalidates pending state.
			// Every later grant update also inspects the current whole profile
			// and checks its source epoch against this original opaque receipt.
			b.nativeOwnership, b.pendingNativeOwnership = publication, nil
			return bounded.Err()
		}); err != nil {
			return err
		}
		if b.options.profile.layout.nat46Sources() != nil {
			if err := b.publishNAT46SourceEpoch(ctx, publication); err != nil {
				return err
			}
		}
		if b.options.profile.layout.native != nil && len(b.options.profile.layout.native.selectedNAT64Transports()) != 0 && b.hasNAT64Origins() {
			if err := b.refreshNAT64Tokens(ctx, publication); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// Revocation requires exact code-owned objects and the shared fence, but not
// a ready generation, safe clock or unchanged external floor. It cannot renew
// anything, including a still-valid ownership tuple.
func (b *guardedBackend) clearOwnership(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing ownership revocation dependencies")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	if !b.options.profile.layout.ownership {
		return errors.New("firewall: ownership revocation requires named model")
	}
	var post guardListings
	if err := b.options.generation.fence.With(ctx, func(bounded context.Context, _ *os.Root) error {
		b.nativeOwnership, b.pendingNativeOwnership = nil, nil
		p := b.options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		data, err := p.run(bounded, commandInput{op: inspectWholeRuleset})
		if err != nil {
			return err
		}
		// This deliberately ignores content/mirror consistency: damaged or
		// expired positive evidence must remain revocable. Shape stays fixed.
		if _, _, err := inspectSealingGuards(bounded, b.options.profile.layout, data); err != nil {
			return err
		}
		prepare := prepareOwnershipClear
		if b.options.profile.layout.native != nil {
			prepare = prepareNativeOwnershipClear
		}
		prepared, err := prepare(bounded)
		if sources := b.options.profile.layout.nat46Sources(); sources != nil {
			prepared, err = prepareNativeNAT46OwnershipClear(bounded, sources.model)
			if err == nil && b.options.profile.layout.native != nil {
				if transports := b.options.profile.layout.native.selectedNAT64Transports(); len(transports) != 0 {
					prepared, err = attachNativeNAT64SourceMode(bounded, prepared, transports)
				}
			}
		} else if b.options.profile.layout.native != nil {
			if transports := b.options.profile.layout.native.selectedNAT64Transports(); len(transports) != 0 {
				prepared, err = prepareNativeNAT64AggregateOwnershipClear(bounded, transports)
			}
		}
		if err != nil {
			return err
		}
		if _, err := p.run(bounded, commandInput{op: applyOwnership, ownership: prepared}); err != nil {
			return err
		}
		post.inet, err = p.run(bounded, commandInput{op: inspectOwned})
		if err != nil {
			return err
		}
		post.netdev, err = p.run(bounded, commandInput{op: inspectGuardEgress})
		return err
	}); err != nil {
		return err
	}
	if err := inspectOwnershipClear(ctx, b.options.profile.layout, post); err != nil {
		return err
	}
	if b.options.profile.layout.native != nil && len(b.options.profile.layout.native.selectedNAT64Transports()) != 0 && b.hasNAT64Origins() {
		return b.refreshNAT64Tokens(ctx, nil)
	}
	return ctx.Err()
}

func inspectOwnershipClear(ctx context.Context, layout *guardLayout, listing guardListings) error {
	for _, item := range []struct {
		family string
		data   []byte
	}{{"inet", listing.inet}, {"netdev", listing.netdev}} {
		observed, err := layout.inspectTable(ctx, item.family, item.data)
		if err != nil {
			return err
		}
		for _, name := range []string{ownership4Set, ownership6Set} {
			if len(observed.sets[name].Elements) != 0 {
				return errors.New("firewall: positive ownership remained after revocation")
			}
		}
		if item.family == "inet" && (len(observed.sets[ownershipEpochSet].Elements) != 0 ||
			len(observed.sets[ownershipEpochMap].Elements) != 0) {
			return errors.New("firewall: positive ownership epoch remained after revocation")
		}
		if layout.native != nil {
			for _, ref := range nativeIDLeaseRefs() {
				if ref.Family == item.family && len(observed.sets[ref.Name].Elements) != 0 {
					return errors.New("firewall: native ID grant remained after source revocation")
				}
			}
			for _, ref := range nativeSourceReferences() {
				if ref.Family == item.family && len(observed.sets[ref.Name].Elements) != 0 {
					return errors.New("firewall: native source identity remained after revocation")
				}
			}
		}
		if layout.nat46Sources() != nil {
			for _, ref := range nativeNAT46TargetGrantRefs() {
				if ref.Family == item.family && len(observed.sets[ref.Name].Elements) != 0 {
					return errors.New("firewall: nat46 target grant remained after source revocation")
				}
			}
			if len(observed.sets[nativeNAT46StaticSourceLive].Elements) != 0 || item.family == "inet" && len(observed.sets[nativeNAT46StaticSourceChannel].Elements) != 0 {
				return errors.New("firewall: nat46 source epoch remained after revocation")
			}
		}
		if layout.native != nil && len(layout.native.selectedNAT64Transports()) != 0 {
			for _, ref := range nativeNAT64GrantRefs() {
				if ref.Family == item.family && len(observed.sets[ref.Name].Elements) != 0 {
					return errors.New("firewall: NAT64 delegated grant remained after source revocation")
				}
			}
		}
		mapping, set := epochChannelNames(false)
		if item.family == "inet" && len(observed.sets[mapping].Elements) != 0 ||
			item.family == "netdev" && len(observed.sets[set].Elements) != 0 {
			return errors.New("firewall: physical ownership epoch remained after revocation")
		}
	}
	return ctx.Err()
}
