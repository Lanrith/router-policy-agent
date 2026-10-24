package firewall

import (
	"context"
	"errors"
	"os"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Static configuration is published only against the same pinned profile,
// ready generation and writer fence as physical ownership and directory grants.
func (b *guardedBackend) refreshConfiguration(ctx context.Context, evidence policy.OwnerConfiguration) (result error) {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing configuration backend dependencies")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	if !b.options.profile.layout.ownership {
		return errors.New("firewall: configuration epoch requires named model")
	}
	defer func() {
		if result != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*commandTimeout)
			defer cancel()
			result = errors.Join(result, b.clearConfiguration(cleanup))
		}
	}()
	var post []byte
	if err := b.options.generation.with(ctx, b.options.expected, func(bounded context.Context) error {
		p := b.options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		if _, err := p.observeProfile(bounded, b.options.profile); err != nil {
			return err
		}
		prepared, err := b.options.profile.renderer.prepareConfiguration(bounded, evidence)
		if sources := b.options.profile.layout.nat46Sources(); sources != nil {
			prepared, err = b.options.profile.renderer.prepareNativeNAT46Configuration(bounded, evidence, sources)
		}
		if err != nil {
			return err
		}
		if _, err := p.run(bounded, commandInput{op: applyConfiguration, configuration: prepared}); err != nil {
			return err
		}
		post, err = p.run(bounded, commandInput{op: inspectWholeRuleset})
		return err
	}); err != nil {
		return err
	}
	_, err := b.options.profile.ruleset.inspect(ctx, b.options.profile.layout, post)
	return err
}

func (b *guardedBackend) clearConfiguration(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing configuration revocation dependencies")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	if !b.options.profile.layout.ownership {
		return errors.New("firewall: configuration revocation requires named model")
	}
	var post guardListings
	if err := b.options.generation.fence.With(ctx, func(bounded context.Context, _ *os.Root) error {
		p := b.options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		data, err := p.run(bounded, commandInput{op: inspectWholeRuleset})
		if err != nil {
			return err
		}
		if _, _, err := inspectSealingGuards(bounded, b.options.profile.layout, data); err != nil {
			return err
		}
		prepared, err := prepareConfigurationClear(bounded)
		if b.options.profile.layout.nat46Sources() != nil {
			prepared, err = prepareNativeNAT46ConfigurationClear(bounded)
		}
		if err != nil {
			return err
		}
		if _, err := p.run(bounded, commandInput{op: applyConfiguration, configuration: prepared}); err != nil {
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
	for _, item := range []struct {
		family string
		data   []byte
	}{{"inet", post.inet}, {"netdev", post.netdev}} {
		observed, err := b.options.profile.layout.inspectTable(ctx, item.family, item.data)
		if err != nil {
			return err
		}
		mapping, set := epochChannelNames(true)
		if item.family == "inet" && b.options.profile.layout.nat46Sources() != nil && len(observed.sets[nativeNAT46StaticChannel].Elements) != 0 {
			return errors.New("firewall: nat46 configuration channel remained after revocation")
		}
		if item.family == "inet" && (len(observed.sets[configurationEpochSet].Elements) != 0 ||
			len(observed.sets[configurationEpochMap].Elements) != 0 || len(observed.sets[mapping].Elements) != 0) ||
			item.family == "netdev" && len(observed.sets[set].Elements) != 0 {
			return errors.New("firewall: positive configuration remained after revocation")
		}
	}
	return ctx.Err()
}
