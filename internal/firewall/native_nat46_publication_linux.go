package firewall

import (
	"context"
	"errors"
)

// The parent source publication has already committed and passed independent
// whole-profile inspection. A fresh writer fence compares the original cached
// receipt and current epoch before deriving its shorter source-GID channel.
// A listing cannot adopt an uncached publication or create positive authority.
func (b *guardedBackend) publishNAT46SourceEpoch(ctx context.Context, publication *nativeSourcePublication) error {
	sources := b.options.profile.layout.nat46Sources()
	if sources == nil || publication == nil {
		return errors.New("firewall: missing selected nat46 source publication")
	}
	var post []byte
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
		if b.nativeOwnership != publication || b.pendingNativeOwnership != nil {
			return errors.New("firewall: nat46 parent publication changed before conversion")
		}
		original, err := publication.evidence.Snapshot(bounded)
		if err != nil {
			return err
		}
		if original.BaselineHash != b.options.profile.renderer.compiler.BaselineHash() || original.BaselineHash != sources.model.baselineHash || original.Epoch != observation.guards.sourceEpoch {
			return errors.New("firewall: nat46 source channel differs from current original parent")
		}
		prepared, err := sources.prepareSourceEpoch(bounded, publication, b.options.clock())
		if err != nil {
			return err
		}
		if _, err := p.run(bounded, commandInput{op: applyNAT46SourceEpoch, nat46Source: prepared}); err != nil {
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
