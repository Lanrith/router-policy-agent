package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// RefreshBindings is helper-local supervision, not reader IPC. It rereads the
// authenticated source and persists deny-only address history before refreshing
// ownership. No directory observation or authorization is created or renewed.
func (engine *Engine) RefreshBindings(ctx context.Context) (result error) {
	if err := engine.acquire(ctx); err != nil {
		return err
	}
	defer engine.release()
	if !engine.named || !engine.started {
		return errors.New("agent: ownership supervision requires a started named model")
	}
	history := state.EmptyClassification()
	defer func() {
		if result == nil || engine.options.Mode != Enforce {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		engine.ownershipFingerprint = ""
		result = errors.Join(result, engine.options.Firewall.ClearOwnership(cleanup), engine.seal(cleanup, history))
	}()
	if err := engine.refreshConfiguration(ctx); err != nil {
		return err
	}
	document, err := engine.options.State.Load(ctx)
	if err != nil {
		return err
	}
	document, err = state.Clone(document)
	if err != nil {
		return err
	}
	history, err = state.Classifiers(document)
	if err != nil {
		return err
	}
	bindings, err := engine.options.Bindings(ctx)
	if err != nil {
		return fmt.Errorf("agent: collect qualified ownership: %w", err)
	}
	now, err := engine.now()
	if err != nil {
		return err
	}
	if err := binding.Validate(bindings, now.utc, engine.lease, engine.maximumDevices); err != nil {
		return err
	}
	if err := engine.checkStartupBindings(ctx, bindings); err != nil {
		return err
	}
	addresses, err := engine.compiler.ClassifyBindings(ctx, bindings, history.MACs, now.utc)
	if err != nil {
		return err
	}
	next, err := state.RememberAddresses(document, addresses)
	if err != nil {
		return err
	}
	history, err = state.Classifiers(next)
	if err != nil {
		return err
	}
	if err := engine.options.State.Save(ctx, next); err != nil {
		return err
	}
	return engine.refreshOwnership(ctx, bindings, history)
}

// The caller holds the engine gate. Refreshing physical evidence cannot make
// an earlier directory decision apply to a new association or address owner.
func (engine *Engine) refreshOwnership(ctx context.Context, bindings binding.Snapshot, history state.Classification) error {
	if !engine.named {
		return nil
	}
	now, err := engine.now()
	if err != nil {
		return err
	}
	evidence, err := engine.compiler.CompileOwnership(ctx, bindings, now.authorization, now.anchor)
	if err != nil {
		return err
	}
	snapshot, err := evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	if engine.options.Mode == Shadow {
		return nil
	}
	if err := engine.publishClassification(ctx, history); err != nil {
		return err
	}
	if snapshot.Fingerprint != engine.ownershipFingerprint {
		if err := engine.options.Firewall.ClearOwnership(ctx); err != nil {
			return err
		}
		if err := engine.seal(ctx, history); err != nil {
			return err
		}
		if err := engine.advanceOwnershipEpoch(ctx); err != nil {
			return err
		}
	}
	evidence, err = evidence.InEpoch(ctx, engine.ownershipEpoch)
	if err != nil {
		return err
	}
	if err := engine.options.Firewall.RefreshOwnership(ctx, evidence); err != nil {
		return err
	}
	engine.ownershipFingerprint = snapshot.Fingerprint
	return nil
}

func (engine *Engine) advanceOwnershipEpoch(ctx context.Context) error {
	epoch, err := engine.options.State.AdvanceOwnershipEpoch(ctx)
	if err != nil {
		return fmt.Errorf("agent: consume ownership sequence: %w", err)
	}
	if epoch <= engine.ownershipEpoch || epoch > policy.MaximumOwnershipEpoch {
		return errors.New("agent: ownership sequence did not advance or is reserved")
	}
	engine.ownershipEpoch = epoch
	return nil
}

func (engine *Engine) refreshConfiguration(ctx context.Context) error {
	if !engine.named || engine.options.Mode == Shadow {
		return nil
	}
	evidence, err := engine.compiler.CompileOwnerConfiguration(ctx, engine.configurationEpoch)
	if err != nil {
		return err
	}
	return engine.options.Firewall.RefreshConfiguration(ctx, evidence)
}
