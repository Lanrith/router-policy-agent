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

// ErrBindingsPending means an explicit incomplete producer publication left
// ownership and application permits successfully sealed. Cleanup failures are
// never reported with this sentinel and must stop the supervisor.
var ErrBindingsPending = errors.New("agent: binding collection pending with ownership sealed")

// RefreshBindings is helper-local supervision, not reader IPC. It rereads the
// authenticated source and persists deny-only address history before refreshing
// ownership. No directory observation or authorization is created or renewed.
func (engine *Engine) RefreshBindings(ctx context.Context) (result error) {
	return engine.refreshBindings(ctx, false)
}

// InitializeBindings waits up to 90 seconds for the producer's first qualified
// post-start observation, then installs ownership through the normal checked
// path. It cannot restore directory grants or change any evidence timestamp.
// The supervisor calls it before accepting requests or declaring readiness.
func (engine *Engine) InitializeBindings(ctx context.Context) error {
	if ctx == nil {
		return errors.New("agent: missing binding startup context")
	}
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return engine.refreshBindings(bounded, true)
}

func (engine *Engine) refreshBindings(ctx context.Context, startup bool) (result error) {
	if err := engine.acquire(ctx); err != nil {
		return err
	}
	defer engine.release()
	if !engine.named || !engine.started {
		return errors.New("agent: ownership supervision requires a started named model")
	}
	if startup && engine.options.Mode != Enforce {
		return nil
	}
	history := state.EmptyClassification()
	defer func() {
		if result == nil || engine.options.Mode != Enforce {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		engine.ownershipFingerprint = ""
		cleanupErr := errors.Join(engine.options.Firewall.ClearOwnership(cleanup), engine.seal(cleanup, history))
		if cleanupErr == nil && ctx.Err() == nil && errors.Is(result, binding.ErrIncomplete) {
			result = ErrBindingsPending
			return
		}
		result = errors.Join(result, cleanupErr)
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
	if startup {
		engine.ownershipFingerprint = ""
		if err := errors.Join(engine.options.Firewall.ClearOwnership(ctx), engine.seal(ctx, history)); err != nil {
			return err
		}
	}
	bindings, err := engine.collectBindings(ctx, startup)
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

// The caller holds the engine gate. During startup no request servers run and
// classification remains closed. Only explicit incomplete publications and
// otherwise-valid pre-start evidence may wait; unsafe/malformed/future inputs
// still fail immediately. Every attempt rereads the independently owned source.
func (engine *Engine) collectBindings(ctx context.Context, startup bool) (binding.Snapshot, error) {
	if !startup {
		return engine.options.Bindings(ctx)
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return binding.Snapshot{}, err
		}
		snapshot, err := engine.options.Bindings(ctx)
		if err == nil {
			now, clockErr := engine.now()
			if clockErr != nil {
				return binding.Snapshot{}, clockErr
			}
			err = binding.Validate(snapshot, now.utc, engine.lease, engine.maximumDevices)
			if err == nil {
				err = engine.checkStartupBindings(ctx, snapshot)
			}
			if err == nil {
				return snapshot, nil
			}
		}
		pending := errors.Is(err, binding.ErrIncomplete) || errors.Is(err, errPreStartupBindings)
		if !pending {
			return binding.Snapshot{}, err
		}
		select {
		case <-ctx.Done():
			return binding.Snapshot{}, ctx.Err()
		case <-ticker.C:
		}
	}
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
