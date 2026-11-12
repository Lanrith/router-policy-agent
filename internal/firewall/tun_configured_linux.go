package firewall

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/lanrith/router-policy-agent/internal/agent"
	"github.com/lanrith/router-policy-agent/internal/hostfs"
	"github.com/lanrith/router-policy-agent/internal/ipc"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
	"github.com/lanrith/router-policy-agent/internal/tunpolicy"
)

func loadTUNProfile(ctx context.Context, config helperConfig) (tunProfile, policy.Baseline, error) {
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: config.Profile.Directory, OwnerUID: 0, Private: true})
	if err != nil {
		return tunProfile{}, policy.Baseline{}, err
	}
	data, readErr := readRouterProfile(ctx, root)
	if err := errors.Join(readErr, root.Close()); err != nil {
		return tunProfile{}, policy.Baseline{}, err
	}
	return decodeTUNProfile(data, config.Profile.SHA256)
}

type tunResources struct {
	profile  tunProfile
	baseline policy.Baseline
	store    *state.Store
	executor *tunpolicy.Executor
	gate     *generationGate
	backend  *tunpolicy.Backend
}

func openTUNResources(ctx context.Context, config helperConfig, clock func() time.Time) (_ *tunResources, result error) {
	r := &tunResources{}
	defer func() {
		if result != nil {
			result = errors.Join(result, r.close(ctx))
		}
	}()
	var err error
	r.profile, r.baseline, err = loadTUNProfile(ctx, config)
	if err != nil {
		return nil, err
	}
	if r.profile.ProgramSHA256 != config.ExpectedGeneration.FloorHash {
		return nil, errors.New("firewall: TUN program generation differs")
	}
	r.executor, err = tunpolicy.OpenExecutor(ctx, config.NFTExecutable, config.ConntrackExecutable)
	if err != nil {
		return nil, err
	}
	r.gate, err = openGenerationGate(ctx, config.GenerationDir)
	if err != nil {
		return nil, err
	}
	r.store, err = state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		return nil, err
	}
	r.backend, err = tunpolicy.New(r.baseline, tunpolicy.Options{Clock: clock,
		Commit: func(ctx context.Context, batch tunpolicy.Batch) error {
			if !batch.Positive() {
				return r.gate.fence.With(ctx, func(ctx context.Context, _ *os.Root) error { return r.executor.Commit(ctx, batch) })
			}
			return r.gate.with(ctx, config.ExpectedGeneration, func(ctx context.Context) error {
				if err := r.executor.Inspect(ctx, r.profile.ProgramSHA256); err != nil {
					return err
				}
				return r.executor.Commit(ctx, batch)
			})
		},
		Invalidate: func(ctx context.Context, scope tunpolicy.CleanupScope) error {
			return r.gate.fence.With(ctx, func(ctx context.Context, _ *os.Root) error { return r.executor.Invalidate(ctx, scope) })
		},
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *tunResources) close(ctx context.Context) error {
	var errs []error
	if r.store != nil {
		errs = append(errs, r.store.Close())
	}
	if r.gate != nil {
		errs = append(errs, r.gate.close(ctx))
	}
	if r.executor != nil {
		errs = append(errs, r.executor.Close())
	}
	return errors.Join(errs...)
}

func runTUNService(ctx context.Context, options configuredOptions, config helperConfig, clock func() time.Time) (result error) {
	r, err := openTUNResources(ctx, config, clock)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		result = errors.Join(result, r.close(cleanup))
	}()
	engine, err := agent.New(r.baseline, agent.Options{Mode: agent.Enforce,
		State:    agent.Persistence{Load: r.store.Load, Save: r.store.Save, AdvanceOwnershipEpoch: r.store.AdvanceOwnershipEpoch},
		Bindings: options.bindings, Clock: clock, Firewall: r.backend.Enforcement()})
	if err != nil {
		return err
	}
	timeout := time.Duration(config.RequestTimeoutMS) * time.Millisecond
	server, err := ipc.NewServer(ipc.ServerOptions{ReaderUID: config.ReaderUID, Timeout: timeout}, engine.Process)
	if err != nil {
		return err
	}
	status, err := ipc.NewStatusServer(ipc.ServerOptions{ReaderUID: config.OperatorUID, Timeout: timeout}, func(ctx context.Context) (ipc.Report, error) {
		report, err := engine.Status(ctx)
		if err != nil {
			return report, err
		}
		var count int
		err = r.gate.with(ctx, config.ExpectedGeneration, func(ctx context.Context) error {
			var err error
			count, err = r.executor.Observe(ctx, r.profile.ProgramSHA256)
			return err
		})
		if err == nil {
			report.FloorState = "matches_pinned_contract"
			sequence := config.ExpectedGeneration.Sequence
			report.WriterSequence = &sequence
			report.KernelTupleCount = &count
		}
		return report, ctx.Err()
	})
	if err != nil {
		return err
	}
	observerCtx, cancelObserver := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancelObserver(); workers.Wait() }()
	if options.observations != nil {
		options.observations.SetUnlinkOnClose(false)
		observer, err := ipc.NewObservationsServer(ipc.ServerOptions{ReaderUID: config.ObserverUID, Timeout: min(timeout, 2*time.Second)}, func(ctx context.Context, request ipc.ObservationRequest) (ipc.ObservationResponse, error) {
			response, err := engine.Observations(ctx, request)
			if response.Snapshot != nil {
				// Identify the configured writer, without turning compilation
				// provenance into a claim about current kernel installation.
				response.Snapshot.WriterSequence = config.ExpectedGeneration.Sequence
				response.Snapshot.FloorHash = config.ExpectedGeneration.FloorHash
			}
			return response, err
		})
		if err != nil {
			return err
		}
		workers.Go(func() { _ = observer.Serve(observerCtx, options.observations) })
	}
	service := &guardedService{engine: engine, server: server, readerUID: config.ReaderUID, tun: true}
	return service.serveListeners(ctx, serviceListeners{requests: options.requests, status: options.status, operator: status, ready: notifyReady})
}

func initializeTUNState(ctx context.Context, config helperConfig) (result error) {
	if _, _, err := loadTUNProfile(ctx, config); err != nil {
		return err
	}
	store, err := state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	if err := store.Initialize(ctx); err != nil {
		return err
	}
	return store.InitializeOwnershipEpoch(ctx)
}

func recoverTUN(ctx context.Context, config helperConfig) (result error) {
	r, err := openTUNResources(ctx, config, kernelUTC)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, r.close(ctx)) }()
	// Close startup before reading persistent history. This cannot initialize or
	// replace a corrupt store, and remains useful without directory connectivity.
	if err := r.backend.Close(ctx, state.EmptyClassification()); err != nil {
		return err
	}
	document, err := r.store.Load(ctx)
	if err != nil {
		return err
	}
	history, err := state.Classifiers(document)
	if err != nil {
		return err
	}
	return r.backend.Seal(ctx, history)
}
