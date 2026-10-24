package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// nativeNAT64BackendOrigin keeps only opaque, compiler-owned runtime proofs.
// It is memory-only and deliberately cannot be reconstructed from the deployed
// profile, an nftables listing, or the build-time YAML input.
type nativeNAT64BackendOrigin struct {
	transport     *nativeNAT64Transport
	ledger        *policy.NAT64AllocationLedger
	readiness     nativeNAT64Readiness
	configuration policy.OwnerConfiguration
}

// nativeNAT64Activation is helper-local wiring from a translator supervisor.
// Neither this value nor its opaque readiness proof is part of the profile.
type nativeNAT64Activation struct {
	Component string
	Ledger    *policy.NAT64AllocationLedger
	Readiness nativeNAT64Readiness
}

func (b *guardedBackend) activateNAT64(
	ctx context.Context,
	ledger *policy.NAT64AllocationLedger,
	readiness nativeNAT64Readiness,
	configuration policy.OwnerConfiguration,
) error {
	if b == nil || b.options.profile == nil || b.options.profile.layout == nil || b.options.profile.layout.native == nil {
		return errors.New("firewall: missing NAT64 backend activation dependencies")
	}
	transports := b.options.profile.layout.native.selectedNAT64Transports()
	if len(transports) != 1 {
		return errors.New("firewall: singular NAT64 activation requires exactly one selected component")
	}
	return b.activateNAT64Components(ctx, []nativeNAT64Activation{{
		Component: transports[0].component, Ledger: ledger, Readiness: readiness,
	}}, configuration)
}

func (b *guardedBackend) activateNAT64Components(
	ctx context.Context,
	activations []nativeNAT64Activation,
	configuration policy.OwnerConfiguration,
) (result error) {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing NAT64 backend activation dependencies")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	layout := b.options.profile.layout
	if layout.native == nil {
		return errors.New("firewall: profile has no selected NAT64 runtime")
	}
	transports := layout.native.selectedNAT64Transports()
	if len(transports) == 0 || len(activations) != len(transports) {
		return errors.New("firewall: NAT64 activation set differs from selected components")
	}
	byComponent := make(map[string]nativeNAT64Activation, len(activations))
	for _, activation := range activations {
		if activation.Component == "" || activation.Ledger == nil || activation.Readiness == nil || byComponent[activation.Component].Component != "" {
			return errors.New("firewall: invalid or duplicate NAT64 activation")
		}
		byComponent[activation.Component] = activation
	}
	origins := make([]*nativeNAT64BackendOrigin, 0, len(transports))
	for _, transport := range transports {
		activation, found := byComponent[transport.component]
		if !found {
			return errors.New("firewall: NAT64 activation omitted a selected component")
		}
		origins = append(origins, &nativeNAT64BackendOrigin{
			transport: transport, ledger: activation.Ledger, readiness: activation.Readiness, configuration: configuration,
		})
	}
	defer func() {
		if result == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*commandTimeout)
		defer cancel()
		result = errors.Join(result, b.clearNAT64(cleanup))
	}()
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
		publication := b.nativeOwnership
		if b.pendingNativeOwnership != nil {
			return errors.New("firewall: source publication awaits independent verification")
		}
		if publication != nil {
			snapshot, snapshotErr := publication.evidence.Snapshot(bounded)
			if snapshotErr != nil || snapshot.BaselineHash != transports[0].baselineHash || snapshot.Epoch != observation.guards.sourceEpoch {
				return errors.New("firewall: NAT64 source receipt differs from current inspected epoch")
			}
		}
		allocations := make([]*preparedNAT64Allocations, 0, len(origins))
		tokens := make([]*nativeNAT64Tokens, 0, len(origins))
		for _, origin := range origins {
			prepared, err := prepareNativeNAT64Allocations(bounded, origin.transport, origin.ledger, origin.readiness)
			if err != nil {
				return err
			}
			registry, err := deriveNativeNAT64Tokens(bounded, origin.transport, layout.native, origin.ledger, origin.configuration, publication, b.options.clock().UTC())
			if err != nil {
				return err
			}
			allocations, tokens = append(allocations, prepared), append(tokens, registry)
		}
		state, err := prepareNativeNAT64State(bounded, allocations, tokens)
		if err != nil {
			return err
		}
		if _, err := p.run(bounded, commandInput{op: applyNAT64State, nat64State: state}); err != nil {
			return err
		}
		post, err = p.run(bounded, commandInput{op: inspectWholeRuleset})
		if err == nil {
			b.nat64Origins = slices.Clone(origins)
			b.nat64Origin = nil
			if len(origins) == 1 {
				b.nat64Origin = origins[0]
			}
		}
		return err
	}); err != nil {
		return err
	}
	if _, err := b.options.profile.ruleset.inspect(ctx, layout, post); err != nil {
		return fmt.Errorf("firewall: verify activated NAT64 runtime: %w", err)
	}
	return ctx.Err()
}

func sameNAT64Origins(first, second []*nativeNAT64BackendOrigin) bool {
	return len(first) == len(second) && slices.Equal(first, second)
}

func (b *guardedBackend) hasNAT64Origins() bool {
	return b != nil && (b.nat64Origin != nil || len(b.nat64Origins) != 0)
}

func (b *guardedBackend) refreshNAT64Tokens(ctx context.Context, publication *nativeSourcePublication) error {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing NAT64 token refresh dependencies")
	}
	origins := slices.Clone(b.nat64Origins)
	if len(origins) == 0 && b.nat64Origin != nil {
		origins = []*nativeNAT64BackendOrigin{b.nat64Origin}
	}
	if len(origins) == 0 {
		return ctx.Err()
	}
	layout := b.options.profile.layout
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
		current := b.nat64Origins
		if len(current) == 0 && b.nat64Origin != nil {
			current = []*nativeNAT64BackendOrigin{b.nat64Origin}
		}
		if !sameNAT64Origins(current, origins) || b.nativeOwnership != publication || b.pendingNativeOwnership != nil {
			return errors.New("firewall: NAT64 runtime origin changed during token refresh")
		}
		if publication != nil {
			snapshot, snapshotErr := publication.evidence.Snapshot(bounded)
			if snapshotErr != nil || snapshot.BaselineHash != origins[0].transport.baselineHash || snapshot.Epoch != observation.guards.sourceEpoch {
				return errors.New("firewall: NAT64 token source differs from current inspected epoch")
			}
		}
		registries := make([]*nativeNAT64Tokens, 0, len(origins))
		for _, origin := range origins {
			tokens, err := deriveNativeNAT64Tokens(bounded, origin.transport, layout.native, origin.ledger, origin.configuration, publication, b.options.clock().UTC())
			if err != nil {
				return err
			}
			registries = append(registries, tokens)
		}
		state, err := prepareNativeNAT64State(bounded, nil, registries)
		if err != nil {
			return err
		}
		if _, err := p.run(bounded, commandInput{op: applyNAT64State, nat64State: state}); err != nil {
			return err
		}
		post, err = p.run(bounded, commandInput{op: inspectWholeRuleset})
		return err
	}); err != nil {
		return err
	}
	_, err := b.options.profile.ruleset.inspect(ctx, layout, post)
	return err
}

func (b *guardedBackend) clearNAT64(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing NAT64 backend revocation dependencies")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	layout := b.options.profile.layout
	if layout.native == nil {
		return errors.New("firewall: profile has no selected NAT64 runtime")
	}
	transports := layout.native.selectedNAT64Transports()
	if len(transports) == 0 {
		return errors.New("firewall: profile has no selected NAT64 runtime")
	}
	var post []byte
	if err := b.options.generation.fence.With(ctx, func(bounded context.Context, _ *os.Root) error {
		b.nat64Origin, b.nat64Origins = nil, nil
		p := b.options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		data, err := p.run(bounded, commandInput{op: inspectWholeRuleset})
		if err != nil {
			return err
		}
		if _, _, err := inspectSealingGuards(bounded, layout, data); err != nil {
			return err
		}
		clears := make([]*preparedNAT64Allocations, 0, len(transports))
		for _, transport := range transports {
			allocationClear, err := prepareNativeNAT64AllocationClear(bounded, transport)
			if err != nil {
				return err
			}
			clears = append(clears, allocationClear)
		}
		state, err := prepareNativeNAT64State(bounded, clears, nil)
		if err != nil {
			return err
		}
		if _, err := p.run(bounded, commandInput{op: applyNAT64State, nat64State: state}); err != nil {
			return err
		}
		post, err = p.run(bounded, commandInput{op: inspectWholeRuleset})
		return err
	}); err != nil {
		return err
	}
	_, err := b.options.profile.ruleset.inspect(ctx, layout, post)
	return err
}
