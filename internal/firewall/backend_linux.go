package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

// guardedBackend is private helper plumbing. Its dependencies and expected
// generation come from the owning router integration, never reader IPC. The
// caller owns their lifetimes. Construction does not qualify P01-P10, release
// provenance, actual writer cooperation, clock synchronization or translation.
type guardedBackend struct {
	options backendOptions
	// Only accessed under the shared writer fence. The original prepared
	// source receipt retains its immutable evidence and monotonic deadlines;
	// diagnostics and kernel listings cannot create this receipt.
	nativeOwnership *nativeSourcePublication
	// A committed source cannot be used for ID grants until the complete
	// post-commit observation has passed. Guard updates see no source receipt
	// while this pointer is pending. Source clear invalidates both pointers.
	pendingNativeOwnership *nativeSourcePublication
	// Set only after allocation and token publication pass the complete profile
	// readback. The opaque origin is never persisted or reconstructed.
	nat64Origin  *nativeNAT64BackendOrigin
	nat64Origins []*nativeNAT64BackendOrigin
}

type backendOptions struct {
	profile    *routerProfile
	executor   *process
	generation *generationGate
	expected   writerGeneration
	clock      func() time.Time
}

func newGuardedBackend(options backendOptions) (*guardedBackend, error) {
	if err := validateBackendOptions(options); err != nil {
		return nil, err
	}
	return &guardedBackend{options: options}, nil
}

func validateBackendOptions(options backendOptions) error {
	validProfile := options.profile != nil && generationHash(options.profile.digest)
	validExecutor := options.executor != nil && options.executor.gate != nil
	validGeneration := options.generation != nil && options.generation.fence != nil
	if !validProfile || !validExecutor || !validGeneration || options.clock == nil {
		return errors.New("firewall: missing guarded backend dependencies")
	}
	p := options.profile
	validCompiler := p.renderer != nil && p.renderer.compiler != nil
	validLayout := p.layout != nil && len(p.layout.managedInterfaces) != 0
	validContract := p.ruleset != nil && len(p.ruleset.program) != 0 && generationHash(p.ruleset.digest)
	if !validCompiler || !validLayout || !validContract {
		return errors.New("firewall: incomplete guarded backend profile")
	}
	if err := options.expected.validate(); err != nil {
		return err
	}
	if !options.expected.Ready || options.expected.FloorHash != p.ruleset.digest {
		return errors.New("firewall: guarded backend generation does not match its reviewed floor")
	}
	return nil
}

// apply preserves the compiler's original age anchor across writer/executor
// queueing, inspection and rendering. Any failure attempts bounded sealing even
// after cancellation or a generation change. A failed cleanup is returned too;
// callers must not report application success or reopen readiness on failure.
func (b *guardedBackend) apply(
	ctx context.Context,
	authorization policy.Authorization,
	classification state.Classification,
) (result error) {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing guarded backend or context")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	history := state.EmptyClassification()
	defer func() {
		if result == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*commandTimeout)
		defer cancel()
		result = errors.Join(result, b.seal(cleanup, history))
	}()
	owned, err := state.CloneClassification(classification)
	if err != nil {
		return err
	}
	if sources := b.options.profile.layout.nat46Sources(); sources != nil {
		owned, err = sources.model.translatedClassification(ctx, owned)
		if err != nil {
			return err
		}
	}
	history = owned
	prepared, publication, err := b.prepareApplication(ctx, authorization, history)
	if err != nil {
		return err
	}
	post, err := b.commitApplication(ctx, prepared, publication)
	if err != nil {
		return err
	}
	// Capture the complete post-commit listing while both gates are held,
	// then validate those owned bytes without extending the writer critical
	// section. This is evidence at that fenced point, not a reusable permit.
	// A cooperating later writer must revoke before changing its owned state.
	_, err = b.options.profile.ruleset.inspect(ctx, b.options.profile.layout, post)
	if err != nil {
		return fmt.Errorf("firewall: verify applied baseline: %w", err)
	}
	return nil
}

func (b *guardedBackend) commitApplication(ctx context.Context, prepared *preparedGuardBatch, publication *nativeSourcePublication) ([]byte, error) {
	if prepared == nil || prepared.sourcePublication != publication {
		return nil, errors.New("firewall: application lost its original source preparation")
	}
	var post []byte
	err := b.options.generation.with(ctx, b.options.expected, func(bounded context.Context) error {
		if b.nativeOwnership != publication || b.pendingNativeOwnership != nil {
			return errors.New("firewall: source publication changed during grant preparation")
		}
		return b.options.executor.replaceGuarded(bounded, b.options, prepared)
	})
	if err != nil {
		return nil, err
	}
	// The scoped mutation is complete. Readback gets a fresh bounded fence;
	// generation and original receipt must still match before taking the
	// snapshot. No success is returned until independent inspection passes.
	// This adds no lease time and never substitutes a newer source receipt.
	err = b.options.generation.with(ctx, b.options.expected, func(bounded context.Context) error {
		if b.nativeOwnership != publication || b.pendingNativeOwnership != nil {
			return errors.New("firewall: source publication changed before grant verification")
		}
		p := b.options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		var err error
		post, err = p.run(bounded, commandInput{op: inspectWholeRuleset})
		return err
	})
	return post, err
}

// seal does not require ready generation metadata or an unchanged external
// floor: revocation must remain possible after either fails. It still requires
// the shared fence and exact code-owned guard objects. It removes all lease
// mirrors atomically and unions deny-only classification without retiring any
// kernel history. It never repairs external rules or opens forwarding at boot.
func (b *guardedBackend) seal(ctx context.Context, classification state.Classification) error {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing guarded sealing dependencies")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	history, err := state.CloneClassification(classification)
	if err != nil {
		return err
	}
	var receipt sealingObservation
	if err := b.options.generation.fence.With(ctx, func(bounded context.Context, _ *os.Root) error {
		var err error
		receipt, err = b.options.executor.sealGuarded(bounded, b.options.profile.layout, history)
		return err
	}); err != nil {
		return err
	}
	sealed, actual, err := inspectSealingGuards(ctx, b.options.profile.layout, receipt.data)
	if err != nil {
		return fmt.Errorf("firewall: verify sealed guards: %w", err)
	}
	sameCohort := slices.Equal(actual.MACs, receipt.history.MACs)
	sameAddresses := slices.Equal(actual.IPv4, receipt.history.IPv4) && slices.Equal(actual.IPv6, receipt.history.IPv6)
	if sealed.leases != 0 || !sameCohort || !sameAddresses {
		return errors.New("firewall: sealed lease or classification verification failed")
	}
	return ctx.Err()
}

// Build from original authorization and a fenced source receipt outside the
// mutation critical section. Every original age/deadline anchor survives this
// work. The final fence independently checks the current whole profile, the
// exact same cached receipt and its epoch, quotas and the complete transaction.
func (b *guardedBackend) prepareApplication(
	ctx context.Context,
	authorization policy.Authorization,
	history state.Classification,
) (*preparedGuardBatch, *nativeSourcePublication, error) {
	options := b.options
	var observation *rulesetObservation
	var publication *nativeSourcePublication
	if err := options.generation.with(ctx, options.expected, func(bounded context.Context) error {
		p := options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		if b.pendingNativeOwnership != nil {
			return errors.New("firewall: source publication awaits independent verification")
		}
		var err error
		observation, err = p.observeProfile(bounded, options.profile)
		publication = b.nativeOwnership
		return err
	}); err != nil {
		return nil, nil, fmt.Errorf("firewall: inspect preparation baseline: %w", err)
	}
	logical, err := options.profile.renderer.prepare(ctx, replacement{
		authorization: authorization, cohort: history.MACs,
		existingCohort: observation.guards.cohort, now: options.clock(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("firewall: render application: %w", err)
	}
	var prepared *preparedGuardBatch
	if options.profile.layout.native != nil && publication != nil {
		source, sourceErr := publication.evidence.Snapshot(ctx)
		if sourceErr != nil {
			return nil, nil, sourceErr
		}
		if source.BaselineHash != options.profile.renderer.compiler.BaselineHash() || source.Epoch != observation.guards.sourceEpoch {
			return nil, nil, errors.New("firewall: cached source publication differs from the current inspected epoch")
		}
		mapped, mapErr := prepareMappedGuards(ctx, logical, &history, options.profile.layout.translationPaths)
		if mapErr != nil {
			return nil, nil, mapErr
		}
		if sources := options.profile.layout.nat46Sources(); sources != nil {
			prepared, err = prepareNativeNAT46Guards(ctx, mapped, publication, sources.model, logical.preparedAt)
			if err == nil {
				if transports := options.profile.layout.native.selectedNAT64Transports(); len(transports) != 0 {
					prepared, err = attachNativeNAT64Grants(ctx, prepared, publication, transports)
				}
			}
		} else if transports := options.profile.layout.native.selectedNAT64Transports(); len(transports) != 0 {
			prepared, err = prepareNativeNAT64AggregateGuards(ctx, mapped, publication, transports, logical.preparedAt)
		} else {
			prepared, err = prepareNativeGuardsWithSource(ctx, mapped, publication, source.BaselineHash, logical.preparedAt)
		}
	} else {
		prepared, err = prepareLayoutGuards(ctx, logical, &history, options.profile.layout)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("firewall: prepare application mirrors: %w", err)
	}
	return prepared, publication, ctx.Err()
}

func (p *process) replaceGuarded(ctx context.Context, options backendOptions, prepared *preparedGuardBatch) error {
	if err := p.acquire(ctx); err != nil {
		return err
	}
	defer p.release()
	observation, err := p.observeProfile(ctx, options.profile)
	if err != nil {
		return fmt.Errorf("firewall: inspect application baseline: %w", err)
	}
	if prepared == nil || prepared.classification == nil {
		return errors.New("firewall: application lost its prepared classification")
	}
	if _, _, err := options.profile.renderer.cohort(replacement{existingCohort: observation.guards.cohort, cohort: prepared.classification.MACs}); err != nil {
		return err
	}
	if publication := prepared.sourcePublication; publication != nil {
		source, err := publication.evidence.Snapshot(ctx)
		if err != nil {
			return err
		}
		if source.BaselineHash != options.profile.renderer.compiler.BaselineHash() || source.Epoch != observation.guards.sourceEpoch {
			return errors.New("firewall: prepared source publication differs from current epoch")
		}
	}
	if err := observation.guards.checkPreparedReplacement(ctx, prepared); err != nil {
		return fmt.Errorf("firewall: check application replacement: %w", err)
	}
	if _, err := p.run(ctx, commandInput{op: applyGuarded, guarded: prepared}); err != nil {
		return fmt.Errorf("firewall: apply guarded replacement: %w", err)
	}
	return ctx.Err()
}

// observeProfile is called only while the executor gate is already held.
func (p *process) observeProfile(ctx context.Context, profile *routerProfile) (*rulesetObservation, error) {
	data, err := p.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		return nil, err
	}
	return profile.ruleset.inspect(ctx, profile.layout, data)
}

type sealingObservation struct {
	data    []byte
	history state.Classification
}

func (p *process) sealGuarded(
	ctx context.Context,
	layout *guardLayout,
	history state.Classification,
) (sealingObservation, error) {
	if err := p.acquire(ctx); err != nil {
		return sealingObservation{}, err
	}
	defer p.release()
	data, err := p.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		return sealingObservation{}, err
	}
	inventory, retained, err := inspectSealingGuards(ctx, layout, data)
	if err != nil {
		return sealingObservation{}, fmt.Errorf("firewall: inspect sealing guards: %w", err)
	}
	for index, values := range []*[]string{&history.MACs, &history.IPv4, &history.IPv6} {
		additions := retained.MACs
		switch index {
		case 1:
			additions = retained.IPv4
		case 2:
			additions = retained.IPv6
		}
		*values = append(*values, additions...)
		slices.Sort(*values)
		*values = slices.Compact(*values)
	}
	if sources := layout.nat46Sources(); sources != nil {
		history, err = sources.model.translatedClassification(ctx, history)
		if err != nil {
			return sealingObservation{}, err
		}
	}
	prepared, err := prepareMappedGuardSeal(ctx, history, layout.translationPaths)
	if err == nil && layout.native != nil {
		if sources := layout.nat46Sources(); sources != nil {
			prepared, err = prepareNativeNAT46Guards(ctx, prepared, nil, sources.model, time.Time{})
			if err == nil {
				if transports := layout.native.selectedNAT64Transports(); len(transports) != 0 {
					prepared, err = attachNativeNAT64Grants(ctx, prepared, nil, transports)
				}
			}
		} else if transports := layout.native.selectedNAT64Transports(); len(transports) != 0 {
			prepared, err = prepareNativeNAT64AggregateGuards(ctx, prepared, nil, transports, time.Time{})
		} else {
			prepared, err = prepareNativeGuards(ctx, prepared)
		}
	}
	if err != nil {
		return sealingObservation{}, err
	}
	if err := inventory.checkPreparedReplacement(ctx, prepared); err != nil {
		return sealingObservation{}, err
	}
	if _, err := p.run(ctx, commandInput{op: sealGuarded, guarded: prepared}); err != nil {
		return sealingObservation{}, err
	}
	data, err = p.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		return sealingObservation{}, err
	}
	return sealingObservation{data: data, history: history}, nil
}

// inspectSealingGuards checks the exact fixed objects but deliberately does not
// require consistent leased mirrors. An expiry-boundary observation, damaged
// lease content or closed owner generation must not prevent removing permits.
// Both permanent MAC sets are retained and repaired to their union. Historical
// address observations remain denial only, never ownership or authorization.
func inspectSealingGuards(
	ctx context.Context,
	layout *guardLayout,
	data []byte,
) (*guardInventory, state.Classification, error) {
	empty := state.EmptyClassification()
	if ctx == nil || layout == nil {
		return nil, empty, errors.New("firewall: missing sealing inspection dependencies")
	}
	objects, err := decodeRulesetListing(ctx, data)
	if err != nil {
		return nil, empty, err
	}
	limit, err := layout.completeInventoryLimit(ctx)
	if err != nil {
		return nil, empty, err
	}
	if len(objects) < 2 || len(objects) > limit {
		return nil, empty, errors.New("firewall: sealing inventory size invalid")
	}
	if err := verifyListingMetadata(objects[0]); err != nil {
		return nil, empty, err
	}
	protected, guards, err := splitRuleset(ctx, objects)
	if err != nil {
		return nil, empty, err
	}
	if len(protected) > maximumRulesetObjects {
		return nil, empty, errors.New("firewall: sealing protected inventory size invalid")
	}
	inet, err := layout.inspectTableObjects(ctx, "inet", guards["inet"])
	if err != nil {
		return nil, empty, err
	}
	netdev, err := layout.inspectTableObjects(ctx, "netdev", guards["netdev"])
	if err != nil {
		return nil, empty, err
	}
	macs, err := listedGuardMACs(inet.sets[cohortSet].Elements)
	if err != nil {
		return nil, empty, err
	}
	other, err := listedGuardMACs(netdev.sets[cohortSet].Elements)
	if err != nil {
		return nil, empty, err
	}
	macs = append(macs, other...)
	slices.Sort(macs)
	macs = slices.Compact(macs)
	addresses4, err := listedGuardAddresses(ctx, inet.sets[classified4Set].Elements, true)
	if err != nil {
		return nil, empty, err
	}
	addresses6, err := listedGuardAddresses(ctx, inet.sets[classified6Set].Elements, false)
	if err != nil {
		return nil, empty, err
	}
	if layout.native != nil {
		for _, item := range []struct {
			name      string
			ipv4      bool
			addresses *[]netip.Addr
		}{{classified4Set, true, &addresses4}, {classified6Set, false, &addresses6}} {
			physical, err := listedGuardAddresses(ctx, netdev.sets[item.name].Elements, item.ipv4)
			if err != nil {
				return nil, empty, err
			}
			*item.addresses = append(*item.addresses, physical...)
			slices.SortFunc(*item.addresses, netip.Addr.Compare)
			*item.addresses = slices.Compact(*item.addresses)
		}
	}
	history := state.Classification{MACs: macs, IPv4: []string{}, IPv6: []string{}}
	for _, address := range addresses4 {
		history.IPv4 = append(history.IPv4, address.String())
	}
	for _, address := range addresses6 {
		history.IPv6 = append(history.IPv6, address.String())
	}
	slices.Sort(history.IPv4)
	slices.Sort(history.IPv6)
	owned, err := state.CloneClassification(history)
	if err != nil {
		return nil, empty, err
	}
	leaseElements := 0
	for _, name := range grantSets {
		for _, ref := range guardLeaseRefs(name) {
			observation := inet
			if ref.Family == "netdev" {
				observation = netdev
			}
			leaseElements += len(observation.sets[ref.Name].Elements)
		}
	}
	additional := translatedGrantRefs(layout.translationPaths)
	if layout.native != nil {
		additional = append(additional, nativeGrantRefs()...)
	}
	if layout.nat46Sources() != nil {
		additional = append(additional, nativeNAT46TargetGrantRefs()...)
	}
	for _, ref := range additional {
		observation := inet
		if ref.Family == "netdev" {
			observation = netdev
		}
		leaseElements += len(observation.sets[ref.Name].Elements)
	}
	if err := ctx.Err(); err != nil {
		return nil, empty, err
	}
	inventory := &guardInventory{
		native: layout.native != nil,
		cohort: macs, addresses4: addresses4, addresses6: addresses6,
		managedInterfaces: slices.Clone(layout.managedInterfaces), leases: leaseElements,
		translationPaths: slices.Clone(layout.translationPaths),
	}
	if sources := layout.nat46Sources(); sources != nil {
		inventory.nat46Model = sources.model
	}
	return inventory, owned, nil
}
