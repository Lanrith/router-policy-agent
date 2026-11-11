// Package tunpolicy publishes identity data for the immutable TUN firewall.
// It does not generate access rules, allocate translations or carry permission
// between the IPv4 and IPv6 connections maintained by Linux.
package tunpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lanrith/router-policy-agent/internal/agent"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/state"
)

const maximumElements = 16384

// Batch contains only code-owned set data operations. A trusted executor must
// commit Program atomically, within CommitBudget, or return an error.
type Batch struct {
	program  string
	positive bool
}

// Program returns nft input containing no rule, route or translator mutation.
func (batch Batch) Program() string { return batch.program }

// CommitBudget bounds rendering, enqueueing and kernel commit after a lifetime is sampled.
// It is subtracted from every positive element's original remaining lifetime.
const CommitBudget = 2250 * time.Millisecond

// CleanupScope selects one fixed negative operation, never caller-supplied
// conntrack filters or commands.
type CleanupScope uint8

const (
	// IdentityConnections retires the current published identity cohort.
	IdentityConnections CleanupScope = iota + 1
	// PolicyConnections retires all entries owned by this policy backend.
	PolicyConnections
)

// Options supplies privileged local dependencies, never reader-controlled code.
// Invalidate removes either the published identity cohort or all connections
// carrying the fixed TUN policy marks. Neither operation grants permission.
type Options struct {
	Commit     func(context.Context, Batch) error
	Invalidate func(context.Context, CleanupScope) error
	Clock      func() time.Time
}

// Backend is a serial data publisher. The engine owns lifecycle and persistent
// history; the publisher retains original, nonrenewable evidence in memory.
type Backend struct {
	baseline       policy.Baseline
	hash           string
	options        Options
	gate           chan struct{}
	history        state.Classification
	ownership      policy.Ownership
	bindings       map[string]int
	cleanupPending bool
	configured     bool
}

// New validates an independent copy of the delegation ceiling. Construction is
// inert. The installed program starts closed until persisted history is loaded.
func New(baseline policy.Baseline, options Options) (*Backend, error) {
	if options.Commit == nil || options.Invalidate == nil || options.Clock == nil || baseline.NetworkModel == nil {
		return nil, errors.New("tunpolicy: incomplete dependencies")
	}
	compiler, err := policy.New(baseline)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(baseline)
	if err != nil {
		return nil, err
	}
	baseline, err = policy.DecodeBaseline(data)
	if err != nil {
		return nil, err
	}
	return &Backend{baseline: baseline, hash: compiler.BaselineHash(), options: options,
		gate: make(chan struct{}, 1), history: state.EmptyClassification(), bindings: map[string]int{}}, nil
}

// Enforcement connects the existing authenticated engine to data-only writes.
func (b *Backend) Enforcement() agent.Enforcement {
	return agent.Enforcement{Seal: b.Seal, Apply: b.Apply, RefreshOwnership: b.RefreshOwnership,
		ClearOwnership: b.ClearOwnership, RefreshConfiguration: b.RefreshConfiguration,
		ClearConfiguration: b.ClearConfiguration, Close: b.Close}
}

func (b *Backend) acquire(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("tunpolicy: missing publisher or context")
	}
	select {
	case b.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			b.release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b *Backend) release() { <-b.gate }

func (b *Backend) commit(ctx context.Context, text string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(text) > 16<<20 {
		return errors.New("tunpolicy: transaction exceeds bound")
	}
	bounded, cancel := context.WithTimeout(ctx, CommitBudget)
	defer cancel()
	positive := false
	for _, name := range []string{"tp_started", "tp_bound4", "tp_bound6", "tp_dest4", "tp_dest6", "tp_grants4", "tp_grants6", "tp_echo4", "tp_echo6"} {
		positive = positive || strings.Contains(text, "add element inet lanrith "+name+" ")
	}
	err := b.options.Commit(bounded, Batch{program: text, positive: positive})
	return errors.Join(err, bounded.Err())
}

func flush(names ...string) string {
	var text strings.Builder
	for _, name := range names {
		fmt.Fprintf(&text, "flush set inet lanrith %s\n", name)
	}
	return text.String()
}
func grantsClosed() string { return flush("tp_grants4", "tp_grants6", "tp_echo4", "tp_echo6") }
func bindingsClosed() string {
	return flush("tp_bound4", "tp_bound6", "tp_dest4", "tp_dest6") + "flush set netdev lanrith_identity tp_bound4\nflush set netdev lanrith_identity tp_bound6\n"
}

func (b *Backend) remember(input state.Classification) error {
	checked, err := state.CloneClassification(input)
	if err != nil {
		return err
	}
	next := state.EmptyClassification()
	for i, values := range [][]string{checked.MACs, checked.IPv4, checked.IPv6} {
		old := [][]string{b.history.MACs, b.history.IPv4, b.history.IPv6}[i]
		values = append(values, old...)
		slices.Sort(values)
		values = slices.Compact(values)
		switch i {
		case 0:
			next.MACs = values
		case 1:
			next.IPv4 = values
		case 2:
			next.IPv6 = values
		}
	}
	if _, err := state.CloneClassification(next); err != nil {
		return err
	}
	// Negative history is retained even if the following kernel commit fails;
	// additions are idempotent and the next seal republishes the entire cohort.
	b.history = next
	return nil
}

func (b *Backend) historyProgram() string {
	var text strings.Builder
	for i, values := range [][]string{b.history.MACs, b.history.IPv4, b.history.IPv6} {
		if len(values) != 0 {
			fmt.Fprintf(&text, "add element inet lanrith %s { %s }\n", []string{"tp_history_mac", "tp_history4", "tp_history6"}[i], strings.Join(values, ", "))
			fmt.Fprintf(&text, "add element netdev lanrith_identity %s { %s }\n", []string{"tp_history_mac", "tp_history4", "tp_history6"}[i], strings.Join(values, ", "))
		}
	}
	return text.String()
}

// Seal revokes grants and unions negative history. It never clears classifiers
// or turns a directory outage into loss of owner permission.
func (b *Backend) Seal(ctx context.Context, history state.Classification) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	if err := b.remember(history); err != nil {
		return err
	}
	return b.commit(ctx, grantsClosed()+b.historyProgram())
}

// ClearOwnership closes current bindings and grants before invalidating flows.
// Addresses remain pending until invalidation succeeds, including on retry.
func (b *Backend) ClearOwnership(ctx context.Context) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	return b.clearOwnership(ctx)
}
func (b *Backend) clearOwnership(ctx context.Context) error {
	b.ownership = policy.Ownership{}
	b.bindings = map[string]int{}
	if err := b.commit(ctx, grantsClosed()+bindingsClosed()); err != nil {
		return err
	}
	if b.cleanupPending {
		if err := b.options.Invalidate(ctx, IdentityConnections); err != nil {
			return err
		}
	}
	b.cleanupPending = false
	return nil
}

// RefreshOwnership publishes only current physical interface/MAC/address data.
// A new episode or a gap in freshness cannot retain an earlier connection.
func (b *Backend) RefreshOwnership(ctx context.Context, evidence policy.Ownership) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	snapshot, err := evidence.Snapshot(ctx)
	if err != nil || snapshot.BaselineHash != b.hash {
		return errors.New("tunpolicy: ownership baseline differs")
	}
	old, oldErr := b.ownership.Snapshot(ctx)
	continuous := oldErr == nil && old.Fingerprint == snapshot.Fingerprint
	if continuous {
		for i := range old.Addresses {
			if _, err := b.ownership.Remaining(i, b.options.Clock()); err != nil {
				continuous = false
				break
			}
		}
	}
	if !continuous {
		if err := b.clearOwnership(ctx); err != nil {
			return err
		}
	}
	// Include rendering in the same allowance subtracted from every sampled
	// lifetime. A large collection cannot extend its first elements while the
	// remaining elements are rendered or the program is inspected.
	ctx, cancel := context.WithTimeout(ctx, CommitBudget)
	defer cancel()

	var text strings.Builder
	text.WriteString(bindingsClosed() + flush("tp_cleanup4", "tp_cleanup6"))
	elements := map[string][]string{}
	refs := map[string]int{}
	addresses := map[netip.Addr]bool{}
	for i, address := range snapshot.Addresses {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining, err := evidence.Remaining(i, b.options.Clock())
		if err != nil {
			return err
		}
		ms := (remaining - CommitBudget).Milliseconds()
		if ms <= 0 {
			return errors.New("tunpolicy: ownership expires before commit")
		}
		family := 6
		if address.Address.Is4() {
			family = 4
		}
		bound := fmt.Sprintf("%s . %s . %s timeout %dms", strconv.Quote(address.Interface), address.MAC, address.Address, ms)
		for _, table := range []string{"inet lanrith", "netdev lanrith_identity"} {
			key := fmt.Sprintf("%s tp_bound%d", table, family)
			elements[key] = append(elements[key], bound)
		}
		key := fmt.Sprintf("inet lanrith tp_dest%d", family)
		elements[key] = append(elements[key], fmt.Sprintf("%s . %s timeout %dms", strconv.Quote(address.Interface), address.Address, ms))
		endpoint, err := policy.Resolve(b.baseline, address.Address)
		if err != nil {
			return err
		}
		for _, variant := range endpoint.Variants {
			addresses[variant] = true
		}
		// NAT46's algorithmic source is a negative cleanup selector, not an
		// additional permission or an observed allocation. Retire its peer-side
		// connection as well as the client's original IPv4 connection.
		if prefix := b.baseline.NetworkModel.NAT46Prefix; address.Address.Is4() && prefix != nil {
			translated, original := prefix.Addr().As16(), address.Address.As4()
			copy(translated[12:], original[:])
			addresses[netip.AddrFrom16(translated)] = true
		}
		refs[address.BindingRef] = i
	}
	// Keep negative cleanup selectors after binding withdrawal. They never
	// expire into permission; replace them atomically with the next cohort.
	ordered := make([]netip.Addr, 0, len(addresses))
	for address := range addresses {
		ordered = append(ordered, address)
	}
	slices.SortFunc(ordered, func(a, c netip.Addr) int { return a.Compare(c) })
	counts := map[int]int{}
	for _, address := range ordered {
		family := 6
		if address.Is4() {
			family = 4
		}
		counts[family]++
		if counts[family] > 2*maximumElements {
			return errors.New("tunpolicy: cleanup cohort exceeds capacity")
		}
		key := fmt.Sprintf("inet lanrith tp_cleanup%d", family)
		elements[key] = append(elements[key], address.String())
	}
	// One command per fixed set avoids parsing a separate nft operation for
	// every address. The transaction and all original deadlines stay atomic.
	keys := make([]string, 0, len(elements))
	for key := range elements {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(&text, "add element %s { %s }\n", key, strings.Join(elements[key], ", "))
	}
	if err := b.commit(ctx, text.String()); err != nil {
		return err
	}
	b.ownership, b.bindings = evidence, refs
	b.cleanupPending = len(addresses) != 0
	return nil
}

// Apply projects already validated grants onto same-family original tuples.
// The immutable packet program chooses the client-facing view; no grant may
// renew its directory lifetime or move to another physical binding episode.
func (b *Backend) Apply(ctx context.Context, authorization policy.Authorization, history state.Classification) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	ctx, cancel := context.WithTimeout(ctx, CommitBudget)
	defer cancel()

	if err := b.remember(history); err != nil {
		return err
	}
	candidate, err := authorization.Snapshot(ctx)
	if err != nil || candidate.BaselineHash != b.hash || !b.configured {
		return errors.New("tunpolicy: authorization baseline unavailable")
	}
	entries := map[string]int64{}
	for i, grant := range candidate.Grants {
		reference, err := authorization.BindingReference(ctx, i)
		if err != nil {
			return err
		}
		current, found := b.bindings[reference]
		if !found {
			return errors.New("tunpolicy: grant binding episode is no longer current")
		}
		now := b.options.Clock()
		remaining, err := authorization.Remaining(i, now)
		if err != nil {
			return err
		}
		owned, err := b.ownership.Remaining(current, now)
		if err != nil {
			return err
		}
		ms := (min(remaining, owned) - CommitBudget).Milliseconds()
		if ms <= 0 {
			return errors.New("tunpolicy: grant expires before commit")
		}
		for _, device := range grant.Device.Variants {
			for _, peer := range grant.Peer.Variants {
				if device.Is4() != peer.Is4() {
					continue
				}
				src, dst := device, peer
				if grant.Direction == policy.ToDevice {
					src, dst = peer, device
				}
				family := 6
				if src.Is4() {
					family = 4
				}
				key := fmt.Sprintf("tp_grants%d { %s . %s . %s . %d", family, src, dst, grant.Protocol, grant.Port)
				entries[key] = max(entries[key], ms)
				if len(entries) > maximumElements {
					return errors.New("tunpolicy: grant capacity exceeded")
				}
			}
		}
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var text strings.Builder
	text.WriteString(grantsClosed() + b.historyProgram())
	for _, key := range keys {
		fmt.Fprintf(&text, "add element inet lanrith %s timeout %dms }\n", key, entries[key])
	}
	return b.commit(ctx, text.String())
}

// RefreshConfiguration opens startup only after the engine has restored history.
func (b *Backend) RefreshConfiguration(ctx context.Context, configuration policy.OwnerConfiguration) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	snapshot, err := configuration.Snapshot(ctx)
	if err != nil || snapshot.BaselineHash != b.hash {
		return errors.New("tunpolicy: owner baseline differs")
	}
	if err := b.commit(ctx, b.historyProgram()+"add element inet lanrith tp_started { 0 }\n"); err != nil {
		return err
	}
	b.configured = true
	return nil
}

// ClearConfiguration closes startup and invalidates pre-start marked flows.
func (b *Backend) ClearConfiguration(ctx context.Context) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	b.configured = false
	if err := b.commit(ctx, flush("tp_started")+grantsClosed()+bindingsClosed()); err != nil {
		return err
	}
	return b.options.Invalidate(ctx, PolicyConnections)
}

// Close withdraws both positive channels while retaining classification.
func (b *Backend) Close(ctx context.Context, history state.Classification) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()
	if err := b.remember(history); err != nil {
		return err
	}
	b.configured = false
	b.ownership = policy.Ownership{}
	b.bindings = map[string]int{}
	if err := b.commit(ctx, flush("tp_started")+grantsClosed()+bindingsClosed()+b.historyProgram()); err != nil {
		return err
	}
	return b.options.Invalidate(ctx, PolicyConnections)
}
