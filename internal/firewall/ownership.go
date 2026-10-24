package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	ownership4Set = "current_ownership4"
	ownership6Set = "current_ownership6"
)

// preparedOwnership carries no directory grants. Its positive tuples come
// only from the immutable helper-local ownership proof, not listing contents,
// reader input or a persisted classifier. Integration must still inspect the
// fixed objects and use the shared writer fence before admitting a mutation.
type preparedOwnership struct {
	batch              preparedBatch
	evidence           policy.Ownership
	baselineHash       string
	timeouts           []int
	epochTimeout       int
	digest             [sha256.Size]byte
	clear              bool
	nativeSources      bool
	withdrawNativeIDs  bool
	nat46SourceModel   *nativeNAT46Model
	nat46Previous      *nativeSourcePublication
	nat46ObservedEpoch uint32
	nat64Transport     *nativeNAT64Transport
	nat64Transports    []*nativeNAT64Transport
}

func prepareOwnershipClear(ctx context.Context) (*preparedOwnership, error) {
	data, err := ownershipChanges(ctx, policy.OwnershipSnapshot{}, nil, 0)
	if err != nil {
		return nil, err
	}
	return &preparedOwnership{batch: preparedBatch{data: data}, digest: sha256.Sum256(data), clear: true}, nil
}

func ownershipDefinitions(family string) []string {
	if family != "inet" && family != "netdev" {
		return nil
	}
	return []string{
		guardSetDefinition(ownership4Set, "ifname . ether_addr . ipv4_addr"),
		guardSetDefinition(ownership6Set, "ifname . ether_addr . ipv6_addr"),
	}
}

func ownershipReferences() []objectReference {
	refs := make([]objectReference, 0, 4)
	for _, family := range []string{"inet", "netdev"} {
		for _, name := range []string{ownership4Set, ownership6Set} {
			refs = append(refs, objectReference{Family: family, Table: ownedTable, Name: name})
		}
	}
	return refs
}

// A positive tuple permits only continuing source validation; it is not an
// access verdict. Every classified source still reaches ordered access and
// lease checks afterwards. Both early and final forward hooks call this chain.
func ownershipSourceRules() []string {
	lines := []string{"chain validate_source {"}
	for _, family := range []struct{ protocol, set string }{{"ip", ownership4Set}, {"ip6", ownership6Set}} {
		lines = append(lines, fmt.Sprintf("iifname . ether saddr . %s saddr @%s return", family.protocol, family.set))
	}
	lines = append(lines, "ether saddr @"+cohortSet+" drop",
		"ip saddr @"+classified4Set+" drop", "ip6 saddr @"+classified6Set+" drop", "}")
	return lines
}

func ownershipTargetRules() []string {
	lines := []string{"chain validate_target {"}
	for _, family := range []struct{ protocol, set string }{{"ip", ownership4Set}, {"ip6", ownership6Set}} {
		lines = append(lines, fmt.Sprintf("oifname . ether daddr . %s daddr @%s return", family.protocol, family.set))
	}
	return append(lines, "ether daddr @"+cohortSet+" drop", "}")
}

func ownershipExpressions(source bool) [][]any {
	iface, ether, address := "oifname", "daddr", "daddr"
	if source {
		iface, ether, address = "iifname", "saddr", "saddr"
	}
	var rules [][]any
	for _, family := range []struct{ protocol, set string }{{"ip", ownership4Set}, {"ip6", ownership6Set}} {
		rules = append(rules, []any{guardMatch(map[string]any{"concat": []any{
			guardMeta(iface), guardPayload("ether", ether), guardPayload(family.protocol, address),
		}}, "@"+family.set), map[string]any{"return": nil}})
	}
	rules = append(rules, []any{guardMatch(guardPayload("ether", ether), "@"+cohortSet), map[string]any{"drop": nil}})
	if source {
		for _, family := range []struct{ protocol, set string }{{"ip", classified4Set}, {"ip6", classified6Set}} {
			rules = append(rules, []any{guardMatch(guardPayload(family.protocol, address), "@"+family.set), map[string]any{"drop": nil}})
		}
	}
	return rules
}

func (renderer *renderer) prepareOwnership(
	ctx context.Context,
	evidence policy.Ownership,
	now time.Time,
) (*preparedOwnership, error) {
	started := time.Now()
	if renderer == nil || renderer.compiler == nil || ctx == nil || now.IsZero() {
		return nil, errors.New("firewall: missing ownership preparation dependencies")
	}
	snapshot, err := evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot.BaselineHash != renderer.compiler.BaselineHash() || now.Before(snapshot.CompiledAt) {
		return nil, errors.New("firewall: ownership belongs to a different baseline or clock")
	}
	timeouts := make([]int, len(snapshot.Addresses))
	for index := range snapshot.Addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining, err := evidence.Remaining(index, now)
		if err != nil {
			return nil, err
		}
		timeouts[index] = int((remaining - preparationBudget - commandBudget) / time.Second)
		if timeouts[index] < 1 || timeouts[index] > maximumElementLifetime {
			return nil, errors.New("firewall: ownership has insufficient remaining lifetime")
		}
	}
	epochTimeout := 0
	if snapshot.Epoch != 0 {
		epochTimeout, err = ownershipEpochTimeout(evidence, now)
		if err != nil {
			return nil, err
		}
	}
	data, err := ownershipChanges(ctx, snapshot, timeouts, epochTimeout)
	if err != nil {
		return nil, err
	}
	return &preparedOwnership{batch: preparedBatch{data: data, preparedAt: now,
		startBefore: now.Add(preparationBudget), startedAt: started}, evidence: evidence,
		baselineHash: snapshot.BaselineHash, timeouts: timeouts, epochTimeout: epochTimeout, digest: sha256.Sum256(data)}, nil
}

// ownershipChanges replaces only fixed ownership sets and epoch mirrors. It
// cannot add a rule, set a packet mark or create a forwarding permission.
func ownershipChanges(ctx context.Context, snapshot policy.OwnershipSnapshot, timeouts []int, epochTimeout int) ([]byte, error) {
	if ctx == nil || len(snapshot.Addresses) != len(timeouts) || len(timeouts) > maximumTupleCount {
		return nil, errors.New("firewall: invalid ownership transaction input")
	}
	commands := make([]change, 0, 8)
	for _, ref := range ownershipReferences() {
		commands = append(commands, change{Flush: &setChange{Set: ref}})
	}
	for _, ref := range ownershipReferences() {
		values := make([]json.RawMessage, 0)
		for index, address := range snapshot.Addresses {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if address.Address.Is4() != (ref.Name == ownership4Set) {
				continue
			}
			if timeouts[index] < 1 || timeouts[index] > maximumElementLifetime {
				return nil, errors.New("firewall: ownership lifetime outside bounds")
			}
			value, err := json.Marshal(map[string]any{"elem": map[string]any{
				"timeout": timeouts[index], "val": map[string]any{"concat": []any{
					address.Interface, address.MAC, address.Address.String(),
				}},
			}})
			if err != nil {
				return nil, errors.New("firewall: ownership tuple encoding failed")
			}
			values = append(values, value)
		}
		if len(values) != 0 {
			commands = append(commands, change{Add: &elementChange{Element: elements{
				Family: ref.Family, Table: ref.Table, Name: ref.Name, Values: values,
			}}})
		}
	}
	operations := make([]any, 0, len(commands)+4)
	for _, command := range commands {
		operations = append(operations, command)
	}
	epoch, err := ownershipEpochChanges(snapshot.Epoch, epochTimeout)
	if err != nil {
		return nil, err
	}
	operations = append(operations, epoch...)
	data, err := json.Marshal(map[string]any{"nftables": operations})
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: ownership transaction encoding or capacity failed")
	}
	return data, ctx.Err()
}

// validateOwnershipPreparation rederives the exact program from its proof and
// checks that queueing has not consumed its absolute deadline. Diagnostic
// snapshots and byte programs cannot substitute for that local proof.
func validateOwnershipPreparation(ctx context.Context, prepared *preparedOwnership, utc time.Time) error {
	if ctx == nil || prepared == nil || utc.IsZero() {
		return errors.New("firewall: missing ownership validation dependencies")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if sha256.Sum256(prepared.batch.data) != prepared.digest {
		return errors.New("firewall: prepared ownership bytes changed")
	}
	if prepared.clear {
		expected, err := prepared.expectedData(ctx, policy.OwnershipSnapshot{})
		if err != nil || !bytes.Equal(expected, prepared.batch.data) || len(prepared.timeouts) != 0 ||
			prepared.epochTimeout != 0 || prepared.baselineHash != "" || !prepared.batch.startedAt.IsZero() ||
			!prepared.batch.preparedAt.IsZero() || !prepared.batch.startBefore.IsZero() {
			return errors.New("firewall: ownership revocation differs from fixed empty replacement")
		}
		return ctx.Err()
	}
	snapshot, err := prepared.evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.BaselineHash != prepared.baselineHash || len(prepared.timeouts) != len(snapshot.Addresses) {
		return errors.New("firewall: prepared ownership proof changed")
	}
	if snapshot.Epoch != 0 {
		remaining, err := prepared.evidence.EpochRemaining(utc)
		if err != nil || prepared.epochTimeout < 1 || prepared.epochTimeout > maximumElementLifetime ||
			time.Duration(prepared.epochTimeout)*time.Second+commandBudget > remaining {
			return errors.New("firewall: prepared ownership epoch escaped its original deadline")
		}
	}
	for index, timeout := range prepared.timeouts {
		remaining, err := prepared.evidence.Remaining(index, utc)
		if err != nil {
			return err
		}
		if timeout < 1 || timeout > maximumElementLifetime || time.Duration(timeout)*time.Second+commandBudget > remaining {
			return errors.New("firewall: prepared ownership deadline escaped its source")
		}
	}
	expected, err := prepared.expectedData(ctx, snapshot)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, prepared.batch.data) {
		return errors.New("firewall: ownership tuple or scope differs from its proof")
	}
	return ctx.Err()
}

// Listings may verify shape and mirrors, but never become fresh evidence.
func (layout *guardLayout) inspectOwnership(ctx context.Context, inet, netdev *guardTableObservation) error {
	if !layout.ownership {
		return nil
	}
	for _, name := range []string{ownership4Set, ownership6Set} {
		first, err := listedGuardLeases(ctx, inet.sets[name].Elements)
		if err != nil {
			return err
		}
		second, err := listedGuardLeases(ctx, netdev.sets[name].Elements)
		if err != nil {
			return err
		}
		if err := sameGuardElements(ctx, first, second); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, raw := range first {
			var element struct {
				Value struct {
					Fields []string `json:"concat"`
				} `json:"val"`
				Timeout int `json:"timeout"`
			}
			if err := decodeNested(raw, "elem", &element, []string{"val", "timeout"}); err != nil {
				return err
			}
			fields := element.Value.Fields
			if len(fields) != 3 || !slices.Contains(layout.managedInterfaces, fields[0]) {
				return errors.New("firewall: ownership observation has invalid attachment")
			}
			mac, err := policy.CanonicalMAC(fields[1])
			if err != nil || mac != fields[1] {
				return errors.New("firewall: ownership observation has invalid identity")
			}
			address, err := netip.ParseAddr(fields[2])
			if err != nil || !address.IsGlobalUnicast() || address.Is4In6() || address.Zone() != "" ||
				address.String() != fields[2] || address.Is4() != (name == ownership4Set) || seen[strings.Join(fields, "\x00")] {
				return errors.New("firewall: ownership observation has invalid address or duplicate tuple")
			}
			seen[strings.Join(fields, "\x00")] = true
		}
	}
	return inspectOwnershipEpoch(ctx, inet)
}
