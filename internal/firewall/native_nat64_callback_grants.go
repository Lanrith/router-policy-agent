package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

// This construction-only projection installs no rules or forwarding permission.
// Its typed writer retains and independently revalidates the original
// logical authorization, source receipt, allocation ledger and live readiness.
// Generic guarded mutation does not admit the callback component's collections.
func (model *nativeNAT64CallbackModel) projectTargetGrants(ctx context.Context, logical guardChanges, publication *nativeSourcePublication, utc, anchor time.Time, origin *nativeNAT64GrantOrigin) ([]change, error) {
	if ctx == nil || model == nil || model.mapped == nil || model.callback == nil || model.callback.native == nil ||
		model.callback.native.callbacks != model.callback || origin == nil ||
		model.mapped.baselineHash != model.callback.native.baselineHash {
		return nil, errors.New("firewall: missing original NAT64 callback grant dependencies")
	}
	transport := model.callback.native
	if model.mapped.namespace != transport.name+"_callback" || model.mapped.translator() != transport.component || model.mapped.prefix != transport.prefix {
		return nil, errors.New("firewall: NAT64 callback grant changed its selected namespace")
	}
	mappings, err := nativeNAT64GrantMappings(ctx, []*nativeNAT64Transport{transport}, []*nativeNAT64GrantOrigin{origin})
	if err != nil {
		return nil, err
	}
	ready := map[netip.Addr]netip.Addr{}
	for _, mapping := range mappings[0] {
		if mapping.Ready {
			ready[mapping.Alias] = mapping.Source
		}
	}
	selected := *model.mapped
	selected.mappings = nil
	for _, mapping := range model.mapped.mappings {
		if ready[mapping.alias] == mapping.target {
			selected.mappings = append(selected.mappings, mapping)
		}
	}
	filtered, err := model.filterLogicalGrants(ctx, logical)
	if err != nil {
		return nil, err
	}
	return selected.projectTargetGrants(ctx, filtered, publication, utc, anchor)
}

// Filter both publication and independent observation through the same immutable
// caller class. Logical grants alone never authorize a chained translation.
func (model *nativeNAT64CallbackModel) filterLogicalGrants(ctx context.Context, logical guardChanges) (guardChanges, error) {
	filtered := guardChanges{Commands: []change{}}
	for _, command := range logical.Commands {
		if err := ctx.Err(); err != nil {
			return guardChanges{}, err
		}
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family != "inet" || element.Table != ownedTable || element.Name != "lease_to4_tcp" && element.Name != "lease_to4_udp" {
			continue
		}
		values := []json.RawMessage{}
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return guardChanges{}, err
			}
			tuple, err := validateLeasedTuple(raw, true)
			if err != nil {
				return guardChanges{}, err
			}
			if model.eligibleCaller(tuple.peer) {
				values = append(values, raw)
			}
		}
		if len(values) != 0 {
			filtered.Commands = append(filtered.Commands, guardAdd("inet", element.Name, values))
		}
	}
	return filtered, ctx.Err()
}

func (model *nativeNAT64CallbackModel) eligibleCaller(address netip.Addr) bool {
	allowed := false
	for _, prefix := range model.callerClass.Allowed {
		allowed = allowed || prefix.Contains(address)
	}
	for _, prefix := range model.callerClass.Excluded {
		if prefix.Contains(address) {
			return false
		}
	}
	return allowed
}

// Deny-only cleanup never requires a fresh positive source or translator proof.
func (model *nativeNAT64CallbackModel) targetGrantClears() ([]change, error) {
	if model == nil || model.mapped == nil || model.callback == nil || model.callback.native == nil ||
		!generationHash(model.mapped.baselineHash) || model.mapped.namespace != model.callback.native.name+"_callback" {
		return nil, errors.New("firewall: missing NAT64 callback cleanup geometry")
	}
	commands := []change{}
	for _, ref := range nativeMappedTargetGrantRefs(model.mapped.policyNamespace()) {
		commands = append(commands, change{Flush: &setChange{Set: ref}})
	}
	return commands, nil
}
