package firewall

import (
	"context"
	"errors"
	"fmt"
)

// Share ordered predicates across contexts with the same original ingress/MAC,
// and protocol. Each terminal branch still checks the exact contexts
// assigned to that original rule. This avoids copying all rules per context.
func (plan *nativeNAT46ContextPlan) wirePolicy(ctx context.Context, groupIndex int, reply, physical bool) (*nativeNAT46Policy, error) {
	return plan.contextPolicy(ctx, groupIndex, true, reply, physical)
}

func (plan *nativeNAT46ContextPlan) contextPolicy(ctx context.Context, groupIndex int, wire, reply, physical bool) (*nativeNAT46Policy, error) {
	if ctx == nil || plan == nil || plan.model == nil || groupIndex < 0 || groupIndex >= len(plan.groups) {
		return nil, errors.New("firewall: missing nat46 mapped policy context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	group := plan.groups[groupIndex]
	direction, family := "original", "inet"
	if reply {
		direction = "reply"
	}
	if physical {
		family = "physical"
	}
	name := fmt.Sprintf("native_n46_context_%d_%s_%s", group.index, direction, family)
	if !wire {
		name += "_raw"
	}
	program := &nativeNAT46Policy{entry: name, grant: fmt.Sprintf("native_n46_context_grant_%d_%s_%s", group.index, direction, family), chains: map[string][]nativeScope{}}
	if !wire {
		program.grant += "_raw"
	}
	ordered := name + "_ordered"
	checks := group.binding(plan.model, wire, reply, physical)
	if !physical {
		checks = nativeJoin(checks, nativeFactsPositiveConnection())
	}
	program.chains[name] = []nativeScope{nativeJoin(checks, nativeVerdict("goto", ordered)), nativeVerdict("drop", "")}
	count := len(program.chains[name])
	for index, rule := range plan.model.rules.rules {
		scopes, err := plan.model.sharedWireScopes(ctx, index, group.entries[0].packet, group.protocol, reply, physical)
		if !wire {
			scopes, err = plan.model.sharedRawScopes(ctx, index, group.entries[0].packet, group.protocol, reply, physical)
		}
		if err != nil {
			return nil, err
		}
		if len(scopes) == 0 {
			continue
		}
		if count+len(scopes)+9 > nativeRuleCapacity {
			return nil, errors.New("firewall: shared nat46 wire policy exceeds capacity")
		}
		branch := fmt.Sprintf("%s_rule_%d", name, index)
		for _, scope := range scopes {
			program.chains[ordered] = append(program.chains[ordered], nativeJoin(scope, nativeVerdict("goto", branch)))
		}
		count += len(scopes)
		owners, directories := []nativeNAT46Context{}, []nativeNAT46Context{}
		for _, entry := range group.entries {
			if entry.rule == index {
				if plan.model.directoryRule(index, group.iface, entry.mapping) {
					directories = append(directories, entry)
				} else {
					owners = append(owners, entry)
				}
			}
		}
		if rule.Action == "deny" || len(owners)+len(directories) == 0 {
			program.chains[branch] = []nativeScope{nativeVerdict("drop", "")}
			count++
			continue
		}
		current := func(entries []nativeNAT46Context) nativeScope {
			checks := nativeNAT46ContextIDs(entries)
			if !physical {
				checks = nativeJoin(checks, nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, index), guardBinary("&", nativeCT("mark"), ownershipRuleMask), index))
			}
			return checks
		}
		if len(directories) > 0 && group.protocol != "icmp" {
			for _, kind := range []uint64{nativeDirectoryTag(reply), nativeNAT46StaticSourceTag(true, reply)} {
				admitted := nativeJoin(current(directories), nativeMark(0xff000000, kind))
				program.chains[branch] = append(program.chains[branch], nativeJoin(admitted, nativeVerdict("jump", program.grant)), nativeJoin(admitted, nativeVerdict("return", "")))
			}
		}
		if len(owners) > 0 {
			for _, kind := range []uint64{nativeTag(false, reply), nativeNAT46StaticTag(reply), nativeNAT46StaticSourceTag(false, reply)} {
				program.chains[branch] = append(program.chains[branch], nativeJoin(current(owners), nativeMark(0xff000000, kind), nativeVerdict("return", "")))
			}
		}
		program.chains[branch] = append(program.chains[branch], nativeVerdict("drop", ""))
		count += len(program.chains[branch])
	}
	program.chains[ordered] = append(program.chains[ordered], nativeVerdict("drop", ""))
	return program, ctx.Err()
}
