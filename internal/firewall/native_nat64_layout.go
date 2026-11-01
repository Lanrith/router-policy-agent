package firewall

import (
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// newNativeNAT64AccessLayout selects one explicit NAT64 component and joins
// its allocation-zone and tuple objects to the immutable native access graph.
// It remains separate from installed profile admission until all raw/wire
// authorization and physical paths are qualified together.
func newNativeNAT64AccessLayout(ctx context.Context, baseline policy.Baseline, componentID string) (*guardLayout, error) {
	if ctx == nil || len(baseline.NAT46) != 0 || len(baseline.NAT46Pools) != 0 {
		return nil, errors.New("firewall: missing or combined NAT64 access geometry")
	}
	transport, err := newNativeNAT64Transport(ctx, baseline, componentID)
	if err != nil {
		return nil, err
	}
	rules, err := newNativeRuleSet(baseline)
	if err != nil {
		return nil, err
	}
	layout, err := newNativeAccessGeometry(ctx, baseline, rules, []string{transport.component})
	if err != nil {
		return nil, err
	}
	layout.native.nat64Transport = transport
	layout.native.nat64Transports = []*nativeNAT64Transport{transport}
	if err := layout.native.compileNAT64(ctx); err != nil {
		return nil, err
	}
	if err := layout.checkNativeCapacity(ctx); err != nil {
		return nil, err
	}
	if err := layout.freezeInspectionSchemas(ctx); err != nil {
		return nil, err
	}
	return layout, ctx.Err()
}

func newNativeNAT64AggregateAccessLayout(ctx context.Context, baseline policy.Baseline) (*guardLayout, error) {
	if ctx == nil || len(baseline.NAT64) == 0 || len(baseline.NAT46) != 0 || len(baseline.NAT46Pools) != 0 {
		return nil, errors.New("firewall: missing or combined aggregate NAT64 geometry")
	}
	transports := make([]*nativeNAT64Transport, 0, len(baseline.NAT64))
	extra := make([]string, 0, len(baseline.NAT64))
	for _, component := range baseline.NAT64 {
		transport, err := newNativeNAT64Transport(ctx, baseline, component.ID)
		if err != nil {
			return nil, err
		}
		transports, extra = append(transports, transport), append(extra, transport.component)
	}
	rules, err := newNativeRuleSet(baseline)
	if err != nil {
		return nil, err
	}
	layout, err := newNativeAccessGeometry(ctx, baseline, rules, extra)
	if err != nil {
		return nil, err
	}
	layout.native.nat64Transports = transports
	if len(transports) == 1 {
		layout.native.nat64Transport = transports[0]
	}
	if err := layout.native.compileNAT64(ctx); err != nil {
		return nil, err
	}
	if err := layout.checkNativeCapacity(ctx); err != nil {
		return nil, err
	}
	if err := layout.freezeInspectionSchemas(ctx); err != nil {
		return nil, err
	}
	return layout, ctx.Err()
}

func (access *nativeAccess) compileNAT64(ctx context.Context) error {
	transports := access.selectedNAT64Transports()
	if ctx == nil || access == nil || len(transports) == 0 {
		return errors.New("firewall: missing NAT64 access dependencies")
	}
	for _, transport := range transports {
		if err := mergeNativeChains(access.inet, transport.chains()); err != nil {
			return err
		}
		if err := access.compileNAT64CarrierContexts(ctx, transport); err != nil {
			return err
		}
		if err := access.compileNAT64Requests(ctx, transport); err != nil {
			return err
		}
		if err := access.compileNAT64WirePolicy(ctx, transport); err != nil {
			return err
		}
		access.inet["native_n64_zone"] = append(access.inet["native_n64_zone"], transport.zoneRules()...)
		if err := access.compileNAT64RawOrder(ctx, transport); err != nil {
			return err
		}
	}
	if err := access.compileNAT64Flows(ctx, transports); err != nil {
		return err
	}
	return ctx.Err()
}

// compileNAT64Requests records connectivity demand only after the caller has
// applied source validation, attachment guards and managed-source admission.
// It preserves first-match static policy, but deliberately ignores runtime
// authorization: an allocation is connectivity state and never a permission.
// The caller continues into allocation-gated enforcement after this returns.
func (access *nativeAccess) compileNAT64Requests(
	ctx context.Context,
	transport *nativeNAT64Transport,
) error {
	if ctx == nil || access == nil || transport == nil {
		return errors.New("firewall: missing NAT64 request dependencies")
	}
	paths, err := nativeNAT64EgressPolicies(ctx, access.ruleSet, transport)
	if err != nil {
		return err
	}
	chain := transport.name + "_request"
	programs, err := nativeNAT64RawPrograms(ctx, paths)
	if err != nil {
		return err
	}
	for pathIndex, raw := range programs {
		branch := chain + "_path_" + strconv.Itoa(pathIndex)
		access.add(chain, nativeVerdict("jump", branch))
		for index, rule := range raw.rules {
			scopes, err := raw.scopes(ctx, index, false, false)
			if err != nil {
				return err
			}
			for _, scope := range scopes {
				if rule.Action == "deny" {
					access.add(branch, scope, nativeVerdict("return", ""))
					continue
				}
				access.add(branch, scope,
					nativeDynamicUpdate(transport.name+"_pending", "ip6 saddr", guardPayload("ip6", "saddr"), nil),
					nativeVerdict("return", ""))
			}
		}
		access.add(branch, nativeVerdict("return", ""))
	}
	access.add(chain, nativeVerdict("return", ""))
	return ctx.Err()
}

func (access *nativeAccess) compileNAT64RawOrder(ctx context.Context, transport *nativeNAT64Transport) error {
	paths, err := nativeNAT64EgressPolicies(ctx, access.ruleSet, transport)
	if err != nil {
		return err
	}
	if err := access.compileNAT64Carrier(ctx, transport, paths); err != nil {
		return err
	}
	for _, hook := range []string{"guard_forward", "permit_flow"} {
		name := transport.name + "_ordered_" + hook
		geometry := nativeJoin(nativeInterface("oifname", transport.component),
			nativeMatch("ip6 daddr "+transport.prefix.String(), guardPayload("ip6", "daddr"), controllerPrefix(transport.prefix)))
		dispatch := []nativeScope{nativeJoin(geometry, nativeVerdict("goto", name))}
		if hook == "guard_forward" {
			// Demand belongs to the original IPv6 packet, after its source and
			// mandatory floor checks but before an allocation exists. Recording
			// it never skips the allocation, epoch or authorization guards.
			dispatch = slices.Insert(dispatch, 0, nativeJoin(geometry, nativeVerdict("jump", transport.name+"_request")))
		}
		position := slices.IndexFunc(access.inet[hook], func(rule nativeScope) bool { return rule.text == "jump native_denies" })
		if position < 0 {
			return errors.New("firewall: NAT64 ordered dispatch lost mandatory deny boundary")
		}
		access.inet[hook] = slices.Insert(access.inet[hook], position, dispatch...)
	}
	// Correlation maps and their import chains live in the inet table, so the
	// export must live there too. Priority 201 is after the mandatory egress
	// floor (200) and after all source-NAT validation. The later netdev hook
	// still independently enforces the physical tuple and current epoch; an
	// export is short-lived correlation evidence and never grants access.
	for _, leg := range transport.legs {
		accepted := nativeJoin(leg.geometry(false), leg.allocation(transport, false))
		access.add("native_n64_export", accepted, nativeVerdict("jump", leg.name+"_export"))
		// The transport chain returns only after it records the exact tuple.
		// Repeat the immutable leg/allocation predicate so that this accept
		// cannot be reached by a packet that skipped the guarded jump.
		access.add("native_n64_export", accepted, nativeVerdict("accept", ""))
	}
	// The selected attachment is translator-only. A packet that reached this
	// postrouting boundary but did not prove a current allocation, supported
	// protocol/direction and token must not fall through the base-chain accept.
	access.add("native_n64_export", nativeInterface("oifname", transport.component), nativeVerdict("drop", ""))
	return ctx.Err()
}
