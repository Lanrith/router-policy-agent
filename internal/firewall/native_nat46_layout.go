package firewall

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// This constructor is intentionally separate from profile admission. It joins
// the native floor and original raw decisions to all NAT46 legs and, when
// selected, one independently addressed NAT64 component. Qualification of
// this graph cannot activate an installed router profile.
func newNativeNAT46AccessLayout(ctx context.Context, baseline policy.Baseline) (*guardLayout, error) {
	transports := make([]*nativeNAT64Transport, 0, len(baseline.NAT64))
	for _, component := range baseline.NAT64 {
		nat64, err := newNativeNAT64Transport(ctx, baseline, component.ID)
		if err != nil {
			return nil, err
		}
		transports = append(transports, nat64)
	}
	sources, err := newNativeNAT46StaticSources(ctx, baseline)
	if err != nil {
		return nil, err
	}
	extra := []string{"nat46"}
	for _, transport := range transports {
		extra = append(extra, transport.component)
	}
	layout, err := newNativeAccessGeometry(ctx, baseline, sources.model.rules, extra)
	if err != nil {
		return nil, err
	}
	access := layout.native
	access.nat46Sources = sources
	transport, err := newNativeNAT46SharedTransport(ctx, sources)
	if err != nil {
		return nil, err
	}
	access.nat46Transport = transport
	attachments := []string{}
	for _, zone := range baseline.Zones {
		for _, prefix := range zone.Networks {
			if prefix.Addr().Is4() {
				attachments = append(attachments, zone.Interfaces...)
				break
			}
		}
	}
	original := map[int][]nativePacketContext{}
	for index, contexts := range access.contexts {
		for _, packet := range contexts {
			if slices.Contains(attachments, packet.iface) {
				original[index] = append(original[index], packet)
			}
		}
	}
	plan, err := sources.model.contextPlan(ctx, original)
	if err != nil {
		return nil, err
	}
	// Keep unqualified WAN source NAT and service-namespace translation closed.
	// A native LAN target must have a declared source attachment on the return.
	for _, mapping := range sources.model.mappings {
		if mapping.targetInterface == baseline.NetworkModel.UplinkInterface || slices.Contains(access.serviceInterfaces, mapping.targetInterface) {
			return nil, errors.New("firewall: nat46 target requires a qualified native LAN attachment")
		}
		for _, rule := range sources.model.rules.rules {
			for _, from := range rule.From {
				if from.MAC != "" && nativeNAT46Destination([]policy.NetworkSelector{from}, mapping, false) {
					return nil, errors.New("firewall: nat46 reply MAC classes require separate qualification")
				}
			}
		}
	}
	if err := access.compileNAT46(ctx, plan); err != nil {
		return nil, err
	}
	if len(transports) != 0 {
		access.nat64Transports = transports
		if len(transports) == 1 {
			access.nat64Transport = transports[0]
		}
		if err := access.compileNAT64(ctx); err != nil {
			return nil, err
		}
	}
	if err := layout.checkNativeCapacity(ctx); err != nil {
		return nil, err
	}
	if err := layout.freezeInspectionSchemas(ctx); err != nil {
		return nil, err
	}
	return layout, ctx.Err()
}

func mergeNativeChains(into, from map[string][]nativeScope) error {
	for name, rules := range from {
		if prior, exists := into[name]; exists && !reflect.DeepEqual(prior, rules) {
			return errors.New("firewall: conflicting immutable native chains")
		}
		into[name] = rules
	}
	return nil
}

func nativeInterface(field, iface string) nativeScope {
	return nativeMatch(fmt.Sprintf("%s %q", field, iface), guardMeta(field), iface)
}

func (access *nativeAccess) compileNAT46(ctx context.Context, plan *nativeNAT46ContextPlan) error {
	transport := access.nat46Transport
	facts, err := nativeTranslationFacts(ctx)
	if err != nil {
		return err
	}
	handoff, err := plan.handoff(ctx)
	if err != nil {
		return err
	}
	for _, graph := range []map[string][]nativeScope{facts, nativeNAT46ReplyConfirmationFacts(), transport.chains(), handoff} {
		if err := mergeNativeChains(access.inet, graph); err != nil {
			return err
		}
	}
	// Inline the unconditional delegated tail of inherit's directory arm.
	// This preserves return/drop behavior without adding a validator level.
	for index, rule := range plan.model.rules.rules {
		if rule.Action != "allow" || rule.Authorization != "inherit" {
			continue
		}
		for _, hook := range []string{"guard_forward", "permit_flow"} {
			state := fmt.Sprintf("native_%d_%s_original_decision_state", index, hook)
			directory, delegated := state+"_directory", state+"_delegated"
			rules := access.inet[directory]
			if len(rules) > 0 && rules[len(rules)-1].text == "goto "+delegated {
				access.inet[directory] = append(slices.Clone(rules[:len(rules)-1]), access.inet[delegated]...)
				delete(access.inet, delegated)
			}
		}
	}
	// Raw originals retain the complete ordinary native floor and first-match
	// decision. A directory candidate can reach only its bounded translator;
	// the wire policy must prove its grant against the real mapped target.
	for name, rules := range access.inet {
		if !strings.HasPrefix(name, "native_") || !strings.Contains(name, "_original_decision_state") {
			continue
		}
		for i, rule := range rules {
			if rule.text == "jump native_grant" {
				rules[i] = nativeJoin(nativeScope{text: "oifname != \"nat46\"", expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardMeta("oifname"), "right": "nat46"}}}}, rule)
			}
		}
		access.inet[name] = rules
		if strings.HasSuffix(name, "_packet") {
			// The source handoff is the first rule, before this remapping.
			access.inet[name] = slices.Insert(rules, 1,
				nativeJoin(nativeInterface("oifname", "nat46"), nativeVerdict("jump", "native_n46_select_context")),
				nativeJoin(nativeInterface("oifname", "nat46"), nativeVerdict("goto", "native_n46_raw_export")))
		}
	}
	// Inherit also follows the real target's identity policy when its wire
	// interface is hidden behind the TUN at the original decision.
	for index, rule := range plan.model.rules.rules {
		if rule.Action != "allow" || rule.Authorization == "directory" {
			continue
		}
		for _, hook := range []string{"guard_forward", "permit_flow"} {
			chain := fmt.Sprintf("native_%d_%s_original_decision_state", index, hook)
			prefix := []nativeScope{}
			for _, mapping := range plan.model.mappings {
				if !slices.Contains(access.managed, mapping.targetInterface) || !nativeNAT46Destination(rule.To, mapping, false) {
					continue
				}
				target := chain + "_source"
				if rule.Authorization == "inherit" {
					target = chain + "_directory"
				}
				prefix = append(prefix, nativeJoin(nativeInterface("oifname", "nat46"), nativeMatch("ip daddr "+mapping.alias.String(), guardPayload("ip", "daddr"), mapping.alias.String()), nativeVerdict("goto", target)))
			}
			access.inet[chain] = append(prefix, access.inet[chain]...)
		}
	}
	for _, hook := range []string{"guard_forward", "permit_flow"} {
		replyChain := "native_n46_wire_reply"
		if hook == "permit_flow" {
			replyChain += "_confirm"
		}
		// Dispatch only the exact two TUN-facing return/output geometries.
		// Unknown TUN traffic never reaches the ordinary native allow program.
		prefix := []nativeScope{
			nativeJoin(nativeInterface("iifname", "nat46"), nativeVerdict("goto", "native_n46_import")),
			nativeJoin(nativeInterface("oifname", "nat46"), nativeMatch("meta nfproto ipv6", guardMeta("nfproto"), "ipv6"), nativeVerdict("goto", replyChain)),
		}
		position := 0
		if hook == "guard_forward" {
			position = 1 // discard any untrusted incoming admission mark first
		}
		access.inet[hook] = slices.Insert(access.inet[hook], position, prefix...)
		access.inet[hook] = slices.Insert(access.inet[hook], position+len(prefix)+1,
			nativeJoin(nativeInterface("oifname", "nat46"), nativeVerdict("jump", "native_n46_raw_eligible")))
	}
	for _, physical := range []bool{false, true} {
		graph := access.inet
		if physical {
			graph = access.netdev
		}
		for groupIndex := range plan.groups {
			for _, reply := range []bool{false, true} {
				for _, wire := range []bool{false, true} {
					if !wire && !reply {
						continue
					}
					program, err := plan.contextPolicy(ctx, groupIndex, wire, reply, physical)
					if err != nil {
						return err
					}
					if err := mergeNativeChains(graph, program.chains); err != nil {
						return err
					}
					// Entry and terminal rule already bound the exact root
					// context/mapping pair and directory kind. Grant predicates
					// depend on the actual tuple, not that context's number.
					graph[program.grant] = []nativeScope{nativeVerdict("goto", nativeNAT46GrantSelector(wire))}
					selector := "native_n46_wire_policy"
					if !wire {
						selector = "native_n46_raw_policy"
					}
					graph[selector] = append(graph[selector], nativeJoin(plan.groups[groupIndex].binding(plan.model, wire, reply, physical), nativeVerdict("goto", program.entry)))
				}
			}
		}
		for _, selector := range []string{"native_n46_wire_policy", "native_n46_raw_policy"} {
			graph[selector] = append(graph[selector], nativeVerdict("drop", ""))
		}
	}
	if err := access.compileNAT46Handoffs(ctx, plan); err != nil {
		return err
	}
	if err := access.compileNAT46Reverse(ctx, plan); err != nil {
		return err
	}
	for _, leg := range transport.legs {
		if err := ctx.Err(); err != nil {
			return err
		}
		access.compileNAT46Leg(leg)
	}
	access.compileNAT46Common()
	for _, graph := range []map[string][]nativeScope{access.inet, access.netdev} {
		for _, wire := range []bool{false, true} {
			name := nativeNAT46GrantSelector(wire)
			graph[name] = append(graph[name], nativeVerdict("drop", ""))
		}
	}
	for _, name := range []string{"native_n46_import", "native_n46_wire_reply", "native_n46_wire_reply_confirm", "native_n46_raw_export", "native_n46_raw_eligible"} {
		access.add(name, nativeVerdict("drop", ""))
	}
	access.netdev["native_n46_physical"] = append(access.netdev["native_n46_physical"], nativeVerdict("drop", ""))
	for _, reply := range []bool{false, true} {
		for _, tag := range []uint64{nativeNAT46StaticTag(reply), nativeNAT46StaticSourceTag(false, reply), nativeNAT46StaticSourceTag(true, reply)} {
			rules := access.inet["native_egress_kind"]
			access.inet["native_egress_kind"] = slices.Insert(rules, len(rules)-1, nativeJoin(nativeMark(0xff000000, tag), nativeVerdict("return", "")))
		}
	}
	// At raw TUN egress, the original physical ordered/source checks have
	// completed. Grants and native target ownership are enforced on wire egress.
	rawAdmitted := []nativeScope{}
	for _, configuration := range []bool{false, true} {
		_, epoch := epochChannelNames(configuration)
		kinds := []uint64{nativeTag(configuration, false)}
		if !configuration {
			kinds = append(kinds, nativeDirectoryTag(false))
		}
		for _, kind := range kinds {
			rawAdmitted = append(rawAdmitted, nativeJoin(nativeMark(0xff000000, kind), nativePriorityEpoch(epoch), nativeVerdict("goto", "restore_owner_priority")))
		}
	}
	access.netdev["native_n46_raw_admitted"] = append(rawAdmitted, nativeVerdict("drop", ""))
	access.netdev["native_physical_admitted"] = slices.Insert(access.netdev["native_physical_admitted"], 0,
		nativeJoin(nativeInterface("oifname", "nat46"), nativeVerdict("goto", "native_n46_raw_admitted")))
	return ctx.Err()
}

func (leg nativeNAT46Leg) joinName(wire bool, suffix string) string {
	side, direction := "raw", "original"
	if wire {
		side = "wire"
	}
	if leg.reply {
		direction = "reply"
	}
	return fmt.Sprintf("native_n46_join_%s_%s_%s_%s_%s", leg.mapping.id, leg.protocol, side, direction, suffix)
}

func (access *nativeAccess) compileNAT46Handoffs(ctx context.Context, plan *nativeNAT46ContextPlan) error {
	geometry, err := access.nat46Sources.evidence.Snapshot(ctx)
	if err != nil {
		return err
	}
	staticInterfaces := nat46StaticInterfaces(geometry)
	for _, group := range plan.groups {
		if !slices.Contains(staticInterfaces, group.iface) {
			// Managed clients must retain their current NAS IPv4 UID. They
			// have no compiler-owned static geometry to borrow on the wire.
			continue
		}
		for _, directory := range []bool{false, true} {
			contexts := []nativePacketContext{}
			for _, entry := range group.entries {
				if plan.model.directoryRule(entry.rule, group.iface, entry.mapping) == directory {
					contexts = append(contexts, entry.packet)
				}
			}
			if len(contexts) == 0 {
				continue
			}
			name, chains, err := access.nat46Sources.sourceHandoffGroup(ctx, contexts, directory)
			if err != nil {
				return err
			}
			if err := mergeNativeChains(access.inet, chains); err != nil {
				return err
			}
			access.add("native_n46_handoff", nativeMark(0xff000000, map[bool]uint64{false: nativeTag(false, false), true: nativeDirectoryTag(false)}[directory]), nativeMark(uint64(nativeSourceMask), 0), nativeMatch("meta priority & 0x3ff == none", guardBinary("&", guardMeta("priority"), "0:3ff"), "none"), nativeNAT46ContextIDs(group.entries), nativeVerdict("goto", name))
		}
		owners := []nativePacketContext{}
		for _, entry := range group.entries {
			if !plan.model.directoryRule(entry.rule, group.iface, entry.mapping) {
				owners = append(owners, entry.packet)
			}
		}
		if len(owners) > 0 {
			name, chains, err := access.nat46Sources.handoffGroup(ctx, owners)
			if err != nil {
				return err
			}
			if err := mergeNativeChains(access.inet, chains); err != nil {
				return err
			}
			ids := make([]uint64, 0, len(owners))
			for _, original := range owners {
				ids = append(ids, original.id)
			}
			access.add("native_n46_handoff", nativeMark(0xff000000, nativeTag(true, false)), nativeNAT46IDs(ids), nativeVerdict("goto", name))
		}
	}
	access.add("native_n46_handoff", nativeVerdict("return", ""))
	for _, entry := range plan.entries {
		// The original physical chain checks real raw addresses and source
		// ownership again. NAT44-only source classes need no remapping here.
		original := access.contexts[entry.rule][0]
		for _, candidate := range access.contexts[entry.rule] {
			if slices.Contains(entry.originalIDs, candidate.id) {
				original = candidate
				break
			}
		}
		access.netdev["native_n46_physical"] = append(access.netdev["native_n46_physical"], nativeJoin(entry.binding(plan.model, false, false, true), nativeVerdict("goto", original.physicalChain(false))))
	}
	return ctx.Err()
}
