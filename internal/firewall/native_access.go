package firewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const (
	nativeTagMask = uint64(0xff0003ff)
)

// nativeAccess is immutable image-generation plumbing. It is not a runtime
// rule update. The constructor deliberately excludes translators: their tuple
// projections, bootstrap services, NAT and correlated errors still require
// separate integration before an image may activate this native component.
type nativeAccess struct {
	baselineHash      string
	ruleSet           *nativeRuleSet
	inet              map[string][]nativeScope
	netdev            map[string][]nativeScope
	egress            map[string][]nativeScope
	contexts          map[int][]nativePacketContext
	physicalRuleCount int
	managed           []string
	core              []nativeCoreScope
	asymmetric        []nativeAsymmetricScope
	coreEgress        map[string][]nativeScope
	sourceGuards      map[string]string
	serviceInterfaces []string
	// A complete translated layout must select its original geometry here.
	// The ordinary native constructor leaves translators unselected.
	nat46Sources    *nativeNAT46StaticSources
	nat46Transport  *nativeNAT46Transport
	nat64Transports []*nativeNAT64Transport
	// nat64Transport is retained as the singular compatibility selector used
	// by component-level tests and publication APIs. Aggregate runtime paths
	// must use nat64Transports and reject an ambiguous singular operation.
	nat64Transport *nativeNAT64Transport
}

func (access *nativeAccess) selectedNAT64Transports() []*nativeNAT64Transport {
	if access == nil {
		return nil
	}
	if len(access.nat64Transports) != 0 {
		return slices.Clone(access.nat64Transports)
	}
	if access.nat64Transport != nil {
		return []*nativeNAT64Transport{access.nat64Transport}
	}
	return nil
}

func newNativeAccessLayout(ctx context.Context, baseline policy.Baseline) (*guardLayout, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing native access context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	set, err := newNativeRuleSet(baseline)
	if err != nil {
		return nil, err
	}
	if len(baseline.NAT64) != 0 || len(baseline.NAT46) != 0 || len(baseline.NAT46Pools) != 0 {
		return nil, errors.New("firewall: native access requires translator-free geometry")
	}
	return newNativeAccessGeometry(ctx, baseline, set, nil)
}

// Build only from a validated, owned rule set. Translator constructors must
// install every exceptional attachment and its complete guards before return.
func newNativeAccessGeometry(ctx context.Context, baseline policy.Baseline, set *nativeRuleSet, extra []string) (*guardLayout, error) {
	ownedSet, err := newNativeRuleSet(baseline)
	if err != nil || set == nil || set.baselineHash == "" || set.baselineHash != ownedSet.baselineHash {
		return nil, errors.New("firewall: native access rules differ from baseline")
	}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		return nil, err
	}
	layout.interfaces = append(layout.interfaces, extra...)
	layout.interfaces = append(layout.interfaces, baseline.NetworkModel.UplinkInterface)
	layout.interfaces = append(layout.interfaces, coreInterfaces(baseline)...)
	slices.Sort(layout.interfaces)
	layout.interfaces = slices.Compact(layout.interfaces)
	managed := []string{}
	for _, zone := range baseline.Zones {
		if baseline.DirectoryManaged(zone.Role) {
			managed = append(managed, zone.Interfaces...)
		}
	}
	slices.Sort(managed)
	managed = slices.Compact(managed)
	access := &nativeAccess{baselineHash: set.baselineHash, ruleSet: set, inet: map[string][]nativeScope{}, netdev: map[string][]nativeScope{}, egress: map[string][]nativeScope{}, managed: slices.Clone(managed)}
	if err := access.compileAsymmetric(ctx, baseline); err != nil {
		return nil, err
	}
	if err := access.compileFloor(ctx, baseline, layout.interfaces); err != nil {
		return nil, err
	}
	if err := access.compileCore(ctx, baseline); err != nil {
		return nil, err
	}
	// Extra translator attachments use their explicit four-leg dispatch. They
	// never enter an ordinary native context selector, including for replies.
	contextInterfaces := slices.DeleteFunc(slices.Clone(layout.interfaces), func(iface string) bool { return slices.Contains(extra, iface) })
	if err := access.compileContexts(ctx, set, contextInterfaces); err != nil {
		return nil, err
	}
	if err := access.compile(ctx, set, managed, layout.interfaces); err != nil {
		return nil, err
	}
	if err := access.compileNAT(ctx, set, baseline); err != nil {
		return nil, err
	}
	if err := access.checkCapacity(layout.interfaces); err != nil {
		return nil, err
	}
	layout.native = access
	if err := layout.checkNativeCapacity(ctx); err != nil {
		return nil, err
	}
	return layout, nil
}

func nativeJoin(parts ...nativeScope) nativeScope {
	var text []string
	var expressions []any
	for _, part := range parts {
		if part.text != "" {
			text = append(text, part.text)
		}
		expressions = append(expressions, part.expressions...)
	}
	return nativeScope{text: strings.Join(text, " "), expressions: expressions}
}

func nativeMatch(text string, left, right any) nativeScope {
	return nativeScope{text: text, expressions: []any{guardMatch(left, right)}}
}

func nativeVerdict(name, target string) nativeScope {
	if target == "" {
		return nativeScope{text: name, expressions: []any{map[string]any{name: nil}}}
	}
	return nativeScope{text: name + " " + target, expressions: []any{map[string]any{name: map[string]any{"target": target}}}}
}

func nativeState(value string) nativeScope {
	return nativeScope{text: "ct state " + value, expressions: []any{controllerCTState(value)}}
}

func nativeCT(key string) any { return map[string]any{"ct": map[string]any{"key": key}} }

func nativeMangle(text string, key, value any) nativeScope {
	return nativeScope{text: text, expressions: []any{map[string]any{"mangle": map[string]any{"key": key, "value": value}}}}
}

func nativeMark(mask, value uint64) nativeScope {
	return nativeMatch(fmt.Sprintf("meta mark & %#x == %#x", mask, value), guardBinary("&", guardMeta("mark"), mask), value)
}

func nativeEpoch(configuration bool) (string, string, string, string) {
	set, mapping := ownershipEpochSet, ownershipEpochMap
	if configuration {
		set, mapping = configurationEpochSet, configurationEpochMap
	}
	channel, physical := epochChannelNames(configuration)
	return set, mapping, channel, physical
}

func nativeTag(configuration, reply bool) uint64 {
	tag := uint64(0xd1000000)
	if configuration {
		tag += 0x02000000
	}
	if reply {
		tag += 0x01000000
	}
	return tag
}

func (access *nativeAccess) add(chain string, parts ...nativeScope) {
	access.inet[chain] = append(access.inet[chain], nativeJoin(parts...))
}

func (access *nativeAccess) compile(ctx context.Context, set *nativeRuleSet, managed, interfaces []string) error {
	for _, hook := range []string{"guard_forward", "permit_flow"} {
		if hook == "guard_forward" {
			access.add(hook, nativeMangle("meta mark set meta mark & "+guardMarkKeep, guardMeta("mark"),
				guardBinary("&", guardMeta("mark"), uint64(0x00ff0000))))
		}
		if len(access.asymmetric) != 0 {
			stage := "confirm"
			if hook == "guard_forward" {
				stage = "guard"
			}
			access.add(hook, nativeVerdict("jump", "native_asymmetric_"+stage))
		}
		access.add(hook, nativeState("invalid"), nativeVerdict("drop", ""))
		access.add(hook, nativeVerdict("jump", "native_raw_floor"))
		access.add(hook, nativeVerdict("jump", "native_forward_floor"))
		if len(access.core) != 0 {
			access.add(hook, nativeVerdict("jump", "native_core_"+hook))
		}
		access.closeServiceAttachments(hook)
		access.add(hook, nativeVerdict("jump", "validate_source"))
		for _, iface := range managed {
			access.add(hook, nativeMatch(fmt.Sprintf("iifname %q", iface), guardMeta("iifname"), iface), nativeVerdict("jump", "native_source"))
		}
		access.add(hook, nativeVerdict("jump", "native_denies"))
		access.add(hook, nativeMatch("ct direction reply", nativeCT("direction"), "reply"), nativeVerdict("jump", "native_reply_"+hook))
		access.add(hook, nativeVerdict("goto", "native_ordered_"+hook))
	}
	access.add("guard_confirm", nativeVerdict("jump", "permit_flow"))
	access.add("guard_confirm", nativeVerdict("drop", ""))
	for _, family := range []struct{ spelling, set string }{{"ip", ownership4Set}, {"ip6", ownership6Set}} {
		access.add("native_source", nativeMatch("iifname . ether saddr . "+family.spelling+" saddr @"+family.set,
			map[string]any{"concat": []any{guardMeta("iifname"), guardPayload("ether", "saddr"), guardPayload(family.spelling, "saddr")}}, "@"+family.set), nativeVerdict("return", ""))
	}
	access.add("native_source", nativeVerdict("drop", ""))
	access.compileGrantChecks()
	access.compileSourceHandoff()
	access.compilePhysicalSource()
	access.compilePhysicalOwnership()
	for index, rule := range set.rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		budget, err := access.ruleBudget(ctx, set, index, managed, interfaces)
		if err != nil {
			return err
		}
		// Four terminal hook rules are appended after the ordered program.
		before := access.ruleCount(interfaces)
		if before+budget+4 > nativeRuleCapacity {
			return errors.New("firewall: native access expansion exceeds capacity")
		}
		scopes, err := set.scopes(ctx, index, false, false)
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			verdict := "return"
			if rule.Action == "deny" {
				verdict = "drop"
			}
			access.add("native_denies", scope, nativeVerdict(verdict, ""))
		}
		for _, hook := range []string{"guard_forward", "permit_flow"} {
			for _, scope := range scopes {
				if rule.Action == "deny" {
					access.add("native_ordered_"+hook, scope, nativeVerdict("drop", ""))
				} else {
					access.add("native_ordered_"+hook, scope, nativeVerdict("goto", fmt.Sprintf("native_%d_%s_original", index, hook)))
				}
			}
			if rule.Action == "deny" {
				continue
			}
			reverse, err := set.scopes(ctx, index, true, false)
			if err != nil {
				return err
			}
			for _, scope := range reverse {
				access.add("native_reply_"+hook,
					nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, index), guardBinary("&", nativeCT("mark"), ownershipRuleMask), index),
					scope, nativeVerdict("goto", fmt.Sprintf("native_%d_%s_reply", index, hook)))
			}
			for _, reply := range []bool{false, true} {
				access.compileDecision(index, rule, hook, reply, managed)
			}
		}
		if rule.Action == "allow" {
			if err := access.compilePhysical(ctx, set, index, interfaces); err != nil {
				return err
			}
		}
		if access.ruleCount(interfaces)-before != budget {
			return errors.New("firewall: native rule budget differs from generated program")
		}
	}
	for _, hook := range []string{"guard_forward", "permit_flow"} {
		access.add("native_reply_"+hook, nativeVerdict("return", ""))
		access.add("native_ordered_"+hook, nativeVerdict("drop", ""))
	}
	return access.checkCapacity(interfaces)
}

func (access *nativeAccess) ruleCount(interfaces []string) int {
	count := 0
	for _, iface := range interfaces {
		count += len(access.corePhysicalEgress(iface))
	}
	for _, family := range []map[string][]nativeScope{access.inet, access.netdev, access.egress} {
		for _, rules := range family {
			count += len(rules)
		}
	}
	return count
}

func (access *nativeAccess) checkCapacity(interfaces []string) error {
	if access.ruleCount(interfaces) > nativeRuleCapacity {
		return errors.New("firewall: native access program exceeds capacity")
	}
	return nil
}

func (access *nativeAccess) compileDecision(index int, rule policy.NetworkRule, hook string, reply bool, managed []string) {
	direction, states := "original", []string{"established", "new"}
	if reply {
		direction, states = "reply", []string{"established"}
	}
	chain := fmt.Sprintf("native_%d_%s_%s", index, hook, direction)
	state := nativeMatch("ct state { "+strings.Join(states, ", ")+" }", nativeCT("state"), map[string]any{"set": states})
	if len(states) == 1 {
		state = nativeState("established")
	}
	// Both failed predicates previously reached an unconditional drop through
	// two wrappers. Keep their conjunction and the same drop in one entry.
	access.add(chain, nativeMatch("ct direction "+direction, nativeCT("direction"), direction), state, nativeVerdict("jump", chain+"_decision_state"))
	access.add(chain, nativeVerdict("drop", ""))
	chain += "_decision_state"
	if rule.Authorization == "directory" {
		access.add(chain, nativeVerdict("jump", "native_grant"))
		access.add(chain, nativeVerdict("goto", chain+"_delegated"))
	} else {
		for _, iface := range managed {
			for _, field := range []string{"iifname", "oifname"} {
				target := chain + "_source"
				if rule.Authorization == "inherit" {
					target = chain + "_directory"
				}
				access.add(chain, nativeMatch(fmt.Sprintf("%s %q", field, iface), guardMeta(field), iface), nativeVerdict("goto", target))
			}
		}
		access.add(chain, nativeMatch("ether saddr @"+cohortSet, guardPayload("ether", "saddr"), "@"+cohortSet), nativeVerdict("goto", chain+"_source"))
		for _, family := range []struct{ protocol, set string }{{"ip", classified4Set}, {"ip6", classified6Set}} {
			for _, field := range []string{"saddr", "daddr"} {
				access.add(chain, nativeMatch(family.protocol+" "+field+" @"+family.set, guardPayload(family.protocol, field), "@"+family.set), nativeVerdict("goto", chain+"_source"))
			}
		}
		access.add(chain, nativeVerdict("goto", chain+"_configuration"))
		if rule.Authorization == "inherit" {
			access.add(chain+"_directory", nativeVerdict("jump", "native_grant"))
			access.add(chain+"_directory", nativeVerdict("goto", chain+"_delegated"))
		}
	}
	for _, configuration := range []bool{false, true} {
		if rule.Authorization == "directory" {
			continue
		}
		name := chain + "_source"
		if configuration {
			name = chain + "_configuration"
		}
		access.compileToken(name, index, hook, reply, configuration, false)
	}
	if rule.Authorization != "owner" {
		access.compileToken(chain+"_delegated", index, hook, reply, false, true)
	}
}

func (access *nativeAccess) compileToken(chain string, index int, hook string, reply, configuration, directory bool) {
	set, mapping, _, _ := nativeEpoch(configuration)
	flowTag := nativeTag(configuration, reply)
	if directory {
		flowTag = nativeDirectoryTag(reply)
	}
	tag := flowTag | uint64(index) // #nosec G115 -- validated rule indices are 0..1023.
	if hook == "guard_forward" && !reply {
		stamp := []nativeScope{nativeMatch("ct mark 0", nativeCT("mark"), 0),
			nativeState("new"),
			nativeMangle("ct mark set meta nfproto map @"+mapping, nativeCT("mark"), map[string]any{"map": map[string]any{"key": guardMeta("nfproto"), "data": "@" + mapping}})}
		if index != 0 {
			stamp = append(stamp, nativeMangle(fmt.Sprintf("ct mark set ct mark | %d", index), nativeCT("mark"), guardBinary("|", nativeCT("mark"), index)))
		}
		access.add(chain, stamp...)
	}
	checks := nativeJoin(
		nativeMatch(fmt.Sprintf("ct mark & %#x @%s", ownershipEpochMask, set), guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+set),
		nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, index), guardBinary("&", nativeCT("mark"), ownershipRuleMask), index))
	if hook == "permit_flow" {
		checks = nativeJoin(nativeMark(nativeTagMask, tag), checks)
	}
	access.add(chain, checks, nativeVerdict("goto", chain+"_admitted"))
	access.add(chain, nativeVerdict("drop", ""))
	chain += "_admitted"
	stamp := []nativeScope{nativeMangle("meta mark set meta mark & "+guardMarkKeep, guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0x00ff0000))),
		nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", tag), guardMeta("mark"), guardBinary("|", guardMeta("mark"), tag))}

	if hook == "permit_flow" {
		if len(access.contexts[index]) == 0 {
			access.add(chain, append(stamp, nativeVerdict("drop", ""))...)
			return
		}
		direction := "original"
		if reply {
			direction = "reply"
		}
		selection := fmt.Sprintf("native_%d_context_%s", index, direction)
		if _, exists := access.inet[selection]; !exists {
			access.add(selection, nativeVerdict("jump", "save_owner_priority"))
			for _, packetContext := range access.contexts[index] {
				parts := []nativeScope{packetContext.predicate, nativeMangle("meta mark set meta mark & 0xfffffc00", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xfffffc00)))}
				if packetContext.id != 0 {
					parts = append(parts, nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", packetContext.id), guardMeta("mark"), guardBinary("|", guardMeta("mark"), packetContext.id)))
				}
				access.add(selection, append(parts, nativeVerdict("return", ""))...)
			}
			access.add(selection, nativeVerdict("drop", ""))
		}
		// The caller checks its exact kind, rule and epoch before entering
		// this shared selector, then checks its own epoch again after source
		// handoff. Only ingress/MAC/address selection is shared across kinds.
		access.add(chain, append(stamp, nativeVerdict("jump", selection))...)
		continuation := chain + "_packet"
		access.add(chain, nativeVerdict("goto", continuation))
		handoff := "native_source_handoff"
		if configuration {
			handoff = "native_configuration_handoff"
		}
		access.add(continuation, nativeVerdict("jump", handoff))
		access.add(continuation, nativeMark(0xff000000, flowTag),
			nativeMatch(fmt.Sprintf("ct mark & %#x @%s", ownershipEpochMask, set), guardBinary("&", nativeCT("mark"), ownershipEpochMask), "@"+set),
			nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, index), guardBinary("&", nativeCT("mark"), ownershipRuleMask), index), nativeVerdict("accept", ""))
		access.add(continuation, nativeVerdict("drop", ""))
	} else {
		access.add(chain, append(stamp, nativeVerdict("accept", ""))...)
	}
}

func (access *nativeAccess) compilePhysical(ctx context.Context, set *nativeRuleSet, index int, _ []string) error {
	for _, reply := range []bool{false, true} {
		for _, group := range nativePhysicalContexts(access.contexts[index], reply) {
			packetContext := group.packet
			selected := set.physicalRule(index, packetContext, reply, false, "")
			scopes, err := (&nativeRuleSet{rules: []policy.NetworkRule{selected}}).scopes(ctx, 0, reply, true)
			if err != nil {
				return err
			}
			kinds := nativePhysicalKinds(set.rules[index].Authorization, reply, group.ids)
			for _, scope := range scopes {
				access.netdev["native_scope_gate"] = append(access.netdev["native_scope_gate"], nativeJoin(
					kinds, scope, nativeVerdict("goto", packetContext.physicalChain(reply))))
			}
		}
	}
	return nil
}

// Each kind reaches its mandatory epoch check in native_physical_admitted.
// Sharing the tuple predicate never merges owner and directory authorization.
func nativePhysicalKinds(authorization string, reply bool, ids []uint64) nativeScope {
	values := []uint64{}
	spelling := []string{}
	for mode := range 3 {
		if authorization == "owner" && mode == 2 || authorization == "directory" && mode != 2 {
			continue
		}
		tag := nativeTag(mode == 1, reply)
		if mode == 2 {
			tag = nativeDirectoryTag(reply)
		}
		for _, id := range ids {
			values = append(values, tag|id)
		}
	}
	slices.Sort(values)
	for _, value := range values {
		spelling = append(spelling, fmt.Sprintf("%#x", value))
	}
	if len(values) == 1 {
		return nativeMark(nativeTagMask, values[0])
	}
	return nativeMatch(fmt.Sprintf("meta mark & %#x { %s }", nativeTagMask, strings.Join(spelling, ", ")),
		guardBinary("&", guardMeta("mark"), nativeTagMask), map[string]any{"set": values})
}

func (access *nativeAccess) compilePhysicalOwnership() {
	for _, iface := range access.managed {
		access.netdev["native_physical_admitted"] = append(access.netdev["native_physical_admitted"], nativeJoin(nativeMatch(fmt.Sprintf("oifname %q", iface), guardMeta("oifname"), iface), nativeVerdict("jump", "native_target")))
	}
	for _, family := range []struct{ protocol, set string }{{"ip", classified4Set}, {"ip6", classified6Set}} {
		access.netdev["native_physical_admitted"] = append(access.netdev["native_physical_admitted"], nativeJoin(nativeMatch(family.protocol+" daddr @"+family.set, guardPayload(family.protocol, "daddr"), "@"+family.set), nativeVerdict("jump", "native_target")))
	}
	for _, reply := range []bool{false, true} {
		access.netdev["native_physical_admitted"] = append(access.netdev["native_physical_admitted"], nativeJoin(nativeMark(0xff000000, nativeDirectoryTag(reply)), nativeVerdict("goto", "native_physical_directory")))
	}
	access.netdev["native_physical_directory"] = []nativeScope{nativeVerdict("jump", "native_grant"), nativeVerdict("goto", "native_final_source")}
	for _, configuration := range []bool{false, true} {
		name := "native_final_source"
		if configuration {
			name = "native_final_configuration"
		}
		for _, reply := range []bool{false, true} {
			access.netdev["native_physical_admitted"] = append(access.netdev["native_physical_admitted"], nativeJoin(nativeMark(0xff000000, nativeTag(configuration, reply)), nativeVerdict("goto", name)))
		}
		_, _, _, epoch := nativeEpoch(configuration)
		access.netdev[name] = []nativeScope{nativeJoin(nativePriorityEpoch(epoch), nativeMangle("meta mark set meta mark & 0xffff1fff", guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0xffff1fff))), nativeVerdict("goto", "restore_owner_priority")), nativeVerdict("drop", "")}
	}
	access.netdev["native_physical_admitted"] = append(access.netdev["native_physical_admitted"], nativeVerdict("drop", ""))
	var target []nativeScope
	for _, family := range []struct{ spelling, set string }{{"ip", ownership4Set}, {"ip6", ownership6Set}} {
		target = append(target, nativeJoin(nativeMatch("oifname . ether daddr . "+family.spelling+" daddr @"+family.set,
			map[string]any{"concat": []any{guardMeta("oifname"), guardPayload("ether", "daddr"), guardPayload(family.spelling, "daddr")}}, "@"+family.set), nativeVerdict("return", "")))
	}
	access.netdev["native_target"] = append(target, nativeVerdict("drop", ""))

}

func nativeRulesText(rules []nativeScope) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.text)
	}
	return result
}

func nativeRulesExpressions(rules []nativeScope) [][]any {
	result := make([][]any, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.expressions)
	}
	return result
}
