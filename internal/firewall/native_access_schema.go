package firewall

import (
	"fmt"
	"slices"
)

func nativeChainNames(chains map[string][]nativeScope) []string {
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (access *nativeAccess) inetText() []string {
	lines := ownerPriorityRules(false)
	for _, name := range nativeChainNames(access.inet) {
		header := "chain " + name + " {"
		if hook, priority := nativeInetHook(name); hook != "" {
			header += fmt.Sprintf(" type filter hook %s priority %d; policy accept;", hook, priority)
		}
		lines = append(lines, header)
		lines = append(lines, nativeRulesText(access.inet[name])...)
		lines = append(lines, "}")
	}
	return lines
}

func (access *nativeAccess) netdevText() []string {
	lines := ownerPriorityRules(true)
	for _, name := range nativeChainNames(access.netdev) {
		lines = append(lines, "chain "+name+" {")
		lines = append(lines, nativeRulesText(access.netdev[name])...)
		lines = append(lines, "}")
	}
	return lines
}

func (access *nativeAccess) physicalRules(device string) []nativeScope {
	var rules []nativeScope
	if access.nat46Transport != nil {
		if device == "nat46" {
			return []nativeScope{nativeVerdict("goto", "native_n46_physical")}
		}
		prefix := access.nat46Sources.model.prefix
		for _, field := range []string{"saddr", "daddr"} {
			rules = append(rules, nativeJoin(nativeMatch("ip6 "+field+" "+prefix.String(), guardPayload("ip6", field), controllerPrefix(prefix)), nativeVerdict("goto", "native_n46_physical")))
		}
		for _, mapping := range access.nat46Sources.model.mappings {
			rules = append(rules, nativeJoin(nativeMatch("ip saddr "+mapping.alias.String(), guardPayload("ip", "saddr"), mapping.alias.String()), nativeVerdict("goto", "native_n46_physical")))
		}
	}
	for _, reply := range []bool{false, true} {
		if slices.Contains(access.managed, device) {
			rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeTag(true, reply)), nativeVerdict("drop", "")))
		}
		// A new classified physical identity cannot reuse an unmanaged
		// configuration token, even when its address did not change.
		rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeTag(true, reply)),
			nativeMatch("ether daddr @"+cohortSet, guardPayload("ether", "daddr"), "@"+cohortSet), nativeVerdict("drop", "")))
	}
	rules = append(rules, access.egress[device]...)
	if len(access.asymmetric) != 0 {
		rules = append(rules,
			nativeJoin(nativeMark(0xff000000, nativeAsymmetricTag), nativeVerdict("drop", "")),
			nativeJoin(nativeMatch("meta priority 0xfffffb00", guardMeta("priority"), nativeAsymmetricPriority), nativeVerdict("drop", "")))
	}
	if !slices.Contains(access.serviceInterfaces, device) && len(access.netdev["native_scope_gate"]) != 0 {
		rules = append(rules, nativeVerdict("jump", "native_scope_gate"))
	}
	for _, configuration := range []bool{false, true} {
		for _, reply := range []bool{false, true} {
			rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeTag(configuration, reply)), nativeVerdict("drop", "")))
		}
		_, epoch := epochChannelNames(configuration)
		// Also reject loss of a packet tag while its admission channel remains.
		rules = append(rules, nativeJoin(nativePriorityEpoch(epoch), nativeVerdict("drop", "")))
	}
	for _, reply := range []bool{false, true} {
		rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeDirectoryTag(reply)), nativeVerdict("drop", "")))
		for _, tag := range []uint64{nativeTag(false, reply), nativeTag(true, reply), nativeDirectoryTag(reply)} {
			for _, pending := range []bool{false, true} {
				rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeNATTag(tag, pending)), nativeVerdict("drop", "")))
			}
		}
	}
	rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeCoreNATPending), nativeVerdict("drop", "")))
	rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeCoreNATFinal), nativeVerdict("drop", "")))
	return rules
}

func (access *nativeAccess) egressText(device string) []string {
	return nativeRulesText(access.physicalRules(device))
}

func nativePriorityScopes(restore bool) []nativeScope {
	var rules []nativeScope
	for priority := uint64(0); priority <= 7; priority++ {
		class := "none"
		if priority != 0 {
			class = fmt.Sprintf("0:%x", priority)
		}
		if restore {
			rules = append(rules, nativeJoin(nativeMark(ownerPriorityMask, priority<<10),
				nativeMangle(fmt.Sprintf("meta priority set %d", priority), guardMeta("priority"), class),
				nativeMangle(fmt.Sprintf("meta mark set meta mark & %#x", ownerPriorityKeep), guardMeta("mark"), guardBinary("&", guardMeta("mark"), ownerPriorityKeep)), nativeVerdict("accept", "")))
		} else {
			parts := []nativeScope{nativeMatch(fmt.Sprintf("meta priority %d", priority), guardMeta("priority"), class),
				nativeMangle(fmt.Sprintf("meta mark set meta mark & %#x", ownerPriorityKeep), guardMeta("mark"), guardBinary("&", guardMeta("mark"), ownerPriorityKeep))}
			if priority != 0 {
				parts = append(parts, nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", priority<<10), guardMeta("mark"), guardBinary("|", guardMeta("mark"), priority<<10)))
			}
			rules = append(rules, nativeJoin(append(parts, nativeVerdict("return", ""))...))
		}
	}
	return append(rules, nativeVerdict("drop", ""))
}

func (access *nativeAccess) schema(schema *guardTableSchema, family string, interfaces []string) {
	for name := range schema.chains {
		if name != "validate_source" && name != "validate_target" {
			delete(schema.chains, name)
			delete(schema.rules, name)
		}
	}
	chains := access.inet
	priorityName := "save_owner_priority"
	if family == "netdev" {
		chains, priorityName = access.netdev, "restore_owner_priority"
	}
	for name, rules := range chains {
		schema.chains[name] = map[string]any{"family": family, "table": ownedTable, "name": name}
		schema.rules[name] = nativeRulesExpressions(rules)
	}
	schema.chains[priorityName] = map[string]any{"family": family, "table": ownedTable, "name": priorityName}
	schema.rules[priorityName] = nativeRulesExpressions(nativePriorityScopes(family == "netdev"))
	if family == "inet" {
		for name := range access.inet {
			hook, priority := nativeInetHook(name)
			if hook == "" {
				continue
			}
			schema.chains[name]["type"], schema.chains[name]["hook"] = "filter", hook
			schema.chains[name]["prio"], schema.chains[name]["policy"] = priority, "accept"
		}
		return
	}
	for index, device := range interfaces {
		name := fmt.Sprintf("guard_egress_%d", index)
		schema.chains[name] = map[string]any{"family": family, "table": ownedTable, "name": name, "dev": device,
			"type": "filter", "hook": "egress", "prio": 0, "policy": "accept"}
		schema.rules[name] = append(nativeRulesExpressions(access.corePhysicalEgress(device)), nativeVerdict("jump", "validate_target").expressions)
		if device == "nat46" && access.nat46Transport != nil {
			schema.rules[name] = nil
		}
		schema.rules[name] = append(schema.rules[name], nativeRulesExpressions(access.physicalRules(device))...)
	}
}

func nativeInetHook(name string) (string, int) {
	switch name {
	case "guard_forward":
		return "forward", -150
	case "native_n64_zone":
		return "prerouting", -300
	case "guard_confirm":
		return "forward", 150
	case "native_before_snat":
		return "postrouting", 99
	case "native_after_snat":
		return "postrouting", 101
	case "native_egress_floor":
		return "postrouting", 200
	case "native_n64_export":
		return "postrouting", 201
	default:
		return "", 0
	}
}
