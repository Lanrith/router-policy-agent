package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// nativeNAT46Transport correlates a translator output with a recently admitted
// input. Its chains only return or drop: they never grant forwarding. The caller
// must check ordered scope, current grants and physical ownership independently
// before export and after import, including at final physical egress.
type nativeNAT46Transport struct {
	legs            []nativeNAT46Leg
	staticGeometry  policy.NAT46StaticGeometry
	sourceGeometry  bool
	shareValidation bool
}

// Static IDs belong to an independent compiler-owned namespace. The ordinary
// transport cannot consume them; enabling this path requires the original
// geometry, whose publication also requires current owner configuration.
func newNativeNAT46StaticTransport(ctx context.Context, sources *nativeNAT46StaticSources) (*nativeNAT46Transport, error) {
	if ctx == nil || sources == nil || sources.model == nil {
		return nil, errors.New("firewall: missing static nat46 transport evidence")
	}
	geometry, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if geometry.Prefix != sources.model.prefix || geometry.BaselineHash != sources.model.baselineHash {
		return nil, errors.New("firewall: static nat46 transport prefix differs")
	}
	// Include the extra fixed namespace and exact static-source branches in
	// the product bound before allocating any packet-rule collections.
	if len(sources.model.mappings) > (nativeRuleCapacity-45)/232 {
		return nil, errors.New("firewall: static nat46 tuple transport exceeds capacity")
	}
	transport, err := newNativeNAT46Transport(ctx, sources.model)
	if err != nil {
		return nil, err
	}
	transport.staticGeometry = sources.evidence
	return transport, ctx.Err()
}

// Source-epoch GIDs use the same original static geometry, in a distinct
// namespace. A current source-epoch channel and current native target ownership
// are still mandatory. The ordinary transport cannot consume these IDs.
func newNativeNAT46SourceTransport(ctx context.Context, sources *nativeNAT46StaticSources) (*nativeNAT46Transport, error) {
	if ctx == nil || sources == nil || sources.model == nil {
		return nil, errors.New("firewall: missing source-epoch nat46 transport geometry")
	}
	if len(sources.model.mappings) > (nativeRuleCapacity-45)/384 {
		return nil, errors.New("firewall: source-epoch nat46 transport exceeds capacity")
	}
	transport, err := newNativeNAT46StaticTransport(ctx, sources)
	if err != nil {
		return nil, err
	}
	transport.sourceGeometry = true
	return transport, ctx.Err()
}

// The original geometry remains mandatory; only duplicate validation code is
// shared. Each selected leg retains its own maps, tuple proof and record chain.
func newNativeNAT46SharedTransport(ctx context.Context, sources *nativeNAT46StaticSources) (*nativeNAT46Transport, error) {
	transport, err := newNativeNAT46SourceTransport(ctx, sources)
	if err != nil {
		return nil, err
	}
	transport.shareValidation = true
	return transport, ctx.Err()
}

type nativeNAT46Leg struct {
	name, protocol string
	mapping        nativeNAT46Mapping
	prefix         netip.Prefix
	reply          bool
}

func newNativeNAT46Transport(ctx context.Context, model *nativeNAT46Model) (*nativeNAT46Transport, error) {
	if ctx == nil || model == nil || !model.prefix.IsValid() || model.prefix.Bits() != 96 {
		return nil, errors.New("firewall: missing nat46 tuple geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Bound the complete four-leg product before allocating any collections or
	// packet rules. This is the same limit as the native packet program.
	if len(model.mappings) > nativeRuleCapacity/160 {
		return nil, errors.New("firewall: nat46 tuple transport exceeds capacity")
	}
	result := &nativeNAT46Transport{}
	for index, mapping := range model.mappings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, protocol := range []string{"tcp", "udp", "icmp"} {
			for _, reply := range []bool{false, true} {
				direction := "forward"
				if reply {
					direction = "reply"
				}
				result.legs = append(result.legs, nativeNAT46Leg{name: fmt.Sprintf("native_n46_%d_%s_%s", index, protocol, direction), protocol: protocol, mapping: mapping, prefix: model.prefix, reply: reply})
			}
		}
	}
	return result, ctx.Err()
}

func nativeRawPayload(offset int) any {
	return map[string]any{"payload": map[string]any{"base": "nh", "offset": offset, "len": 32}}
}

func (leg nativeNAT46Leg) key(imported bool) nativeScope {
	offset, from, to := 96, "sport", "dport"
	if imported {
		offset = 160
	}
	if leg.reply {
		offset, from, to = 288, "dport", "sport"
		if imported {
			offset = 128
		}
	}
	if leg.protocol == "icmp" {
		return nativeScope{text: fmt.Sprintf("@nh,%d,32 . @th,32,32", offset), expressions: []any{nativeRawPayload(offset), map[string]any{"payload": map[string]any{"base": "th", "offset": 32, "len": 32}}}}
	}
	return nativeScope{text: fmt.Sprintf("@nh,%d,32 . %s %s . %s %s", offset, leg.protocol, from, leg.protocol, to),
		expressions: []any{nativeRawPayload(offset), guardPayload(leg.protocol, from), guardPayload(leg.protocol, to)}}
}

func (leg nativeNAT46Leg) tuple(imported bool, metadata bool) (string, any) {
	key := leg.key(imported)
	fields := append([]any{}, key.expressions...)
	text := key.text
	if metadata {
		fields = append(fields, nativeCT("mark"), guardMeta("mark"), guardMeta("priority"))
		text += " . ct mark . meta mark . meta priority"
	}
	return text, map[string]any{"concat": fields}
}

func (transport *nativeNAT46Transport) definitions() []string {
	result := []string{}
	for _, leg := range transport.legs {
		key, _ := leg.tuple(false, false)
		for _, value := range []struct{ name, expression string }{{"epoch", "ct mark"}, {"context", "meta mark"}, {"channel", "meta priority"}} {
			result = append(result, fmt.Sprintf("map %s_%s { typeof %s : %s; flags dynamic,timeout; timeout 2s; size 1024; }", leg.name, value.name, key, value.expression))
		}
		key, _ = leg.tuple(false, true)
		result = append(result, fmt.Sprintf("set %s_tuple { typeof %s; flags dynamic,timeout; timeout 2s; size 1024; }", leg.name, key))
	}
	return result
}

func (leg nativeNAT46Leg) geometry(imported bool) nativeScope {
	iface := nativeMatch("oifname \"nat46\"", guardMeta("oifname"), "nat46")
	family, field, address := "ip", "daddr", leg.mapping.alias.String()
	if imported {
		iface = nativeMatch("iifname \"nat46\"", guardMeta("iifname"), "nat46")
	}
	if leg.reply == imported {
		other := "iifname"
		if imported {
			other = "oifname"
		}
		iface = nativeJoin(iface, nativeScope{text: other + " != \"nat46\"", expressions: []any{map[string]any{"match": map[string]any{"op": "!=", "left": guardMeta(other), "right": "nat46"}}}})
	}
	if leg.reply != imported {
		family, field, address = "ip6", "saddr", leg.mapping.target.String()
		if imported {
			field = "daddr"
		}
		iface = nativeJoin(iface, nativeMatch(fmt.Sprintf("%s %q", map[bool]string{true: "oifname", false: "iifname"}[imported], leg.mapping.targetInterface), guardMeta(map[bool]string{true: "oifname", false: "iifname"}[imported]), leg.mapping.targetInterface))
		source := "saddr"
		if leg.reply {
			source = "daddr"
		}
		prefix := controllerPrefix(leg.prefix)
		iface = nativeJoin(iface, nativeMatch("ip6 "+source+" "+leg.prefix.String(), guardPayload("ip6", source), prefix))
	} else if leg.reply {
		field = "saddr"
	}
	direction := "original"
	state := nativeMatch("ct state { established, new }", nativeCT("state"), map[string]any{"set": []string{"established", "new"}})
	if leg.reply {
		direction = "reply"
		state = nativeState("established")
	}
	protocol := nativeMatch("meta l4proto "+leg.protocol, guardMeta("l4proto"), leg.protocol)
	if leg.protocol == "icmp" {
		header, echo := "icmp", "echo-request"
		if family == "ip6" {
			header = "icmpv6"
		}
		if leg.reply {
			echo = "echo-reply"
		}
		protocol = nativeJoin(nativeMatch(header+" type "+echo, guardPayload(header, "type"), echo), nativeMatch(header+" code 0", guardPayload(header, "code"), 0))
	}
	return nativeJoin(iface, nativeMatch(family+" "+field+" "+address, guardPayload(family, field), address), protocol, nativeMatch("ct direction "+direction, nativeCT("direction"), direction), state)
}

func nativeDynamicUpdate(name, text string, key, value any) nativeScope {
	statement := map[string]any{"op": "update", "elem": key, "set": "@" + name}
	kind := "set"
	if value != nil {
		kind = "map"
		statement = map[string]any{"op": "update", "elem": key, "data": value, "map": "@" + name}
	}
	return nativeScope{text: "update @" + name + " { " + text + " }", expressions: []any{map[string]any{kind: statement}}}
}

func nativeDynamicDelete(name, text string, key, value any) nativeScope {
	return nativeScope{text: "delete @" + name + " { " + text + " }", expressions: []any{map[string]any{"map": map[string]any{"op": "delete", "elem": key, "data": value, "map": "@" + name}}}}
}

func (transport *nativeNAT46Transport) chains() map[string][]nativeScope {
	chains := map[string][]nativeScope{}
	// Marks and priorities have different nft datatypes. Pin every epoch bit
	// without casting, assigning the latest epoch, or changing either field.
	for bit := uint(10); bit < 32; bit++ {
		mask := uint32(1) << bit
		class := epochClassID(mask)
		equal := nativeMatch(fmt.Sprintf("ct mark & %#x == %#x", mask, mask), guardBinary("&", nativeCT("mark"), mask), mask)
		zero := nativeMatch(fmt.Sprintf("ct mark & %#x == 0", mask), guardBinary("&", nativeCT("mark"), mask), 0)
		priorityZero := nativeMatch(fmt.Sprintf("meta priority & %s == none", class), guardBinary("&", guardMeta("priority"), class), "none")
		prioritySet := nativeMatch(fmt.Sprintf("meta priority & %s == %s", class, class), guardBinary("&", guardMeta("priority"), class), class)
		chains["native_n46_same_epoch"] = append(chains["native_n46_same_epoch"], nativeJoin(equal, priorityZero, nativeVerdict("drop", "")), nativeJoin(zero, prioritySet, nativeVerdict("drop", "")))
	}
	chains["native_n46_same_epoch"] = append(chains["native_n46_same_epoch"], nativeVerdict("return", ""))
	for _, leg := range transport.legs {
		for _, imported := range []bool{false, true} {
			direction := "export"
			if imported {
				direction = "import"
			}
			name := leg.name + "_" + direction
			checked := name + "_checked"
			chains[name] = append(chains[name], nativeJoin(leg.geometry(imported), nativeVerdict("goto", checked)), nativeVerdict("drop", ""))
			keyText, key := leg.tuple(imported, false)
			if imported {
				// A positive connection retains its original epoch/rule. Missing map
				// lookups cannot reuse another hook's packet metadata.
				if !leg.reply {
					chains[checked] = append(chains[checked], nativeJoin(nativeMatch("ct mark 0", nativeCT("mark"), 0), nativeState("new"), nativeMangle("ct mark set "+keyText+" map @"+leg.name+"_epoch", nativeCT("mark"), map[string]any{"map": map[string]any{"key": key, "data": "@" + leg.name + "_epoch"}})))
				}
				chains[checked] = append(chains[checked], nativeJoin(nativeMangle("meta mark set 0", guardMeta("mark"), 0), nativeMangle("meta priority set 0", guardMeta("priority"), "none"),
					nativeMangle("meta mark set "+keyText+" map @"+leg.name+"_context", guardMeta("mark"), map[string]any{"map": map[string]any{"key": key, "data": "@" + leg.name + "_context"}}),
					nativeMangle("meta priority set "+keyText+" map @"+leg.name+"_channel", guardMeta("priority"), map[string]any{"map": map[string]any{"key": key, "data": "@" + leg.name + "_channel"}})))
				tupleText, tuple := leg.tuple(true, true)
				chains[checked] = append(chains[checked], nativeJoin(nativeMatch(tupleText+" @"+leg.name+"_tuple", tuple, "@"+leg.name+"_tuple"), nativeVerdict("goto", checked+"_current")), nativeVerdict("drop", ""))
			} else {
				chains[checked] = append(chains[checked], nativeVerdict("goto", checked+"_current"))
			}
			current := checked + "_current"
			source := current + "_source"
			continuation := nativeVerdict("return", "")
			if !imported {
				continuation = nativeVerdict("goto", source+"_record")
			}
			if transport.shareValidation {
				shared := leg.sharedCurrentName(imported)
				if _, exists := chains[shared]; !exists {
					for name, rules := range transport.sourceChecks(leg, imported, shared, nativeVerdict("return", "")) {
						chains[name] = rules
					}
				}
				chains[current] = []nativeScope{nativeVerdict("jump", shared), continuation}
			} else {
				for name, rules := range transport.sourceChecks(leg, imported, current, continuation) {
					chains[name] = rules
				}
			}
			if !imported {
				record := source + "_record"
				fields := []struct {
					name, text string
					value      any
				}{{"epoch", "ct mark", nativeCT("mark")}, {"context", "meta mark", guardMeta("mark")}, {"channel", "meta priority", guardMeta("priority")}}
				parts := []nativeScope{}
				// nft dynamic map update refreshes an existing element's lifetime,
				// not its value. Delete before inserting the current admitted snapshot;
				// the full correlation tuple rejects partial or missing snapshots.
				for _, value := range fields {
					parts = append(parts, nativeDynamicDelete(leg.name+"_"+value.name, keyText+" : "+value.text, key, value.value))
				}
				for _, value := range fields {
					parts = append(parts, nativeDynamicUpdate(leg.name+"_"+value.name, keyText+" : "+value.text, key, value.value))
				}
				tupleText, tuple := leg.tuple(false, true)
				parts = append(parts, nativeDynamicUpdate(leg.name+"_tuple", tupleText, tuple, nil), nativeVerdict("return", ""))
				chains[record] = append(chains[record], nativeJoin(parts...))
			}
		}
	}
	return chains
}

// The selected nft version keeps the raw expression in map key headers. Its
// TCP/UDP set header omits the unnamed raw-address datatype; echo headers
// expose both raw fields as integers. Exact dynamic update and membership
// rules pin each raw payload offset and width independently.
func (transport *nativeNAT46Transport) schema() *guardTableSchema {
	schema := &guardTableSchema{sets: map[string]map[string]any{}, maps: map[string]map[string]any{}, chains: map[string]map[string]any{}, rules: map[string][][]any{}}
	for _, leg := range transport.legs {
		_, key := leg.tuple(false, false)
		for _, value := range []struct{ name, datatype string }{{"epoch", "mark"}, {"context", "mark"}, {"channel", "classid"}} {
			name := leg.name + "_" + value.name
			header := guardSetHeader("inet", name, map[string]any{"typeof": key}, 1024)
			header["map"], header["flags"], header["timeout"] = value.datatype, []string{"timeout", "dynamic"}, 2
			schema.maps[name] = header
		}
		name := leg.name + "_tuple"
		types := []string{"inet_service", "inet_service", "mark", "mark", "classid"}
		if leg.protocol == "icmp" {
			types = []string{"integer", "integer", "mark", "mark", "classid"}
		}
		header := guardSetHeader("inet", name, types, 1024)
		header["flags"], header["timeout"] = []string{"timeout", "dynamic"}, 2
		schema.sets[name] = header
	}
	for name, rules := range transport.chains() {
		schema.chains[name] = map[string]any{"family": "inet", "table": ownedTable, "name": name}
		schema.rules[name] = nativeRulesExpressions(rules)
	}
	return schema
}
