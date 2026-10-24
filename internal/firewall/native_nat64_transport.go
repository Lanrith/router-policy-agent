package firewall

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Allocation zones are confined to the native IPv6 connection. The translated
// IPv4 connection retains zone zero so source NAT allocates globally distinct
// return tuples. Zones carry connectivity identity, never an admission mark.
// Neither these chains nor their construction installs hooks or permits traffic.
type nativeNAT64Transport struct {
	geometry        *policy.NAT64AllocationGeometry
	baselineHash    string
	component, name string
	uplink          string
	prefix, pool    netip.Prefix
	mappings        []policy.NAT64SourceMapping
	sourceNetworks  map[string][]netip.Prefix
	legs            []nativeNAT64Leg
	ruleCount       int
}

type nativeNAT64Leg struct {
	name, iface, protocol string
	prefix, pool          netip.Prefix
	reply                 bool
}

// nft ct-zone registers contain host-order uint16 values. Raw IPv4 suffixes
// contain network-order bytes. Select a zone whose register bytes equal the
// alias bytes; numerical zone IDs are diagnostic and architecture dependent.
// This is a bijective encoding and does not assign or authorize an allocation.
func nativeNAT64ZoneIdentity(identity uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], identity)
	return binary.NativeEndian.Uint16(raw[:])
}

func newNativeNAT64Transport(ctx context.Context, baseline policy.Baseline, componentID string) (*nativeNAT64Transport, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing NAT64 tuple context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(baseline)
	if err != nil {
		return nil, errors.New("firewall: NAT64 baseline encoding failed")
	}
	b, err := policy.DecodeBaseline(raw)
	if err != nil {
		return nil, err
	}
	compiler, err := policy.New(b)
	if err != nil {
		return nil, err
	}
	geometry, err := compiler.CompileNAT64AllocationGeometry(ctx)
	if err != nil {
		return nil, err
	}
	for index, component := range b.NAT64 {
		if component.ID != componentID {
			continue
		}
		if !interfaceName.MatchString(component.ID) || component.ID == b.NetworkModel.UplinkInterface {
			return nil, errors.New("firewall: invalid NAT64 translator attachment")
		}
		for _, zone := range b.Zones {
			if slices.Contains(zone.Interfaces, component.ID) {
				return nil, errors.New("firewall: NAT64 translator shares a native attachment")
			}
		}
		transport := &nativeNAT64Transport{geometry: geometry, baselineHash: compiler.BaselineHash(), component: component.ID,
			name: fmt.Sprintf("native_n64_%d", index), uplink: b.NetworkModel.UplinkInterface, prefix: component.Prefix, pool: *component.SourcePool,
			mappings: slices.Clone(component.SourceMappings), sourceNetworks: map[string][]netip.Prefix{}, ruleCount: len(b.NetworkModel.Rules)}
		for _, zone := range b.Zones {
			for _, iface := range zone.Interfaces {
				for _, network := range zone.Networks {
					if network.Addr().Is6() {
						transport.sourceNetworks[iface] = append(transport.sourceNetworks[iface], network)
					}
				}
			}
		}
		for _, protocol := range []string{"tcp", "udp", "icmp"} {
			for _, reply := range []bool{false, true} {
				direction := "forward"
				if reply {
					direction = "reply"
				}
				transport.legs = append(transport.legs, nativeNAT64Leg{name: transport.name + "_" + protocol + "_" + direction,
					iface: component.ID, prefix: component.Prefix, pool: *component.SourcePool, protocol: protocol, reply: reply})
			}
		}
		return transport, ctx.Err()
	}
	return nil, errors.New("firewall: missing NAT64 tuple component")
}

func nativeRawField(offset, width int) any {
	return map[string]any{"payload": map[string]any{"base": "nh", "offset": offset, "len": width}}
}

// IPv6 exports and imports use the original connection zone; IPv4 uses the
// alias's low sixteen bits. Both are integer datatypes. The peer's IPv4 bits
// and complete transport tuple remain part of the key in both directions.
func (leg nativeNAT64Leg) tuple(imported bool) (string, any) {
	identity, peer := "ct zone", 288
	identityValue := nativeCT("zone")
	if leg.reply != imported {
		identityOffset := 112
		peer = 128
		if leg.reply {
			identityOffset, peer = 144, 96
		}
		identity, identityValue = fmt.Sprintf("@nh,%d,16", identityOffset), nativeRawField(identityOffset, 16)
	} else if leg.reply {
		peer = 160
	}
	text := fmt.Sprintf("%s . @nh,%d,32", identity, peer)
	fields := []any{identityValue, nativeRawField(peer, 32)}
	if leg.protocol == "icmp" {
		// Echo sequence numbers are packet instances, not connection identity.
		// The preserved echo identifier is the conntrack protocol source key in
		// both address families. Unlike a raw integer payload expression, this
		// fixed inet_service datatype also remains inspectable with multiple
		// live concatenated map elements on nftables 1.1.3.
		text += " . ct original proto-src"
		fields = append(fields, map[string]any{"ct": map[string]any{"key": "proto-src", "dir": "original"}})
	} else {
		from, to := "sport", "dport"
		if leg.reply {
			from, to = to, from
		}
		text += fmt.Sprintf(" . %s %s . %s %s", leg.protocol, from, leg.protocol, to)
		fields = append(fields, guardPayload(leg.protocol, from), guardPayload(leg.protocol, to))
	}
	return text, map[string]any{"concat": fields}
}

func (transport *nativeNAT64Transport) definitions() []string {
	result := []string{
		fmt.Sprintf("set %s_pending { type ipv6_addr; flags dynamic,timeout; timeout 5s; size 4096; }", transport.name),
		fmt.Sprintf("map %s_zones { typeof ip6 saddr : ct zone; flags timeout; timeout 90s; size 65533; }", transport.name),
		fmt.Sprintf("map %s_aliases { type ipv4_addr : ipv6_addr; flags timeout; timeout 90s; size 65533; }", transport.name),
		fmt.Sprintf("set %s_active_aliases { type ipv4_addr; flags timeout; timeout 90s; size 65533; }", transport.name),
		fmt.Sprintf("set %s_sources { typeof ct zone . ip6 saddr; flags timeout; timeout 90s; size 65533; }", transport.name),
		fmt.Sprintf("map %s_tokens { type mark . mark . classid : mark; size 65536; }", transport.name),
		fmt.Sprintf("map %s_token_epoch { type mark : mark; size 65536; }", transport.name),
		fmt.Sprintf("map %s_token_context { type mark : mark; size 65536; }", transport.name),
		fmt.Sprintf("map %s_token_channel { type mark : classid; size 65536; }", transport.name),
		fmt.Sprintf("set %s_token_epoch_pairs { type mark . mark; size 65536; }", transport.name),
	}
	for _, leg := range transport.legs {
		key, _ := leg.tuple(false)
		result = append(result, fmt.Sprintf("map %s_proof { typeof %s : meta mark; flags dynamic,timeout; timeout 2s; size 1024; }", leg.name, key))
	}
	return result
}

func (transport *nativeNAT64Transport) token() (string, any) {
	text := "(ct mark) . (meta mark & 0xff00e3ff) . (meta priority)"
	key := map[string]any{"concat": []any{nativeCT("mark"), guardBinary("&", guardMeta("mark"), nativeFactsMask), guardMeta("priority")}}
	return text + " map @" + transport.name + "_tokens", map[string]any{"map": map[string]any{"key": key, "data": "@" + transport.name + "_tokens"}}
}

// The caller must put these rules before connection tracking, in its separately
// inspected root-owned raw hook. No IPv4 packet has its connection zone changed.
func (transport *nativeNAT64Transport) zoneRules() []nativeScope {
	rules := []nativeScope{}
	for _, reply := range []bool{false, true} {
		field, match := "saddr", nativeMatch("ip6 daddr "+transport.prefix.String(), guardPayload("ip6", "daddr"), controllerPrefix(transport.prefix))
		if reply {
			field, match = "daddr", nativeInterface("iifname", transport.component)
		}
		value := map[string]any{"map": map[string]any{"key": guardPayload("ip6", field), "data": "@" + transport.name + "_zones"}}
		rules = append(rules, nativeJoin(match, nativeMangle("ct zone set ip6 "+field+" map @"+transport.name+"_zones", nativeCT("zone"), value)))
	}
	return rules
}

func (leg nativeNAT64Leg) geometry(imported bool) nativeScope {
	return leg.packetGeometry(imported, true, true, true)
}

func (leg nativeNAT64Leg) grantGeometry(imported bool) nativeScope {
	return leg.packetGeometry(imported, true, true, false)
}

// physicalGeometry retains the address family, protocol and echo direction at
// netdev egress. A TUN-originated packet no longer exposes its ingress name at
// that hook. The earlier inet import chain requires the exact translator
// attachment before it can mint the immutable authorization tag checked beside
// this geometry. Conntrack direction/state expressions are also deliberately
// omitted because the netdev hook does not support them.
func (leg nativeNAT64Leg) physicalGeometry(imported bool) nativeScope {
	return leg.packetGeometry(imported, false, false, true)
}

func (leg nativeNAT64Leg) physicalGrantGeometry(imported bool) nativeScope {
	return leg.packetGeometry(imported, false, false, false)
}

func (leg nativeNAT64Leg) packetGeometry(imported, connection, attachmentRequired, protocolRequired bool) nativeScope {
	attachment, field, family := "oifname", "daddr", "ip6"
	if imported {
		attachment = "iifname"
	}
	address := leg.prefix
	if leg.reply != imported {
		family, field, address = "ip", "saddr", leg.pool
	}
	if leg.reply {
		field = map[string]string{"saddr": "daddr", "daddr": "saddr"}[field]
	}
	direction, state := "original", nativeMatch("ct state { established, new }", nativeCT("state"), map[string]any{"set": []string{"established", "new"}})
	if leg.reply {
		direction, state = "reply", nativeState("established")
	}
	protocol := nativeScope{}
	if protocolRequired {
		protocol = nativeMatch("meta l4proto "+leg.protocol, guardMeta("l4proto"), leg.protocol)
	}
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
	result := nativeJoin(nativeMatch(family+" "+field+" "+address.String(), guardPayload(family, field), controllerPrefix(address)), protocol)
	if attachmentRequired {
		result = nativeJoin(nativeInterface(attachment, leg.iface), result)
	}
	if connection {
		result = nativeJoin(result, nativeMatch("ct direction "+direction, nativeCT("direction"), direction), state)
	}
	return result
}

// allocation proves that the packet still belongs to the current timed
// allocator publication. IPv6 legs use their assigned conntrack zone and
// original source address directly. IPv4 legs join the alias's raw low bits
// to the independently published reverse mapping. A short-lived correlation
// token therefore cannot survive allocator revocation or reassignment.
func (leg nativeNAT64Leg) allocation(transport *nativeNAT64Transport, imported bool) nativeScope {
	addressField := "saddr"
	if leg.reply {
		addressField = "daddr"
	}
	if leg.reply == imported {
		text := "ct zone . ip6 " + addressField + " @" + transport.name + "_sources"
		key := map[string]any{"concat": []any{nativeCT("zone"), guardPayload("ip6", addressField)}}
		return nativeMatch(text, key, "@"+transport.name+"_sources")
	}
	text := fmt.Sprintf("ip %s @%s_active_aliases", addressField, transport.name)
	return nativeMatch(text, guardPayload("ip", addressField), "@"+transport.name+"_active_aliases")
}

// Transport import replaces only packet metadata, and initializes a new IPv4
// connection's epoch from the fresh exact export. Confirmed epochs are retained.
// Current ownership, allocation publication, ordered policy and grants must be
// checked by the caller independently before and after this correlation.
func (transport *nativeNAT64Transport) chains() map[string][]nativeScope {
	chains := map[string][]nativeScope{}
	for _, leg := range transport.legs {
		for _, imported := range []bool{false, true} {
			direction := "export"
			if imported {
				direction = "import"
			}
			name := leg.name + "_" + direction
			checked := name + "_checked"
			chains[name] = []nativeScope{nativeJoin(leg.geometry(imported), nativeVerdict("goto", checked)), nativeVerdict("drop", "")}
			keyText, key := leg.tuple(imported)
			proof := map[string]any{"map": map[string]any{"key": key, "data": "@" + leg.name + "_proof"}}
			if imported {
				tokenStage, channelStage, epochStage, contextStage := checked+"_token", checked+"_channel", checked+"_epoch", checked+"_context"
				chains[checked] = append(chains[checked],
					nativeJoin(nativeMangle("meta mark set "+keyText+" map @"+leg.name+"_proof", guardMeta("mark"), proof), nativeVerdict("goto", tokenStage)), nativeVerdict("drop", ""))
				chains[tokenStage] = []nativeScope{nativeJoin(
					nativeMangle("meta priority set meta mark map @"+transport.name+"_token_channel", guardMeta("priority"), map[string]any{"map": map[string]any{"key": guardMeta("mark"), "data": "@" + transport.name + "_token_channel"}}),
					nativeVerdict("goto", channelStage)), nativeVerdict("drop", "")}
				expectedEpoch := map[string]any{"map": map[string]any{"key": guardMeta("mark"), "data": "@" + transport.name + "_token_epoch"}}
				chains[channelStage] = []nativeScope{
					nativeJoin(nativeMatch("ct mark 0", nativeCT("mark"), 0), nativeState("new"),
						nativeMangle("ct mark set meta mark map @"+transport.name+"_token_epoch", nativeCT("mark"), expectedEpoch)),
					nativeVerdict("goto", epochStage),
				}
				epochPair := map[string]any{"concat": []any{nativeCT("mark"), guardMeta("mark")}}
				chains[epochStage] = []nativeScope{
					nativeJoin(nativeMatch("ct mark . meta mark @"+transport.name+"_token_epoch_pairs", epochPair, "@"+transport.name+"_token_epoch_pairs"), nativeVerdict("goto", contextStage)),
					nativeVerdict("drop", ""),
				}
				chains[contextStage] = []nativeScope{nativeJoin(
					nativeMangle("meta mark set meta mark map @"+transport.name+"_token_context", guardMeta("mark"), map[string]any{"map": map[string]any{"key": guardMeta("mark"), "data": "@" + transport.name + "_token_context"}}),
					nativeVerdict("return", "")), nativeVerdict("drop", "")}
				continue
			}
			tokenText, token := transport.token()
			record := checked + "_record"
			chains[checked] = []nativeScope{nativeJoin(nativeMangle("ct mark set "+tokenText, nativeCT("mark"), token), nativeVerdict("goto", record)), nativeVerdict("drop", "")}
			chains[record] = []nativeScope{nativeJoin(
				nativeDynamicDelete(leg.name+"_proof", keyText+" : ct mark", key, nativeCT("mark")),
				nativeDynamicUpdate(leg.name+"_proof", keyText+" : ct mark", key, nativeCT("mark")),
				nativeMangle("ct mark set ct mark map @"+transport.name+"_token_epoch", nativeCT("mark"), map[string]any{"map": map[string]any{"key": nativeCT("mark"), "data": "@" + transport.name + "_token_epoch"}}),
				nativeVerdict("return", "")), nativeVerdict("drop", "")}
		}
	}
	return chains
}

func (transport *nativeNAT64Transport) schema() *guardTableSchema {
	schema := &guardTableSchema{sets: map[string]map[string]any{}, maps: map[string]map[string]any{}, chains: map[string]map[string]any{}, rules: map[string][][]any{}}
	pending := guardSetHeader("inet", transport.name+"_pending", "ipv6_addr", 4096)
	pending["flags"], pending["timeout"] = []string{"timeout", "dynamic"}, 5
	schema.sets[transport.name+"_pending"] = pending
	zone := guardSetHeader("inet", transport.name+"_zones", map[string]any{"typeof": guardPayload("ip6", "saddr")}, 65533)
	zone["map"], zone["flags"], zone["timeout"] = "integer", []string{"timeout"}, 90
	schema.maps[transport.name+"_zones"] = zone
	aliases := guardSetHeader("inet", transport.name+"_aliases", "ipv4_addr", 65533)
	aliases["map"], aliases["flags"], aliases["timeout"] = "ipv6_addr", []string{"timeout"}, 90
	schema.maps[transport.name+"_aliases"] = aliases
	activeAliases := guardSetHeader("inet", transport.name+"_active_aliases", "ipv4_addr", 65533)
	activeAliases["flags"], activeAliases["timeout"] = []string{"timeout"}, 90
	schema.sets[transport.name+"_active_aliases"] = activeAliases
	sources := guardSetHeader("inet", transport.name+"_sources", map[string]any{"typeof": map[string]any{"concat": []any{nativeCT("zone"), guardPayload("ip6", "saddr")}}}, 65533)
	sources["flags"], sources["timeout"] = []string{"timeout"}, 90
	schema.sets[transport.name+"_sources"] = sources
	for _, item := range []struct {
		name     string
		datatype any
		mapType  string
	}{{"_tokens", []string{"mark", "mark", "classid"}, "mark"}, {"_token_epoch", "mark", "mark"}, {"_token_context", "mark", "mark"}, {"_token_channel", "mark", "classid"}} {
		name := transport.name + item.name
		header := guardSetHeader("inet", name, item.datatype, 65536)
		header["map"] = item.mapType
		schema.maps[name] = header
	}
	epochPairs := guardSetHeader("inet", transport.name+"_token_epoch_pairs", []string{"mark", "mark"}, 65536)
	schema.sets[transport.name+"_token_epoch_pairs"] = epochPairs
	for _, leg := range transport.legs {
		_, key := leg.tuple(false)
		name := leg.name + "_proof"
		header := guardSetHeader("inet", name, map[string]any{"typeof": key}, 1024)
		header["map"], header["flags"], header["timeout"] = "mark", []string{"timeout", "dynamic"}, 2
		schema.maps[name] = header
	}
	for name, rules := range transport.chains() {
		schema.chains[name] = map[string]any{"family": "inet", "table": ownedTable, "name": name}
		schema.rules[name] = nativeRulesExpressions(rules)
	}
	return schema
}
