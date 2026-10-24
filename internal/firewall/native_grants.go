package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

func nativeLeaseSet(name string) string { return "native_" + name }

func nativeLeaseRefs() []objectReference {
	refs := make([]objectReference, 0, len(grantSets))
	for _, name := range grantSets {
		refs = append(refs, objectReference{Family: "netdev", Table: ownedTable, Name: nativeLeaseSet(name)})
	}
	return refs
}

// Every projection comes from a validated full logical grant and retains its
// original remaining lifetime. Epoch/physical ownership gates independently
// bind the device tuple to the association admitted by the inet hooks.
func projectNativeGrants(ctx context.Context, source guardChanges) ([]change, error) {
	values := map[string]map[string]int{}
	for _, name := range grantSets {
		values[name] = map[string]int{}
	}
	for _, command := range source.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family != "inet" || element.Table != ownedTable || !isGrantSet(element.Name) {
			continue
		}
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			tuple, err := validateLeasedTuple(raw, ipv4Set(element.Name))
			if err != nil {
				return nil, err
			}
			var lease struct {
				Element struct {
					Timeout int `json:"timeout"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &lease); err != nil {
				return nil, err
			}
			key, err := json.Marshal(map[string]any{"concat": []any{tuple.device.String(), tuple.peer.String(), tuple.port}})
			if err != nil {
				return nil, err
			}
			values[element.Name][string(key)] = max(values[element.Name][string(key)], lease.Element.Timeout)
			if len(values[element.Name]) > maximumTupleCount {
				return nil, errors.New("firewall: native grant projection capacity exceeded")
			}
		}
	}
	commands := make([]change, 0, 2*len(grantSets))
	for _, ref := range nativeLeaseRefs() {
		commands = append(commands, change{Flush: &setChange{Set: ref}})
		name := strings.TrimPrefix(ref.Name, "native_")
		keys := make([]string, 0, len(values[name]))
		for key := range values[name] {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		elements := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			raw, err := json.Marshal(map[string]any{"elem": map[string]any{"val": json.RawMessage(key), "timeout": values[name][key]}})
			if err != nil {
				return nil, err
			}
			elements = append(elements, raw)
		}
		if len(elements) != 0 {
			commands = append(commands, guardAdd("netdev", ref.Name, elements))
		}
	}
	return commands, ctx.Err()
}

func nativeGrantDefinitions() []string {
	var definitions []string
	for _, name := range grantSets {
		address := "ipv6_addr"
		if ipv4Set(name) {
			address = "ipv4_addr"
		}
		definitions = append(definitions, guardSetDefinition(nativeLeaseSet(name), address+" . "+address+" . inet_service"))
	}
	return append(definitions, nativeIDGrantDefinitions("netdev")...)
}

func nativeGrantSchema(schema *guardTableSchema) {
	nativeIDGrantSchema(schema, "netdev")
	for _, name := range grantSets {
		address := "ipv6_addr"
		if ipv4Set(name) {
			address = "ipv4_addr"
		}
		schema.sets[nativeLeaseSet(name)] = guardLeaseHeader("netdev", nativeLeaseSet(name), []string{address, address, "inet_service"})
	}
}

func nativeDirectoryTag(reply bool) uint64 {
	if reply {
		return 0xd6000000
	}
	return 0xd5000000
}

func (access *nativeAccess) compileGrantChecks() {
	for _, name := range grantSets {
		family, protocol := guardProtocol(name)
		fromDevice := strings.HasPrefix(name, "lease_from")
		for _, reply := range []bool{false, true} {
			direction, port := "original", "dport"
			if reply {
				direction, port = "reply", "sport"
			}
			device, peer := "saddr", "daddr"
			if fromDevice == reply {
				device, peer = "daddr", "saddr"
			}
			key := []any{guardMeta("iifname"), guardPayload("ether", "saddr"), guardPayload(family, device), guardPayload(family, peer), guardPayload(protocol, port)}
			text := "iifname . ether saddr . " + family + " " + device + " . " + family + " " + peer + " . " + protocol + " " + port
			set := name
			if device == "daddr" {
				key = []any{guardMeta("oifname"), guardPayload(family, device), guardPayload(family, peer), guardPayload(protocol, port)}
				text = "oifname . " + family + " " + device + " . " + family + " " + peer + " . " + protocol + " " + port
				set = inboundSet(name)
			}
			access.add("native_grant", nativeMatch("ct direction "+direction, nativeCT("direction"), direction),
				nativeMatch(text+" @"+set, map[string]any{"concat": key}, "@"+set), nativeVerdict("return", ""))
			physical := nativeJoin(nativeMark(0xff000000, nativeDirectoryTag(reply)),
				nativeMatch(fmt.Sprintf("%s %s . %s %s . %s %s @%s", family, device, family, peer, protocol, port, nativeLeaseSet(name)),
					map[string]any{"concat": []any{guardPayload(family, device), guardPayload(family, peer), guardPayload(protocol, port)}}, "@"+nativeLeaseSet(name)), nativeVerdict("return", ""))
			access.netdev["native_grant"] = append(access.netdev["native_grant"], physical)
		}
	}
	access.add("native_grant", nativeVerdict("drop", ""))
	access.netdev["native_grant"] = append(access.netdev["native_grant"], nativeVerdict("drop", ""))
}
