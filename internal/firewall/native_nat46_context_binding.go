package firewall

import (
	"fmt"
	"strings"
)

// The literal collection is immutable rule data. Each row keeps a context,
// endpoint, attachment and protocol together; it creates no mutable permit set.
// It is the union of entry.binding predicates, sharing their fixed TUN leg and
// embedded client prefix. Current ownership and permission remain independent.
func (group nativeNAT46ContextGroup) binding(model *nativeNAT46Model, wire, reply, physical bool) nativeScope {
	if len(group.entries) == 1 {
		return group.entries[0].binding(model, wire, reply, physical)
	}
	family, field, client := "ip", "daddr", "saddr"
	if wire {
		family = "ip6"
	}
	if reply {
		field, client = "saddr", "daddr"
	}
	withInterface := wire && !reply || !wire && reply || !physical
	interfaceField := "oifname"
	if wire && reply || !wire && !reply {
		interfaceField = "iifname"
	}
	fields := []any{guardBinary("&", guardMeta("mark"), ownershipRuleMask)}
	text := "(meta mark & 0x3ff)"
	if withInterface {
		fields, text = append(fields, guardMeta(interfaceField)), text+" . "+interfaceField
	}
	fields = append(fields, guardPayload(family, field), guardMeta("l4proto"))
	text += " . " + family + " " + field + " . meta l4proto"
	protocol := group.protocol
	if wire && protocol == "icmp" {
		protocol = "ipv6-icmp"
	}
	rows, literals := []any{}, []string{}
	for _, entry := range group.entries {
		mapping := model.mappings[entry.mapping]
		iface, address := entry.packet.iface, mapping.alias
		if wire {
			iface, address = mapping.targetInterface, mapping.target
		}
		row := []any{entry.packet.id}
		literal := fmt.Sprintf("%#x", entry.packet.id)
		if withInterface {
			row, literal = append(row, iface), literal+fmt.Sprintf(" . %q", iface)
		}
		row = append(row, address.String(), protocol)
		literal += " . " + address.String() + " . " + protocol
		rows, literals = append(rows, map[string]any{"concat": row}), append(literals, literal)
	}
	parts := []nativeScope{nativeMatch(text+" { "+strings.Join(literals, ", ")+" }", map[string]any{"concat": fields}, map[string]any{"set": rows})}
	if wire && reply || !wire && !reply {
		parts = append(parts, nativeMatch("oifname \"nat46\"", guardMeta("oifname"), "nat46"))
	} else if !physical {
		parts = append(parts, nativeMatch("iifname \"nat46\"", guardMeta("iifname"), "nat46"))
	}
	if wire {
		parts = append(parts, nativeMatch("ip6 "+client+" "+model.prefix.String(), guardPayload("ip6", client), controllerPrefix(model.prefix)))
	}
	if group.protocol == "icmp" {
		kind, protocol := "echo-request", "icmp"
		if reply {
			kind = "echo-reply"
		}
		if wire {
			protocol = "icmpv6"
		}
		parts = append(parts, nativeMatch(protocol+" type "+kind, guardPayload(protocol, "type"), kind), nativeMatch(protocol+" code 0", guardPayload(protocol, "code"), 0))
	}
	return nativeJoin(parts...)
}
