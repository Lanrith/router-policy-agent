package firewall

import (
	"context"
	"errors"
	"fmt"
)

// Callback correlation is a separate IPv4-initiated connection, never an
// established reply to an IPv6-initiated flow. This construction-only component
// reuses the mapped IPv4/IPv6 proof transport on the original NAT64 attachment.
// It does not install hooks or grant permission. Installed callback admission
// remains closed until ordered policy, grants and physical gates are joined.
type nativeNAT64CallbackTransport struct {
	native *nativeNAT64Transport
	proof  *nativeNAT46Transport
}

func newNativeNAT64CallbackTransport(ctx context.Context, transport *nativeNAT64Transport) (*nativeNAT64CallbackTransport, error) {
	if ctx == nil || transport == nil || transport.geometry == nil || !generationHash(transport.baselineHash) ||
		!transport.prefix.IsValid() || transport.prefix.Bits() != 96 || transport.callbacks != nil {
		return nil, errors.New("firewall: missing or already selected NAT64 callback geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Retain the compiler's fixed reservations. Runtime allocation snapshots
	// cannot add callback destinations through this constructor.
	if _, err := transport.geometry.Capture(ctx, transport.component, nil, transport.mappings); err != nil {
		return nil, err
	}
	if len(transport.mappings) > nativeRuleCapacity/160 {
		return nil, errors.New("firewall: NAT64 callback transport exceeds capacity")
	}
	callback := &nativeNAT64CallbackTransport{native: transport, proof: &nativeNAT46Transport{}}
	for index, mapping := range transport.mappings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !mapping.Ready {
			continue
		}
		selected, length := "", -1
		for iface, networks := range transport.sourceNetworks {
			for _, network := range networks {
				if !network.Contains(mapping.Source) || network.Bits() < length {
					continue
				}
				if network.Bits() == length && selected != iface {
					return nil, errors.New("firewall: ambiguous NAT64 callback target attachment")
				}
				selected, length = iface, network.Bits()
			}
		}
		if selected == "" {
			return nil, errors.New("firewall: NAT64 callback requires a declared native target attachment")
		}
		target := nativeNAT46Mapping{id: fmt.Sprintf("callback-%d", index), alias: mapping.Alias, target: mapping.Source, targetInterface: selected}
		for _, protocol := range []string{"tcp", "udp", "icmp"} {
			for _, reply := range []bool{false, true} {
				direction := "forward"
				if reply {
					direction = "reply"
				}
				callback.proof.legs = append(callback.proof.legs, nativeNAT46Leg{name: fmt.Sprintf("%s_callback_%d_%s_%s", transport.name, index, protocol, direction),
					component: transport.component, namespace: transport.name + "_callback", protocol: protocol, prefix: transport.prefix, mapping: target, reply: reply})
			}
		}
	}
	// Construction precedes schema freezing and original runtime publications.
	// Every allocator/token revocation now withdraws these proofs atomically too.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	transport.callbacks = callback
	return callback, nil
}

func (callback *nativeNAT64CallbackTransport) chains() map[string][]nativeScope {
	chains := callback.proof.chains()
	for _, leg := range callback.proof.legs {
		// The NAT64 geometric direction is the reverse of callback initiation.
		allocation := nativeNAT64Leg{reply: !leg.reply}
		for _, imported := range []bool{false, true} {
			direction := "export"
			if imported {
				direction = "import"
			}
			name := leg.name + "_" + direction
			chains[name] = []nativeScope{nativeJoin(leg.geometry(imported), allocation.allocation(callback.native, imported), nativeVerdict("goto", name+"_checked")), nativeVerdict("drop", "")}
		}
	}
	return chains
}

func (callback *nativeNAT64CallbackTransport) clears() []any {
	operations := []any{}
	for _, leg := range callback.proof.legs {
		for _, suffix := range []string{"_epoch", "_context", "_channel", "_tuple"} {
			kind := "map"
			if suffix == "_tuple" {
				kind = "set"
			}
			operations = append(operations, map[string]any{"flush": map[string]any{kind: objectReference{Family: "inet", Table: ownedTable, Name: leg.name + suffix}}})
		}
	}
	return operations
}

func (callback *nativeNAT64CallbackTransport) schema() *guardTableSchema {
	schema := callback.proof.schema()
	for name, rules := range callback.chains() {
		schema.rules[name] = nativeRulesExpressions(rules)
	}
	return schema
}
