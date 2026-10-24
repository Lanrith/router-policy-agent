package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

const nativeCoreEpoch = uint64(0xfffffc00)

type nativeCoreScope struct {
	id                                      uint64
	kind, clientInterface, serviceInterface string
	prefix                                  netip.Prefix
	listeners                               []netip.Addr
	upstream                                *policy.CoreEgress
}

func nativeCoreTag(reply bool) uint64 {
	if reply {
		return 0xb2000000
	}
	return 0xb1000000
}

func (access *nativeAccess) compileCore(ctx context.Context, b policy.Baseline) error {
	for _, service := range b.NetworkModel.CoreServices {
		for _, client := range service.Clients {
			for _, prefix := range client.Addresses {
				if err := ctx.Err(); err != nil {
					return err
				}
				scope := nativeCoreScope{id: uint64(len(access.core)), kind: service.Kind, clientInterface: client.Interface, serviceInterface: service.Interface, prefix: prefix}
				for _, listener := range service.Addresses {
					if listener.Is4() == prefix.Addr().Is4() {
						scope.listeners = append(scope.listeners, listener)
					}
				}
				if len(scope.listeners) == 0 || scope.id > uint64(ownershipRuleMask) {
					return errors.New("firewall: invalid or oversized native core geometry")
				}
				access.core = append(access.core, scope)
			}
		}
	}
	for _, path := range b.NetworkModel.CoreEgress {
		path.Destinations = slices.Clone(path.Destinations)
		path.TranslatedAddresses = slices.Clone(path.TranslatedAddresses)
		if path.Masquerade && len(path.TranslatedAddresses) == 0 {
			return errors.New("firewall: core dependencies require qualified dynamic uplink source projection")
		}
		for _, prefix := range path.Destinations {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(access.core) > int(ownershipRuleMask) {
				return errors.New("firewall: native core scope capacity exceeded")
			}
			clientInterface := b.NetworkModel.UplinkInterface
			if path.DestinationInterface != "" {
				clientInterface = path.DestinationInterface
			}
			access.core = append(access.core, nativeCoreScope{id: uint64(len(access.core)), kind: path.Kind, clientInterface: clientInterface, serviceInterface: path.Interface, prefix: prefix, listeners: []netip.Addr{path.Address}, upstream: &path})
		}
	}
	if len(access.core) == 0 {
		return nil
	}
	for _, family := range []struct {
		spelling string
		prefixes []string
	}{{"ip", []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"}}, {"ip6", []string{"::/128", "::1/128", "fe80::/10", "ff00::/8"}}} {
		for _, raw := range family.prefixes {
			prefix := netip.MustParsePrefix(raw)
			access.addCoreSourceDeny(family.spelling, prefix)
			access.addCoreTargetDeny(family.spelling, prefix)
			value := controllerPrefix(prefix)
			text := prefix.String()
			if prefix.Bits() == prefix.Addr().BitLen() {
				value, text = prefix.Addr().String(), prefix.Addr().String()
			}
			access.netdev["native_core_reply_source"] = append(access.netdev["native_core_reply_source"], nativeJoin(nativeMatch(family.spelling+" saddr "+text, guardPayload(family.spelling, "saddr"), value), nativeVerdict("drop", "")))
		}
	}
	for _, block := range b.ProtectedNetworks {
		if block.ProtectionID == "P01" {
			for _, prefix := range block.Networks {
				spelling := "ip6"
				if prefix.Addr().Is4() {
					spelling = "ip"
				}
				access.addCoreSourceDeny(spelling, prefix)
				access.addCoreTargetDeny(spelling, prefix)
			}
		}
	}
	access.add("native_core_source", nativeVerdict("return", ""))
	access.add("native_core_target", nativeVerdict("return", ""))
	access.netdev["native_core_target"] = append(access.netdev["native_core_target"], nativeVerdict("return", ""))
	access.netdev["native_core_source"] = append(access.netdev["native_core_source"], nativeVerdict("return", ""))
	access.netdev["native_core_reply_source"] = append(access.netdev["native_core_reply_source"], nativeVerdict("return", ""))
	access.netdev["native_core_reply_egress"] = []nativeScope{nativeVerdict("jump", "native_core_reply_source"), nativeVerdict("jump", "native_core_target"), nativeVerdict("goto", "restore_owner_priority")}
	for _, scope := range access.core {
		for _, hook := range []string{"guard_forward", "permit_flow"} {
			for _, reply := range []bool{false, true} {
				chain := fmt.Sprintf("native_core_%d_%s_%t", scope.id, hook, reply)
				for _, predicate := range scope.predicates(reply, false) {
					access.add("native_core_"+hook, predicate, nativeVerdict("goto", chain))
				}
				access.compileCoreDecision(scope, hook, reply, chain)
			}
		}
	}
	for _, hook := range []string{"guard_forward", "permit_flow"} {
		access.add("native_core_"+hook, nativeVerdict("return", ""))
	}
	access.coreEgress = access.corePhysicalRules()
	return ctx.Err()
}

func (access *nativeAccess) addCoreSourceDeny(spelling string, prefix netip.Prefix) {
	value, text := controllerPrefix(prefix), prefix.String()
	if prefix.Bits() == prefix.Addr().BitLen() {
		value, text = prefix.Addr().String(), prefix.Addr().String()
	}
	rule := nativeJoin(nativeMatch(spelling+" saddr "+text, guardPayload(spelling, "saddr"), value), nativeVerdict("drop", ""))
	access.add("native_core_source", rule)
	access.netdev["native_core_source"] = append(access.netdev["native_core_source"], rule)
}

func (access *nativeAccess) addCoreTargetDeny(spelling string, prefix netip.Prefix) {
	value, text := controllerPrefix(prefix), prefix.String()
	if prefix.Bits() == prefix.Addr().BitLen() {
		value, text = prefix.Addr().String(), prefix.Addr().String()
	}
	rule := nativeJoin(nativeMatch(spelling+" daddr "+text, guardPayload(spelling, "daddr"), value), nativeVerdict("drop", ""))
	access.add("native_core_target", rule)
	access.netdev["native_core_target"] = append(access.netdev["native_core_target"], rule)
}

func (scope nativeCoreScope) predicates(reply, physical bool) []nativeScope {
	family := 6
	if scope.prefix.Addr().Is4() {
		family = 4
	}
	protocols, ports := nativeCoreTransport(scope.kind)
	if scope.upstream != nil {
		return scope.upstreamPredicates(reply, physical, family, protocols, ports)
	}
	var result []nativeScope
	for _, listener := range scope.listeners {
		target := netip.PrefixFrom(listener, listener.BitLen())
		if reply && physical && scope.kind == "ntp" {
			target = netip.Prefix{}
		}
		for _, protocol := range protocols {
			for _, port := range ports {
				predicate := nativeScopePredicate(protocol, family, policy.NetworkSelector{Interface: scope.clientInterface}, policy.NetworkSelector{Interface: scope.serviceInterface}, scope.prefix, target, port, reply, physical)
				result = append(result, predicate)
			}
		}
		// NTP replies have the requested remote source after time redirection.
		if reply && physical && scope.kind == "ntp" {
			break
		}
	}
	return result
}

func (access *nativeAccess) compileCoreDecision(scope nativeCoreScope, hook string, reply bool, chain string) {
	direction := "original"
	if reply {
		direction = "reply"
	}
	admitted := chain + "_admitted"
	access.add(chain, nativeMatch("ct direction "+direction, nativeCT("direction"), direction), nativeVerdict("jump", admitted))
	access.add(chain, nativeVerdict("drop", ""))
	if reply {
		access.add(admitted, nativeState("established"), nativeVerdict("goto", admitted+"_state"))
	} else {
		access.add(admitted, nativeMatch("ct state { established, new }", nativeCT("state"), map[string]any{"set": []string{"established", "new"}}), nativeVerdict("goto", admitted+"_state"))
	}
	access.add(admitted, nativeVerdict("drop", ""))
	admitted += "_state"
	if !reply {
		access.add(admitted, nativeVerdict("jump", "native_core_source"))
	}
	access.add(admitted, nativeVerdict("jump", "native_core_target"))
	marker := nativeCoreEpoch | scope.id
	if hook == "guard_forward" && !reply {
		access.add(admitted, nativeMatch("ct mark 0", nativeCT("mark"), 0), nativeState("new"), nativeMangle(fmt.Sprintf("ct mark set %#x", marker), nativeCT("mark"), marker))
	}
	checks := nativeMatch(fmt.Sprintf("ct mark %#x", marker), nativeCT("mark"), marker)
	if hook == "permit_flow" {
		checks = nativeJoin(checks, nativeMark(nativeTagMask, nativeCoreTag(reply)|scope.id))
	}
	access.add(admitted, checks, nativeVerdict("goto", admitted+"_token"))
	access.add(admitted, nativeVerdict("drop", ""))
	admitted += "_token"
	access.add(admitted, nativeMangle("meta mark set meta mark & "+guardMarkKeep, guardMeta("mark"), guardBinary("&", guardMeta("mark"), uint64(0x00ff0000))), nativeMangle(fmt.Sprintf("meta mark set meta mark | %#x", nativeCoreTag(reply)|scope.id), guardMeta("mark"), guardBinary("|", guardMeta("mark"), nativeCoreTag(reply)|scope.id)))
	if hook == "permit_flow" {
		access.add(admitted, nativeVerdict("jump", "save_owner_priority"))
		access.add(admitted, nativeMangle("meta priority set 0xfffffc00", guardMeta("priority"), "ffff:fc00"))
	}
	access.add(admitted, nativeVerdict("accept", ""))
}

func (access *nativeAccess) corePhysicalRules() map[string][]nativeScope {
	rules := map[string][]nativeScope{}
	for _, scope := range access.core {
		for _, reply := range []bool{false, true} {
			tag := nativeCoreTag(reply)
			target := "native_core_reply_egress"
			if !reply {
				target = "native_core_request_egress"
				access.netdev[target] = []nativeScope{nativeVerdict("jump", "native_core_source"), nativeVerdict("jump", "native_core_target"), nativeVerdict("goto", "restore_owner_priority")}
				if scope.upstream != nil && scope.upstream.Masquerade {
					tag = nativeCoreNATFinal
					// The complete physical predicate below pins the generated WAN
					// source. It may be a protected router address only on this
					// correlated, exact service dependency.
					target = "native_core_nat_egress"
					access.netdev[target] = []nativeScope{nativeVerdict("jump", "native_core_target"), nativeVerdict("goto", "restore_owner_priority")}
				}
			}
			outgoing := scope.serviceInterface
			if reply != (scope.upstream != nil) {
				outgoing = scope.clientInterface
			}
			for _, predicate := range scope.predicates(reply, true) {
				rules[outgoing] = append(rules[outgoing], nativeJoin(nativeMark(nativeTagMask, tag|scope.id), nativeMatch("meta priority 0xfffffc00", guardMeta("priority"), "ffff:fc00"), predicate, nativeVerdict("goto", target)))
			}
		}
	}
	return rules
}

// Keep the closed core-kind boundary on every physical interface, including
// interfaces with no reachable core scope. Only the tuple copies are culled.
func (access *nativeAccess) corePhysicalEgress(device string) []nativeScope {
	rules := append([]nativeScope{}, access.coreEgress[device]...)
	if len(access.core) != 0 {
		for _, reply := range []bool{false, true} {
			rules = append(rules, nativeJoin(nativeMark(0xff000000, nativeCoreTag(reply)), nativeVerdict("drop", "")))
		}
		rules = append(rules, nativeJoin(nativeMatch("meta priority 0xfffffc00", guardMeta("priority"), "ffff:fc00"), nativeVerdict("drop", "")))
	}
	return rules
}

func coreInterfaces(b policy.Baseline) []string {
	var interfaces []string
	for _, service := range b.NetworkModel.CoreServices {
		interfaces = append(interfaces, service.Interface)
	}
	for _, path := range b.NetworkModel.CoreEgress {
		interfaces = append(interfaces, path.Interface)
		if path.DestinationInterface != "" {
			interfaces = append(interfaces, path.DestinationInterface)
		}
	}
	slices.Sort(interfaces)
	return slices.Compact(interfaces)
}

// coreServiceInterfaces returns only service-side namespace attachments. A
// physical destination interface on an internal dependency remains an
// ordinary LAN attachment: it still receives a netdev hook through the zone
// inventory, but must not be closed as though it were a service namespace.
func coreServiceInterfaces(b policy.Baseline) []string {
	var interfaces []string
	for _, service := range b.NetworkModel.CoreServices {
		interfaces = append(interfaces, service.Interface)
	}
	for _, path := range b.NetworkModel.CoreEgress {
		interfaces = append(interfaces, path.Interface)
	}
	slices.Sort(interfaces)
	return slices.Compact(interfaces)
}

func nativeCoreTransport(kind string) ([]string, []uint16) {
	switch kind {
	case "ntp":
		return []string{"udp"}, []uint16{123}
	case "metrics":
		return []string{"tcp"}, []uint16{9100}
	case "radius":
		return []string{"udp"}, []uint16{1812, 1813}
	case "radius_proxy":
		return []string{"udp"}, []uint16{1812}
	case "logs":
		return []string{"tcp"}, []uint16{443}
	case "discovery":
		return []string{"tcp", "udp"}, []uint16{53}
	default:
		return []string{"tcp", "udp"}, []uint16{53}
	}
}

func (scope nativeCoreScope) upstreamPredicates(reply, physical bool, family int, protocols []string, ports []uint16) []nativeScope {
	path := scope.upstream
	sources := []netip.Addr{path.Address}
	if physical && !reply && path.Masquerade {
		sources = path.TranslatedAddresses
	}
	var result []nativeScope
	for _, source := range sources {
		for _, protocol := range protocols {
			for _, port := range ports {
				result = append(result, nativeScopePredicate(protocol, family, policy.NetworkSelector{Interface: path.Interface}, policy.NetworkSelector{Interface: scope.clientInterface}, netip.PrefixFrom(source, source.BitLen()), scope.prefix, port, reply, physical))
			}
		}
	}
	return result
}
