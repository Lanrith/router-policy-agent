package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func nativeNAT46SourcePrefix(translation, source netip.Prefix) netip.Prefix {
	address, original := translation.Addr().As16(), source.Addr().As4()
	copy(address[12:], original[:])
	return netip.PrefixFrom(netip.AddrFrom16(address), 96+source.Bits())
}

type nativeNAT46Policy struct {
	entry, grant string
	chains       map[string][]nativeScope
}

// wirePolicy retains first-match authorization for a context selected by the
// original raw policy. Directory decisions cannot fall through to another
// owner rule. Its grant leaf must independently check a current typed grant;
// these chains install no hook and never accept a packet.
//
// The caller must bind originalRule to original.id from its own compiled
// context inventory, and check all current epochs, ownership and translator
// facts before and after this component. F1/F5 NAS-target geometry has a
// separate source namespace and is deliberately not admitted by this path.
func (model *nativeNAT46Model) wirePolicy(ctx context.Context, originalRule, mappingIndex int, original nativePacketContext, protocol string, reply, physical bool) (*nativeNAT46Policy, error) {
	return model.compileWirePolicy(ctx, originalRule, mappingIndex, original, protocol, reply, physical, false)
}

// Source-epoch static namespaces require the original compiler geometry. The
// caller must use its current source channel, client history exclusion, target
// ownership and a grant dispatcher that keeps static GIDs out of NAS UID sets.
func (model *nativeNAT46Model) wireSourcePolicy(ctx context.Context, sources *nativeNAT46StaticSources, originalRule, mappingIndex int, original nativePacketContext, protocol string, reply, physical bool) (*nativeNAT46Policy, error) {
	if ctx == nil || model == nil || sources == nil {
		return nil, errors.New("firewall: missing nat46 source policy geometry")
	}
	geometry, err := sources.evidence.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if geometry.BaselineHash != model.baselineHash || geometry.Prefix != model.prefix {
		return nil, errors.New("firewall: nat46 source policy geometry changed baseline")
	}
	return model.compileWirePolicy(ctx, originalRule, mappingIndex, original, protocol, reply, physical, true)
}

func (model *nativeNAT46Model) compileWirePolicy(ctx context.Context, originalRule, mappingIndex int, original nativePacketContext, protocol string, reply, physical, sourceGeometry bool) (*nativeNAT46Policy, error) {
	if ctx == nil || model == nil || model.rules == nil || originalRule < 0 || originalRule >= len(model.rules.rules) ||
		mappingIndex < 0 || mappingIndex >= len(model.mappings) || original.id > uint64(ownershipRuleMask) || original.iface == "" {
		return nil, errors.New("firewall: missing nat46 ordered wire policy")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	direction, family := "original", "inet"
	if reply {
		direction = "reply"
	}
	if physical {
		family = "physical"
	}
	name := fmt.Sprintf("native_n46_policy_%d_%s_%d_%d_%s_%s", mappingIndex, protocol, originalRule, original.id, direction, family)
	program := &nativeNAT46Policy{entry: name, grant: fmt.Sprintf("native_n46_grant_%d_%s_%s_%s", mappingIndex, protocol, direction, family), chains: map[string][]nativeScope{}}
	ordered := name + "_ordered"
	checks := nativeMark(uint64(ownershipRuleMask), original.id)
	if !physical {
		checks = nativeJoin(checks, nativeFactsPositiveConnection(),
			nativeMatch(fmt.Sprintf("ct mark & %#x == %d", ownershipRuleMask, originalRule), guardBinary("&", nativeCT("mark"), ownershipRuleMask), originalRule))
	}
	program.chains[name] = []nativeScope{nativeJoin(checks, nativeVerdict("goto", ordered)), nativeVerdict("drop", "")}
	count := len(program.chains[name])
	branchReserve := 4
	if sourceGeometry {
		branchReserve = 6
	}
	for index, rule := range model.rules.rules {
		scopes, err := model.wireScopes(ctx, index, mappingIndex, original, protocol, reply, physical)
		if err != nil {
			return nil, err
		}
		if len(scopes) == 0 {
			continue
		}
		branch := fmt.Sprintf("%s_rule_%d", name, index)
		// Include the terminal drop and the largest authorization branch before
		// appending rules to the program. The full layout has the same bound.
		if count+len(scopes)+branchReserve > nativeRuleCapacity {
			return nil, errors.New("firewall: nat46 ordered wire policy exceeds capacity")
		}
		for _, scope := range scopes {
			program.chains[ordered] = append(program.chains[ordered], nativeJoin(scope, nativeVerdict("goto", branch)))
		}
		count += len(scopes)
		if rule.Action == "deny" || index != originalRule {
			program.chains[branch] = []nativeScope{nativeVerdict("drop", "")}
			count++
			continue
		}
		directory := rule.Authorization == "directory" || rule.Authorization == "inherit" &&
			(slices.Contains(model.managed, original.iface) || slices.Contains(model.managed, model.mappings[mappingIndex].targetInterface))
		if directory && protocol == "icmp" {
			// Directory grants authorize TCP/UDP listeners. Echo cannot borrow
			// an unrelated transport grant or a blanket directory-live flag.
			program.chains[branch] = []nativeScope{nativeVerdict("drop", "")}
			count++
			continue
		}
		if directory {
			kind := nativeDirectoryTag(reply) | original.id
			program.chains[branch] = []nativeScope{
				nativeJoin(nativeMark(nativeTagMask, kind), nativeVerdict("jump", program.grant)),
				nativeJoin(nativeMark(nativeTagMask, kind), nativeVerdict("return", "")),
			}
			if sourceGeometry {
				kind = nativeNAT46StaticSourceTag(true, reply) | original.id
				program.chains[branch] = append(program.chains[branch], nativeJoin(nativeMark(nativeTagMask, kind), nativeVerdict("jump", program.grant)), nativeJoin(nativeMark(nativeTagMask, kind), nativeVerdict("return", "")))
			}
			program.chains[branch] = append(program.chains[branch], nativeVerdict("drop", ""))
		} else {
			program.chains[branch] = []nativeScope{
				nativeJoin(nativeMark(nativeTagMask, nativeTag(false, reply)|original.id), nativeVerdict("return", "")),
				nativeJoin(nativeMark(nativeTagMask, nativeNAT46StaticTag(reply)|original.id), nativeVerdict("return", "")),
			}
			if sourceGeometry {
				program.chains[branch] = append(program.chains[branch], nativeJoin(nativeMark(nativeTagMask, nativeNAT46StaticSourceTag(false, reply)|original.id), nativeVerdict("return", "")))
			}
			program.chains[branch] = append(program.chains[branch], nativeVerdict("drop", ""))
		}
		count += len(program.chains[branch])
	}
	program.chains[ordered] = append(program.chains[ordered], nativeVerdict("drop", ""))
	return program, ctx.Err()
}

// wireScopes projects one original rule for a fixed mapping and original packet
// context. Interface, MAC and address alternatives remain paired before the
// original IPv4 source becomes an embedded IPv6 source. A wire frame's Ethernet
// identity can never substitute for that original context.
//
// These predicates supply no verdict or grant. A caller must enforce ordering,
// authorization, current source/target ownership, tuple freshness and connection
// facts independently, then repeat the relevant checks at physical egress.
func (model *nativeNAT46Model) wireScopes(ctx context.Context, ruleIndex, mappingIndex int, original nativePacketContext, protocol string, reply, physical bool) ([]nativeScope, error) {
	if ctx == nil || model == nil || model.rules == nil || !model.prefix.IsValid() || !model.prefix.Addr().Is6() || model.prefix.Bits() != 96 ||
		ruleIndex < 0 || ruleIndex >= len(model.rules.rules) ||
		mappingIndex < 0 || mappingIndex >= len(model.mappings) || original.iface == "" ||
		original.family != 0 && original.family != 4 && original.family != 6 ||
		protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return nil, errors.New("firewall: missing nat46 wire scope dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rule, mapping := model.rules.rules[ruleIndex], model.mappings[mappingIndex]
	if original.family == 6 || rule.Family == 6 || rule.Protocol != "any" && rule.Protocol != protocol ||
		!nativeNAT46Destination(rule.To, mapping, false) {
		return nil, ctx.Err()
	}
	// Count reachable original alternatives before allocating predicates or
	// their embedded prefix collections. Ports remain under the original rule.
	ports := max(1, len(rule.Ports))
	count := 0
	for _, source := range rule.From {
		if source.Interface != "" && source.Interface != original.iface || source.MAC != "" && source.MAC != original.mac {
			continue
		}
		count += nativePrefixCount(source.Addresses, 4) * ports
		if count > nativeRuleCapacity {
			return nil, errors.New("firewall: nat46 wire scope exceeds capacity")
		}
	}
	projected := policy.NetworkRule{Action: rule.Action, Authorization: rule.Authorization,
		Protocol: protocol, Ports: rule.Ports, Family: 6,
		To: []policy.NetworkSelector{{Interface: mapping.targetInterface, Addresses: []netip.Prefix{netip.PrefixFrom(mapping.target, 128)}}}}
	for _, source := range rule.From {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if source.Interface != "" && source.Interface != original.iface || source.MAC != "" && source.MAC != original.mac {
			continue
		}
		prefixes := nativePrefixAlternatives(source.Addresses, 4)
		for _, prefix := range prefixes {
			if !prefix.IsValid() {
				prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			}
			projected.From = append(projected.From, policy.NetworkSelector{Interface: "nat46",
				Addresses: []netip.Prefix{nativeNAT46SourcePrefix(model.prefix, prefix)}})
		}
	}
	if len(projected.From) == 0 {
		return nil, ctx.Err()
	}
	if protocol == "icmp" {
		// The typed echo predicate constrains L4. A redundant protocol match
		// would disappear from nft's canonical packet graph.
		projected.Protocol = "any"
	}
	scopes, err := (&nativeRuleSet{rules: []policy.NetworkRule{projected}}).scopes(ctx, 0, reply, physical)
	if err != nil {
		return nil, err
	}
	if protocol == "icmp" {
		kind := "echo-request"
		if reply {
			kind = "echo-reply"
		}
		for index := range scopes {
			scopes[index] = nativeJoin(scopes[index],
				nativeMatch("icmpv6 type "+kind, guardPayload("icmpv6", "type"), kind),
				nativeMatch("icmpv6 code 0", guardPayload("icmpv6", "code"), 0))
		}
	}
	return scopes, ctx.Err()
}
