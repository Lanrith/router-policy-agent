package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// nativeScope is one conjunction from a normalized rule. Alternatives stay
// within the same rule index, before advancing to the next ordered decision.
// Physical predicates omit the original ingress and source MAC: the caller must
// correlate those through the exact rule/epoch stamped before route traversal.
// A reply instead checks the original source MAC as its actual target MAC.
// These predicates supply no access verdict or owner permission by themselves.
type nativeScope struct {
	text        string
	expressions []any
}

// nativeRuleSet owns a validated copy, including selector and port slices.
// Only image-generation plumbing constructs it; no reader can provide a rule
// fragment, interface expression or already-rendered predicate.
type nativeRuleSet struct {
	baselineHash string
	rules        []policy.NetworkRule
	uplinkNAT    []policy.UplinkNAT
}

func newNativeRuleSet(baseline policy.Baseline) (*nativeRuleSet, error) {
	data, err := json.Marshal(baseline)
	if err != nil {
		return nil, errors.New("firewall: native rule baseline encoding failed")
	}
	owned, err := policy.DecodeBaseline(data)
	if err != nil {
		return nil, err
	}
	if owned.NetworkModel == nil {
		return nil, errors.New("firewall: native ordered predicates require a named model")
	}
	compiler, err := policy.New(owned)
	if err != nil {
		return nil, err
	}
	return &nativeRuleSet{baselineHash: compiler.BaselineHash(), rules: owned.NetworkModel.Rules, uplinkNAT: owned.NetworkModel.UplinkNAT}, nil
}

func (set *nativeRuleSet) scopes(ctx context.Context, index int, reply, physical bool) ([]nativeScope, error) {
	if ctx == nil || set == nil || index < 0 || index >= len(set.rules) {
		return nil, errors.New("firewall: missing native predicate context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rule := set.rules[index]
	if _, err := nativeScopeCount(rule); err != nil {
		return nil, err
	}
	var result []nativeScope
	for _, source := range rule.From {
		for _, target := range rule.To {
			for _, family := range []int{4, 6} {
				if rule.Family != 0 && rule.Family != family || rule.Protocol == "icmp" && family != 4 || rule.Protocol == "icmpv6" && family != 6 {
					continue
				}
				fromGroups := nativePrefixGroups(nativePrefixAlternatives(source.Addresses, family))
				toGroups := nativePrefixGroups(nativePrefixAlternatives(target.Addresses, family))
				ports := rule.Ports
				if len(ports) == 0 {
					ports = []uint16{0}
				}
				for _, from := range fromGroups {
					for _, to := range toGroups {
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						scope, err := nativeAlternativeScope(rule.Protocol, family, source, target, from, to, ports, reply, physical)
						if err != nil {
							return nil, err
						}
						result = append(result, scope)
					}
				}
			}
		}
	}
	return result, nil
}

// physicalScopes retains the whole incoming endpoint alternative before the
// physical predicate omits iif/source MAC. An address from another attachment
// must not be borrowed merely because that rule also mentions that attachment.
func (set *nativeRuleSet) physicalScopes(ctx context.Context, index int, packetContext nativePacketContext, reply, translated bool) ([]nativeScope, error) {
	if ctx == nil || set == nil || index < 0 || index >= len(set.rules) || translated && packetContext.source == nil {
		return nil, errors.New("firewall: missing physical packet context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selected := set.physicalRule(index, packetContext, reply, translated, "")
	return (&nativeRuleSet{rules: []policy.NetworkRule{selected}}).scopes(ctx, 0, reply, true)
}

// physicalRule filters whole endpoint alternatives using both known physical
// attachments. The source address/MAC conjunction stays with its original iif;
// an endpoint on another oif cannot produce a reachable egress predicate.
func (set *nativeRuleSet) physicalRule(index int, packetContext nativePacketContext, reply, translated bool, outgoing string) policy.NetworkRule {
	selected := set.rules[index]
	if packetContext.family != 0 {
		if selected.Family != 0 && selected.Family != packetContext.family {
			selected.From, selected.To = nil, nil
			return selected
		}
		selected.Family = packetContext.family
	}
	if translated {
		if selected.Family == 6 || selected.Protocol == "icmpv6" {
			selected.From, selected.To = nil, nil
			return selected
		}
		selected.Family = 4
	}
	endpoints := selected.From
	if reply {
		endpoints = selected.To
	}
	retained := []policy.NetworkSelector{}
	for _, source := range endpoints {
		if source.Interface != "" && source.Interface != packetContext.iface || !reply && source.MAC != "" && source.MAC != packetContext.mac {
			continue
		}
		if translated {
			matches := len(source.Addresses) == 0
			for _, prefix := range source.Addresses {
				matches = matches || packetContext.source.within(prefix)
			}
			if !matches {
				continue
			}
			source.Addresses = nil
		}
		retained = append(retained, source)
	}
	if reply {
		selected.To = retained
	} else {
		selected.From = retained
	}
	if outgoing != "" {
		endpoints = selected.To
		if reply {
			endpoints = selected.From
		}
		retained = []policy.NetworkSelector{}
		for _, endpoint := range endpoints {
			if endpoint.Interface == "" || endpoint.Interface == outgoing {
				retained = append(retained, endpoint)
			}
		}
		if reply {
			selected.From = retained
		} else {
			selected.To = retained
		}
	}
	return selected
}

func nativePrefixAlternatives(prefixes []netip.Prefix, family int) []netip.Prefix {
	if len(prefixes) == 0 {
		return []netip.Prefix{{}}
	}
	var result []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Addr().Is4() == (family == 4) {
			result = append(result, prefix)
		}
	}
	return result
}

func nativeScopePredicate(protocol string, family int, source, target policy.NetworkSelector, from, to netip.Prefix, port uint16, reply, physical bool) nativeScope {
	incoming, outgoing, mac := source.Interface, target.Interface, source.MAC
	if reply {
		incoming, outgoing, from, to = outgoing, incoming, to, from
	}
	spelling, familyName := "ip", "ipv4"
	if family == 6 {
		spelling, familyName = "ip6", "ipv6"
	}
	// A /0 selects every address in its family. Keep the family predicate
	// even when nft would fold the tautological address comparison away.
	if from.IsValid() && from.Bits() == 0 {
		from = netip.Prefix{}
	}
	if to.IsValid() && to.Bits() == 0 {
		to = netip.Prefix{}
	}
	var text []string
	var expressions []any
	appendMatch := func(selector string, left, right any) {
		text = append(text, selector)
		expressions = append(expressions, guardMatch(left, right))
	}
	if !from.IsValid() && !to.IsValid() {
		if physical {
			appendMatch("meta protocol "+spelling, guardMeta("protocol"), spelling)
		} else {
			appendMatch("meta nfproto "+familyName, guardMeta("nfproto"), familyName)
		}
	}
	if incoming != "" && !physical {
		appendMatch(fmt.Sprintf("iifname %q", incoming), guardMeta("iifname"), incoming)
	}
	if outgoing != "" {
		appendMatch(fmt.Sprintf("oifname %q", outgoing), guardMeta("oifname"), outgoing)
	}
	for _, endpoint := range []struct {
		field  string
		prefix netip.Prefix
	}{{"saddr", from}, {"daddr", to}} {
		if !endpoint.prefix.IsValid() {
			continue
		}
		value := any(endpoint.prefix.Addr().String())
		literal := endpoint.prefix.Addr().String()
		if endpoint.prefix.Bits() != endpoint.prefix.Addr().BitLen() {
			value, literal = controllerPrefix(endpoint.prefix), endpoint.prefix.String()
		}
		appendMatch(spelling+" "+endpoint.field+" "+literal, guardPayload(spelling, endpoint.field), value)
	}
	if mac != "" && (reply == physical) {
		field := "saddr"
		if reply {
			field = "daddr"
		}
		appendMatch("ether "+field+" "+mac, guardPayload("ether", field), mac)
	}
	if port != 0 {
		field := "dport"
		if reply {
			field = "sport"
		}
		// A typed transport field already constrains its L4 protocol. Avoid
		// redundant predicates whose canonical listing nft would elide.
		appendMatch(fmt.Sprintf("%s %s %d", protocol, field, port), guardPayload(protocol, field), port)
	} else if protocol != "any" {
		if protocol == "icmpv6" {
			protocol = "ipv6-icmp"
		}
		appendMatch("meta l4proto "+protocol, guardMeta("l4proto"), protocol)
	}
	return nativeScope{text: strings.Join(text, " "), expressions: expressions}
}
