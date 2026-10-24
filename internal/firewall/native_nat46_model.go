package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

type nativeNAT46Mapping struct {
	id, targetInterface string
	alias, target       netip.Addr
}

// This is immutable projection geometry. It does not install a translator,
// publish a tuple proof, supply a grant or activate the default helper.
type nativeNAT46Model struct {
	baselineHash string
	prefix       netip.Prefix
	rules        *nativeRuleSet
	mappings     []nativeNAT46Mapping
	managed      []string
}

func newNativeNAT46Model(ctx context.Context, baseline policy.Baseline) (*nativeNAT46Model, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing nat46 model context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(baseline)
	if err != nil {
		return nil, errors.New("firewall: nat46 baseline encoding failed")
	}
	b, err := policy.DecodeBaseline(raw)
	if err != nil {
		return nil, err
	}
	if b.NetworkModel == nil || b.NetworkModel.NAT46Prefix == nil || len(b.NAT46Pools) != 1 || len(b.NAT46) == 0 {
		return nil, errors.New("firewall: nat46 projection requires enabled generated geometry")
	}
	compiler, err := policy.New(b)
	if err != nil {
		return nil, err
	}
	model := &nativeNAT46Model{baselineHash: compiler.BaselineHash(), prefix: *b.NetworkModel.NAT46Prefix,
		rules: &nativeRuleSet{baselineHash: compiler.BaselineHash(), rules: b.NetworkModel.Rules, uplinkNAT: b.NetworkModel.UplinkNAT}}
	for _, zone := range b.Zones {
		if b.DirectoryManaged(zone.Role) {
			model.managed = append(model.managed, zone.Interfaces...)
		}
	}
	for _, mapping := range b.NAT46 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !mapping.Ready {
			continue
		}
		iface, err := nativeNAT46TargetInterface(b, mapping.Target)
		if err != nil {
			return nil, err
		}
		model.mappings = append(model.mappings, nativeNAT46Mapping{id: mapping.ID, alias: mapping.Alias, target: mapping.Target, targetInterface: iface})
	}
	projected := 0
	for index, rule := range model.rules.rules {
		if rule.Family == 6 || rule.Protocol == "icmpv6" || !nativeNAT46HasIPv4Source(rule) {
			continue
		}
		for _, mapping := range model.mappings {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !nativeNAT46Destination(rule.To, mapping, false) || nativeNAT46Destination(rule.To, mapping, true) {
				continue
			}
			alias := policy.NetworkSelector{Interface: "nat46", Addresses: []netip.Prefix{netip.PrefixFrom(mapping.alias, 32)}}
			branch := rule
			branch.Family, branch.To = 4, []policy.NetworkSelector{alias}
			count, err := nativeScopeCount(branch)
			if err != nil || count > nativeRuleCapacity-projected {
				return nil, errors.New("firewall: nat46 projection exceeds capacity")
			}
			projected += count
			model.rules.rules[index].To = append(model.rules.rules[index].To, alias)
		}
	}
	return model, ctx.Err()
}

func nativeNAT46HasIPv4Source(rule policy.NetworkRule) bool {
	for _, source := range rule.From {
		if nativePrefixCount(source.Addresses, 4) != 0 {
			return true
		}
	}
	return false
}

func nativeNAT46Destination(selectors []policy.NetworkSelector, mapping nativeNAT46Mapping, rawOnly bool) bool {
	for _, endpoint := range selectors {
		for _, variant := range []struct {
			address netip.Addr
			iface   string
		}{{mapping.alias, "nat46"}, {mapping.target, mapping.targetInterface}} {
			if rawOnly && variant.iface != "nat46" || endpoint.Interface != "" && endpoint.Interface != variant.iface {
				continue
			}
			if len(endpoint.Addresses) == 0 {
				return true
			}
			for _, prefix := range endpoint.Addresses {
				if prefix.Contains(variant.address) {
					return true
				}
			}
		}
	}
	return false
}

func nativeNAT46TargetInterface(b policy.Baseline, target netip.Addr) (string, error) {
	selected, length := b.NetworkModel.UplinkInterface, -1
	for _, zone := range b.Zones {
		for _, prefix := range zone.Networks {
			if !prefix.Contains(target) || prefix.Bits() < length {
				continue
			}
			if len(zone.Interfaces) != 1 || prefix.Bits() == length && selected != zone.Interfaces[0] {
				return "", errors.New("firewall: ambiguous nat46 target attachment")
			}
			selected, length = zone.Interfaces[0], prefix.Bits()
		}
	}
	for _, service := range b.NetworkModel.CoreServices {
		for _, listener := range service.Addresses {
			if listener == target {
				return service.Interface, nil
			}
		}
	}
	return selected, nil
}
