package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// This is the forwarded-packet boundary. Local input/output and namespace UID
// isolation remain in the router's independently reviewed root firewall.
func (access *nativeAccess) compileFloor(ctx context.Context, b policy.Baseline, interfaces []string) error {
	access.sourceGuards = map[string]string{}
	access.serviceInterfaces = coreServiceInterfaces(b)
	attachments := map[string][]netip.Prefix{}
	owned := slices.Clone(b.NetworkModel.ServicePrefixes)
	for _, zone := range b.Zones {
		owned = append(owned, zone.Networks...)
		for _, iface := range zone.Interfaces {
			attachments[iface] = append(attachments[iface], zone.Networks...)
		}
	}
	for _, service := range b.NetworkModel.CoreServices {
		for _, address := range service.Addresses {
			prefix := netip.PrefixFrom(address, address.BitLen())
			attachments[service.Interface] = append(attachments[service.Interface], prefix)
			owned = append(owned, prefix)
		}
	}
	for _, path := range b.NetworkModel.CoreEgress {
		prefix := netip.PrefixFrom(path.Address, path.Address.BitLen())
		attachments[path.Interface] = append(attachments[path.Interface], prefix)
		owned = append(owned, prefix)
	}
	for index, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := fmt.Sprintf("native_attachment_%d", index)
		access.sourceGuards[iface] = name
		access.add("native_forward_floor", nativeMatch(fmt.Sprintf("iifname %q", iface), guardMeta("iifname"), iface), nativeVerdict("goto", name))
		for _, physical := range []bool{false, true} {
			rules := []nativeScope{}
			if iface == b.NetworkModel.UplinkInterface {
				for _, prefix := range owned {
					rules = append(rules, nativeJoin(nativeFloorPrefix(prefix, false, physical), nativeVerdict("drop", "")))
				}
				rules = append(rules, nativeVerdict("return", ""))
			} else {
				for _, prefix := range attachments[iface] {
					rules = append(rules, nativeJoin(nativeFloorPrefix(prefix, false, physical), nativeVerdict("return", "")))
				}
				rules = append(rules, nativeVerdict("drop", ""))
			}
			if physical {
				access.netdev[name] = rules
			} else {
				access.inet[name] = rules
			}
		}
	}
	access.add("native_forward_floor", nativeVerdict("drop", ""))
	// P03 includes delegated ceilings and must never become an owner ban.
	for _, block := range b.ProtectedNetworks {
		if block.ProtectionID == "P01" {
			for _, prefix := range block.Networks {
				access.addFloorDeny(prefix, false)
				access.addFloorDeny(prefix, true)
			}
		}
	}
	for _, scope := range []struct {
		prefixes []string
		target   bool
	}{
		{[]string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3", "::/128", "::1/128", "fe80::/10", "ff00::/8"}, false},
		{[]string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/24", "255.255.255.255/32", "::/128", "::1/128", "fe80::/10", "ff01::/16", "ff02::/16"}, true},
	} {
		for _, raw := range scope.prefixes {
			access.addFloorDeny(netip.MustParsePrefix(raw), scope.target)
		}
	}
	access.add("native_raw_floor", nativeVerdict("return", ""))
	access.netdev["native_raw_floor"] = append(access.netdev["native_raw_floor"], nativeVerdict("return", ""))
	// A forwarded packet must reach a reviewed physical attachment and retain
	// an admission kind. Each kind still needs its full physical tuple/epoch
	// checks; this also closes interfaces with no installed netdev hook.
	// nft lists interface indices as interface-name strings, including "0".
	access.add("native_egress_floor", nativeMatch("meta iif 0", guardMeta("iif"), "0"), nativeVerdict("return", ""))
	for _, iface := range interfaces {
		access.add("native_egress_floor", nativeMatch(fmt.Sprintf("oifname %q", iface), guardMeta("oifname"), iface), nativeVerdict("goto", "native_egress_kind"))
	}
	access.add("native_egress_floor", nativeVerdict("drop", ""))
	for _, reply := range []bool{false, true} {
		for _, tag := range []uint64{nativeTag(false, reply), nativeTag(true, reply), nativeDirectoryTag(reply), nativeCoreTag(reply)} {
			access.add("native_egress_kind", nativeMark(0xff000000, tag), nativeVerdict("return", ""))
		}
		for _, tag := range []uint64{nativeTag(false, reply), nativeTag(true, reply), nativeDirectoryTag(reply)} {
			access.add("native_egress_kind", nativeMark(0xff000000, nativeNATTag(tag, false)), nativeVerdict("return", ""))
		}
	}
	if len(access.asymmetric) != 0 {
		access.add("native_egress_kind", nativeMark(0xff000000, nativeAsymmetricTag), nativeVerdict("return", ""))
	}
	access.add("native_egress_kind", nativeMark(0xff000000, nativeCoreNATFinal), nativeVerdict("return", ""))
	access.add("native_egress_kind", nativeVerdict("drop", ""))
	return ctx.Err()
}

func nativeFloorPrefix(prefix netip.Prefix, target, physical bool) nativeScope {
	family := 6
	if prefix.Addr().Is4() {
		family = 4
	}
	source, destination := prefix, netip.Prefix{}
	if target {
		source, destination = destination, source
	}
	return nativeScopePredicate("any", family, policy.NetworkSelector{}, policy.NetworkSelector{}, source, destination, 0, false, physical)
}

func (access *nativeAccess) addFloorDeny(prefix netip.Prefix, target bool) {
	access.add("native_raw_floor", nativeFloorPrefix(prefix, target, false), nativeVerdict("drop", ""))
	access.netdev["native_raw_floor"] = append(access.netdev["native_raw_floor"], nativeJoin(nativeFloorPrefix(prefix, target, true), nativeVerdict("drop", "")))
}

func (access *nativeAccess) closeServiceAttachments(hook string) {
	for _, iface := range access.serviceInterfaces {
		for _, field := range []string{"iifname", "oifname"} {
			access.add(hook, nativeMatch(fmt.Sprintf("%s %q", field, iface), guardMeta(field), iface), nativeVerdict("drop", ""))
		}
	}
}
