package policy

import (
	"context"
	"errors"
	"net/netip"
)

// NAT64TargetClass describes connectivity address space, never access permission.
// Exclusions take precedence over Allowed. Returned slices are independently
// owned; they cannot replace an original allocation ledger or readiness proof.
type NAT64TargetClass struct {
	Allowed, Excluded []netip.Prefix
}

// TargetClass describes the same IPv4 class as EligibleTarget for an installed
// component. Reverse callbacks use it for the IPv4 caller embedded under that
// component's prefix. It supplies no grant, identity or live translator proof.
func (geometry *NAT64AllocationGeometry) TargetClass(ctx context.Context, componentID string) (NAT64TargetClass, error) {
	if ctx == nil || geometry == nil || geometry.compiler == nil {
		return NAT64TargetClass{}, errors.New("policy: missing NAT64 target class geometry")
	}
	if err := ctx.Err(); err != nil {
		return NAT64TargetClass{}, err
	}
	private := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	for _, component := range geometry.compiler.baseline.NAT64 {
		if component.ID != componentID {
			continue
		}
		if component.Scope == "private" {
			return NAT64TargetClass{Allowed: private}, ctx.Err()
		}
		result := NAT64TargetClass{Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Excluded: private}
		// These are the IPv4 exclusions of netip.IsGlobalUnicast. The
		// remaining policy-specific exclusions share their canonical lists
		// with validAddress and globalIPv4, rather than a firewall copy.
		result.Excluded = append(result.Excluded,
			netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("224.0.0.0/4"))
		for _, prefix := range nonPeerPrefixes {
			if prefix.Addr().Is4() {
				result.Excluded = append(result.Excluded, prefix)
			}
		}
		result.Excluded = append(result.Excluded, nonGlobalIPv4...)
		return result, ctx.Err()
	}
	return NAT64TargetClass{}, errors.New("policy: undeclared NAT64 target class component")
}
