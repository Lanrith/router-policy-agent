package firewall

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

// nativeSourceClass describes one policy-equivalent subset of a NAT source allocation.
// Sources in children belong to more-specific classes and are excluded here.
// This does not establish placement, grant access, or validate an actual source.
type nativeSourceClass struct {
	prefix   netip.Prefix
	children []netip.Prefix
}

func (class nativeSourceClass) contains(address netip.Addr) bool {
	if !class.prefix.Contains(address) {
		return false
	}
	for _, child := range class.children {
		if child.Contains(address) {
			return false
		}
	}
	return true
}

// within is true only when every address represented by the class is inside
// the selector. Selector boundaries must be included when partitionNativeSources is called.
func (class nativeSourceClass) within(selector netip.Prefix) bool {
	return selector.Addr().Is4() && selector.Bits() <= class.prefix.Bits() && selector.Contains(class.prefix.Addr())
}

func partitionNativeSources(ctx context.Context, allocations, boundaries []netip.Prefix) ([]nativeSourceClass, error) {
	if ctx == nil || len(allocations) == 0 || len(allocations) > 256 || len(boundaries) > 4096 {
		return nil, errors.New("firewall: invalid source-class geometry")
	}
	order := func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	}
	pools := slices.Clone(allocations)
	slices.SortFunc(pools, order)
	for i, prefix := range pools {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return nil, errors.New("firewall: invalid IPv4 source allocation")
		}
		if i > 0 && pools[i-1].Overlaps(prefix) {
			return nil, errors.New("firewall: overlapping source allocations")
		}
	}
	unique := map[netip.Prefix]bool{}
	for _, prefix := range pools {
		unique[prefix] = true
	}
	for _, prefix := range boundaries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return nil, errors.New("firewall: invalid source selector boundary")
		}
		if !prefix.Addr().Is4() {
			continue
		}
		for _, pool := range pools {
			if pool.Bits() < prefix.Bits() && pool.Contains(prefix.Addr()) {
				unique[prefix] = true
				break
			}
		}
	}
	nodes := make([]netip.Prefix, 0, len(unique))
	for prefix := range unique {
		nodes = append(nodes, prefix)
	}
	slices.SortFunc(nodes, order)
	if len(nodes) > 1024 {
		return nil, errors.New("firewall: source-class capacity exceeded")
	}
	classes := make([]nativeSourceClass, 0, len(nodes))
	// Sorted prefixes form a forest. A stack visits immediate children without
	// a quadratic scan, even when the owner declares many host exceptions.
	stack := []int{}
	for _, prefix := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for len(stack) > 0 && !classes[stack[len(stack)-1]].prefix.Contains(prefix.Addr()) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			parent := &classes[stack[len(stack)-1]]
			parent.children = append(parent.children, prefix)
		}
		classes = append(classes, nativeSourceClass{prefix: prefix})
		stack = append(stack, len(classes)-1)
	}
	result := make([]nativeSourceClass, 0, len(classes))
	for _, class := range classes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		size := uint64(1) << (32 - class.prefix.Bits())
		for _, child := range class.children {
			size -= uint64(1) << (32 - child.Bits())
		}
		if size != 0 {
			result = append(result, class)
		}
	}
	return result, ctx.Err()
}
