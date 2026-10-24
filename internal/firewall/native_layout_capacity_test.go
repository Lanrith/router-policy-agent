package firewall

import (
	"context"
	"errors"
	"testing"
)

func TestNativeCapacityIncludesFixedGuards(t *testing.T) {
	t.Parallel()
	layout, err := newNativeNAT46AccessLayout(t.Context(), nat46ForwardingBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	// Mutate only a test-owned, thawed layout. Production constructors finish
	// construction and capacity checks before freezing their expectations.
	layout.inspectionSchemas = nil
	count, err := layout.compiledNativeRuleCount(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if count <= layout.native.ruleCount(layout.interfaces) {
		t.Fatal("capacity omitted fixed guard or hook rules")
	}
	padding := make([]nativeScope, nativeRuleCapacity-count)
	for index := range padding {
		padding[index] = nativeVerdict("drop", "")
	}
	layout.native.inet["native_capacity_padding"] = padding
	if err := layout.checkNativeCapacity(t.Context()); err != nil {
		t.Fatal("exact complete rule limit rejected", err)
	}
	layout.native.inet["native_capacity_padding"] = append(padding, nativeVerdict("drop", ""))
	if err := layout.native.checkCapacity(layout.interfaces); err != nil {
		t.Fatal("test did not reproduce the incremental-accounting gap", err)
	}
	if err := layout.checkNativeCapacity(t.Context()); err == nil {
		t.Fatal("one rule beyond the complete limit admitted")
	}
}

func TestNativeCompleteCapacityRequiresContext(t *testing.T) {
	t.Parallel()
	layout := &guardLayout{native: &nativeAccess{}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := layout.checkNativeCapacity(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if err := (*guardLayout)(nil).checkNativeCapacity(t.Context()); err == nil {
		t.Fatal("missing layout accepted")
	}
}
