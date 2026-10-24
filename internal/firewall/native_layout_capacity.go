package firewall

import (
	"context"
	"errors"
	"fmt"
)

// Include the fixed guard and hook rules as well as the native access graph.
// Incremental access budgets bound construction, but omit the fixed base.
// This final count uses only the completed code-owned schema, never a listing.
func (layout *guardLayout) compiledNativeRuleCount(ctx context.Context) (int, error) {
	if ctx == nil || layout == nil || layout.native == nil {
		return 0, errors.New("firewall: missing complete native capacity dependencies")
	}
	count := 0
	for _, family := range []string{"inet", "netdev"} {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		schema, err := layout.schema(family)
		if err != nil {
			return 0, err
		}
		for _, rules := range schema.rules {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			count += len(rules)
		}
	}
	return count, ctx.Err()
}

func (layout *guardLayout) checkNativeCapacity(ctx context.Context) error {
	count, err := layout.compiledNativeRuleCount(ctx)
	if err != nil {
		return err
	}
	if count > nativeRuleCapacity {
		return fmt.Errorf("firewall: complete native guard program exceeds capacity: %d > %d", count, nativeRuleCapacity)
	}
	return nil
}

// The protected artifact keeps its independent 8,192-object bound. Helper
// objects have an exact code-owned inventory; counting them against that same
// allowance would reject a valid large helper before its schema can be checked.
// Output bytes and strict decoding remain bounded separately.
func (layout *guardLayout) completeInventoryLimit(ctx context.Context) (int, error) {
	if ctx == nil || layout == nil {
		return 0, errors.New("firewall: missing complete inventory dependencies")
	}
	limit := 1 + maximumRulesetObjects // One actual listing metadata object.
	for _, family := range []string{"inet", "netdev"} {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		schema, err := layout.schema(family)
		if err != nil {
			return 0, err
		}
		limit += 1 + len(schema.sets) + len(schema.maps) + len(schema.chains)
		for _, rules := range schema.rules {
			limit += len(rules)
		}
	}
	return limit, ctx.Err()
}
