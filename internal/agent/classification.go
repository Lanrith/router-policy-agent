package agent

import (
	"context"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/state"
)

// History is additive in the kernel. Empty failure/stop handoffs cannot erase
// the helper's knowledge of already published classifiers. This cache contains
// deny-only history, never a restored address binding or permission.
func (engine *Engine) classificationUnion(input state.Classification) (state.Classification, bool, error) {
	owned, err := state.CloneClassification(input)
	if err != nil {
		return state.Classification{}, false, err
	}
	added := false
	for index, values := range []*[]string{&owned.MACs, &owned.IPv4, &owned.IPv6} {
		previous := engine.classification.MACs
		switch index {
		case 1:
			previous = engine.classification.IPv4
		case 2:
			previous = engine.classification.IPv6
		}
		for _, value := range *values {
			if _, exists := slices.BinarySearch(previous, value); !exists {
				added = true
			}
		}
		*values = append(*values, previous...)
		slices.Sort(*values)
		*values = slices.Compact(*values)
	}
	checked, err := state.CloneClassification(owned)
	return checked, added, err
}

// The result records a completed classification rotation, including withdrawal
// of old ownership and application permits. It is local to the current engine
// transaction; it is neither a source receipt nor authorization.
func (engine *Engine) publishClassification(ctx context.Context, history state.Classification) (bool, error) {
	_, added, err := engine.classificationUnion(history)
	if err != nil {
		return false, err
	}
	if added || engine.classificationFailed {
		if err := engine.seal(ctx, history); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
