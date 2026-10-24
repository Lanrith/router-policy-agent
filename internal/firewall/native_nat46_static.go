package firewall

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Both children come from the same independently owned root baseline. The
// diagnostic source snapshot cannot replace either compiler-local evidence or
// the current OwnerConfiguration proof required by a writer.
type nativeNAT46StaticSources struct {
	model    *nativeNAT46Model
	evidence policy.NAT46StaticGeometry
}

func newNativeNAT46StaticSources(ctx context.Context, baseline policy.Baseline) (*nativeNAT46StaticSources, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing static nat46 source context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(baseline)
	if err != nil {
		return nil, errors.New("firewall: static nat46 baseline encoding failed")
	}
	b, err := policy.DecodeBaseline(raw)
	if err != nil {
		return nil, err
	}
	compiler, err := policy.New(b)
	if err != nil {
		return nil, err
	}
	geometry, err := compiler.CompileNAT46StaticGeometry(ctx)
	if err != nil {
		return nil, err
	}
	model, err := newNativeNAT46Model(ctx, b)
	if err != nil {
		return nil, err
	}
	return &nativeNAT46StaticSources{model: model, evidence: geometry}, ctx.Err()
}
