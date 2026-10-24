package policy

import (
	"context"
	"errors"
)

// OwnerConfigurationSnapshot is diagnostic metadata for immutable owner intent.
// It contains no device ownership, directory observation or delegated grant.
type OwnerConfigurationSnapshot struct {
	BaselineHash string `json:"baseline_hash"`
	Epoch        uint32 `json:"epoch"`
}

// OwnerConfiguration binds static owner intent to a durably consumed startup
// sequence. It is helper-local and cannot be restored from a diagnostic copy.
// Static configuration has no directory or binding deadline. Flows involving
// managed identities still require separate current physical evidence.
type OwnerConfiguration struct {
	data *OwnerConfigurationSnapshot
}

// CompileOwnerConfiguration requires a validated named baseline and a startup
// sequence consumed by the locked durable store. The trusted helper supplies
// that sequence; reader IPC cannot call this operation or choose its value.
// Publication must independently enforce the pinned profile and writer fence.
func (compiler *Compiler) CompileOwnerConfiguration(ctx context.Context, epoch uint32) (OwnerConfiguration, error) {
	if ctx == nil || compiler == nil || compiler.baseline.NetworkModel == nil || epoch == 0 || epoch > MaximumOwnershipEpoch {
		return OwnerConfiguration{}, errors.New("policy: missing named owner configuration or consumed sequence")
	}
	if err := ctx.Err(); err != nil {
		return OwnerConfiguration{}, err
	}
	return OwnerConfiguration{data: &OwnerConfigurationSnapshot{BaselineHash: compiler.hash, Epoch: epoch}}, nil
}

// Snapshot returns diagnostic values without supplying publishable evidence.
func (configuration OwnerConfiguration) Snapshot(ctx context.Context) (OwnerConfigurationSnapshot, error) {
	if ctx == nil || configuration.data == nil {
		return OwnerConfigurationSnapshot{}, errors.New("policy: missing owner configuration evidence or context")
	}
	if err := ctx.Err(); err != nil {
		return OwnerConfigurationSnapshot{}, err
	}
	return *configuration.data, nil
}

// MarshalJSON rejects persistence and transport of positive configuration proof.
func (configuration OwnerConfiguration) MarshalJSON() ([]byte, error) {
	return nil, errors.New("policy: owner configuration evidence cannot be serialized")
}
