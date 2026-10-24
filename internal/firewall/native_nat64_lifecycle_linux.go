package firewall

import (
	"context"
	"errors"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// refreshRuntimeConfiguration publishes the owner epoch before asking the
// separately supervised translator for live activation proofs. A failed or
// incomplete activation withdraws both NAT64 runtime state and the owner epoch;
// profile data alone can never activate translation.
func (b *guardedBackend) refreshRuntimeConfiguration(
	ctx context.Context,
	configuration policy.OwnerConfiguration,
	supervisor nativeNAT64Supervisor,
) (result error) {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing runtime configuration dependencies")
	}
	var transports []*nativeNAT64Transport
	if b.options.profile != nil && b.options.profile.layout != nil && b.options.profile.layout.native != nil {
		transports = b.options.profile.layout.native.selectedNAT64Transports()
	}
	if (len(transports) != 0) != (supervisor != nil) {
		return errors.New("firewall: NAT64 supervisor differs from selected profile")
	}
	if err := b.refreshConfiguration(ctx, configuration); err != nil {
		return err
	}
	if len(transports) == 0 {
		return ctx.Err()
	}
	defer func() {
		if result == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*commandTimeout)
		defer cancel()
		result = errors.Join(result, b.clearRuntimeConfiguration(cleanup))
	}()
	activations, err := supervisor.activations(ctx, slices.Clone(transports))
	if err != nil {
		return err
	}
	return b.activateNAT64Components(ctx, activations, configuration)
}

// clearRuntimeConfiguration is denial-only and deliberately does not ask the
// translator supervisor for evidence. The selected profile supplies the fixed
// object inventory needed to revoke NAT64 before clearing the owner epoch.
func (b *guardedBackend) clearRuntimeConfiguration(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing runtime configuration revocation dependencies")
	}
	var transports []*nativeNAT64Transport
	if b.options.profile != nil && b.options.profile.layout != nil && b.options.profile.layout.native != nil {
		transports = b.options.profile.layout.native.selectedNAT64Transports()
	}
	if len(transports) == 0 {
		return b.clearConfiguration(ctx)
	}
	return errors.Join(b.clearNAT64(ctx), b.clearConfiguration(ctx))
}
