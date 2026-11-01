package firewall

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Re-observing identical producer evidence must not replace its original
// publication with a shorter relative timeout and withdraw its child grants.
// Keep only the original opaque receipt and installed deadlines. A new input,
// changed deadline/episode, expired receipt or missing epoch takes the normal
// fenced publication/revocation path. No listing can supply positive evidence.
func reuseNativeSource(ctx context.Context, previous *nativeSourcePublication, evidence policy.Ownership, epoch uint32, utc, anchor time.Time) (bool, error) {
	if ctx == nil || utc.IsZero() || anchor.IsZero() {
		return false, errors.New("firewall: missing source reuse clock")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if previous == nil {
		return false, nil
	}
	old, err := previous.evidence.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	next, err := evidence.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	if utc.Before(next.CompiledAt) {
		return false, errors.New("firewall: source reuse precedes compilation")
	}
	if old.BaselineHash != next.BaselineHash || old.BindingGeneration != next.BindingGeneration || old.Fingerprint != next.Fingerprint || old.Epoch != next.Epoch || epoch != old.Epoch || epoch == 0 || !old.ExpiresAt.Equal(next.ExpiresAt) || !slices.Equal(old.Addresses, next.Addresses) {
		return false, nil
	}
	if utc.Before(old.CompiledAt) || anchor.Before(previous.startedAt) {
		return false, errors.New("firewall: source reuse clock regressed")
	}
	if previous.epochTimeout < 1 || previous.epochTimeout > maximumElementLifetime || len(previous.timeouts) != len(old.Addresses) {
		return false, errors.New("firewall: source reuse receipt changed")
	}
	if _, err := previous.evidence.EpochRemaining(utc); err != nil {
		return false, nil //nolint:nilerr // Expiry selects normal fenced preparation, never reuse.
	}
	if !anchor.Before(previous.startedAt.Add(time.Duration(previous.epochTimeout) * time.Second)) {
		return false, nil
	}
	for index := range old.Addresses {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if _, err := previous.remaining(ctx, index, anchor); err != nil {
			return false, nil //nolint:nilerr // An elapsed publication cannot be reused; normal preparation still validates it.
		}
		if _, err := previous.evidence.Remaining(index, utc); err != nil {
			return false, nil //nolint:nilerr // Expired evidence must take the normal checked path.
		}
	}
	return true, nil
}
