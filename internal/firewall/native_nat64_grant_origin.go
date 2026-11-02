package firewall

import (
	"context"
	"errors"
	"slices"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

// This memory-only dependency binds dynamic grant projection to the original
// allocation ledger and live supervisor. Listings and diagnostic snapshots
// cannot substitute for either object or alter the immutable compiler baseline.
type nativeNAT64GrantOrigin struct {
	transport *nativeNAT64Transport
	ledger    *policy.NAT64AllocationLedger
	readiness nativeNAT64Readiness
}

func nativeNAT64GrantMappings(ctx context.Context, transports []*nativeNAT64Transport, origins []*nativeNAT64GrantOrigin) ([][]policy.NAT64SourceMapping, error) {
	if ctx == nil || len(transports) == 0 || len(origins) != 0 && len(origins) != len(transports) {
		return nil, errors.New("firewall: incomplete NAT64 grant origins")
	}
	mappings := make([][]policy.NAT64SourceMapping, len(transports))
	for index, transport := range transports {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if transport == nil || transport.geometry == nil || !generationHash(transport.baselineHash) {
			return nil, errors.New("firewall: missing NAT64 grant geometry")
		}
		if len(origins) == 0 {
			mappings[index] = slices.Clone(transport.mappings)
			continue
		}
		origin := origins[index]
		if origin == nil || origin.transport != transport || origin.ledger == nil || origin.readiness == nil {
			return nil, errors.New("firewall: NAT64 grant origin changed its selected transport")
		}
		entries, err := transport.geometry.ValidateLedger(ctx, transport.component, origin.ledger)
		if err != nil {
			return nil, err
		}
		if err := origin.readiness.verifyNAT64Readiness(ctx, transport, entries); err != nil {
			return nil, err
		}
		mappings[index] = make([]policy.NAT64SourceMapping, 0, len(entries))
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			mappings[index] = append(mappings[index], policy.NAT64SourceMapping{
				Source: entry.Source, Alias: entry.Alias, Ready: nativeNAT64AllocationReady(entry, transport),
			})
		}
	}
	return mappings, ctx.Err()
}
