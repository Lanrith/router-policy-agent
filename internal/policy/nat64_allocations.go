package policy

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
)

// NAT64AllocationGeometry owns the compiler's source-pool catalog. It supplies
// connectivity geometry only: no binding, installed mapping, permission,
// original allocator receipt or runtime readiness can be recovered from it.
type NAT64AllocationGeometry struct {
	compiler *Compiler
}

// NAT64AllocationLedger is an immutable complete allocation snapshot. A new
// snapshot must retain every previous source/alias pair. Retirement and absence
// of traffic cannot make an alias available to a different IPv6 identity.
type NAT64AllocationLedger struct {
	geometry  *NAT64AllocationGeometry
	component string
	entries   []NAT64Allocation
}

// NAT64Allocation is diagnostic connectivity data, never authorization or proof
// that a translator installed the mapping. Identity is unique only within its
// component; /16-or-smaller pools make the IPv4 suffix an injective identifier.
// The kernel representation of this identifier is deliberately not selected.
type NAT64Allocation struct {
	Source   netip.Addr
	Alias    netip.Addr
	Identity uint16
}

// CompileNAT64AllocationGeometry retains the compiler's complete owned pool
// geometry independently of NAT46 and of translator process availability.
func (compiler *Compiler) CompileNAT64AllocationGeometry(ctx context.Context) (*NAT64AllocationGeometry, error) {
	if ctx == nil || compiler == nil || compiler.baseline.NetworkModel == nil || len(compiler.baseline.NAT64) == 0 {
		return nil, errors.New("policy: missing named NAT64 allocation geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, component := range compiler.baseline.NAT64 {
		if component.SourcePool == nil {
			return nil, errors.New("policy: NAT64 allocations require an owned source pool")
		}
	}
	return &NAT64AllocationGeometry{compiler: compiler}, nil
}

// MarshalJSON prevents a diagnostic encoding from replacing original geometry.
func (geometry NAT64AllocationGeometry) MarshalJSON() ([]byte, error) {
	return nil, errors.New("policy: original NAT64 allocation geometry cannot be serialized")
}

// MarshalJSON prevents a persisted diagnostic snapshot from replacing a ledger.
func (ledger NAT64AllocationLedger) MarshalJSON() ([]byte, error) {
	return nil, errors.New("policy: original NAT64 allocation ledger cannot be serialized")
}

// Capture validates a complete snapshot against original compiler geometry
// and an optional previous process-local ledger. Ready flags are not imported:
// a separate original publication must establish installed connectivity.
func (geometry *NAT64AllocationGeometry) Capture(ctx context.Context, componentID string, previous *NAT64AllocationLedger, records []NAT64SourceMapping) (*NAT64AllocationLedger, error) {
	if ctx == nil || geometry == nil || geometry.compiler == nil {
		return nil, errors.New("policy: missing original NAT64 allocation dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if previous != nil && (previous.geometry != geometry || previous.component != componentID) {
		return nil, errors.New("policy: NAT64 allocation parent belongs to different geometry")
	}
	var selected *NAT64
	for index := range geometry.compiler.baseline.NAT64 {
		component := &geometry.compiler.baseline.NAT64[index]
		if component.ID == componentID {
			selected = component
			break
		}
	}
	if selected == nil || selected.SourcePool == nil {
		return nil, errors.New("policy: unknown NAT64 allocation component")
	}
	pool := *selected.SourcePool
	maximum := (1 << (32 - pool.Bits())) - 3
	if records == nil || len(records) > maximum {
		return nil, errors.New("policy: NAT64 allocation snapshot exceeds its pool")
	}
	sources, aliases := map[netip.Addr]netip.Addr{}, map[netip.Addr]bool{}
	entries := make([]NAT64Allocation, 0, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !geometry.nativeSource(record.Source) || !record.Alias.Is4() || !validAddress(record.Alias) ||
			!pool.Contains(record.Alias) || record.Alias == pool.Addr() || record.Alias == pool.Addr().Next() ||
			record.Alias == lastPoolAddress(pool) || aliases[record.Alias] {
			return nil, errors.New("policy: invalid or duplicate NAT64 allocation")
		}
		if _, duplicate := sources[record.Source]; duplicate {
			return nil, errors.New("policy: duplicate NAT64 source identity")
		}
		address := record.Alias.As4()
		identity := binary.BigEndian.Uint16(address[2:])
		if identity == 0 {
			return nil, errors.New("policy: reserved NAT64 allocation identity")
		}
		sources[record.Source], aliases[record.Alias] = record.Alias, true
		entries = append(entries, NAT64Allocation{Source: record.Source, Alias: record.Alias, Identity: identity})
	}
	for _, reserved := range selected.SourceMappings {
		if sources[reserved.Source] != reserved.Alias {
			return nil, errors.New("policy: retained NAT64 source allocation changed")
		}
	}
	if previous != nil {
		for _, retained := range previous.entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if sources[retained.Source] != retained.Alias {
				return nil, errors.New("policy: previous NAT64 allocation was removed or reassigned")
			}
		}
	}
	slices.SortFunc(entries, func(first, second NAT64Allocation) int { return first.Source.Compare(second.Source) })
	return &NAT64AllocationLedger{geometry: geometry, component: componentID, entries: entries}, ctx.Err()
}

func (geometry *NAT64AllocationGeometry) nativeSource(source netip.Addr) bool {
	if !source.Is6() || !validAddress(source) || wellKnownPrefix.Contains(source) {
		return false
	}
	for _, component := range geometry.compiler.baseline.NAT64 {
		if component.Prefix.Contains(source) {
			return false
		}
	}
	if prefix := geometry.compiler.baseline.NetworkModel.NAT46Prefix; prefix != nil && prefix.Contains(source) {
		return false
	}
	return true
}

// Snapshot returns independent diagnostic data. It cannot replace an original
// ledger or establish that any mapping is installed in the translator.
func (ledger *NAT64AllocationLedger) Snapshot(ctx context.Context) ([]NAT64Allocation, error) {
	if ctx == nil || ledger == nil || ledger.geometry == nil {
		return nil, errors.New("policy: missing original NAT64 allocation ledger")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return slices.Clone(ledger.entries), nil
}

// ValidateLedger preserves original-object identity across package boundaries.
// A copied diagnostic snapshot cannot be substituted for compiler-owned
// geometry when a privileged runtime prepares installed allocation state.
func (geometry *NAT64AllocationGeometry) ValidateLedger(ctx context.Context, componentID string, ledger *NAT64AllocationLedger) ([]NAT64Allocation, error) {
	if ctx == nil || geometry == nil || geometry.compiler == nil || ledger == nil || ledger.geometry != geometry || ledger.component != componentID {
		return nil, errors.New("policy: NAT64 ledger is detached from original geometry")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return slices.Clone(ledger.entries), nil
}
