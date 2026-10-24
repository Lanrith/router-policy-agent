package policy

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
)

// OwnedAddress is qualified current placement and address evidence. It contains
// no directory permission. BindingRef identifies the association and ownership
// episode without exposing the producer's session identifiers.
type OwnedAddress struct {
	MAC        string     `json:"mac"`
	Interface  string     `json:"interface"`
	VLAN       uint16     `json:"vlan"`
	Address    netip.Addr `json:"address"`
	ExpiresAt  time.Time  `json:"expires_at"`
	BindingRef string     `json:"binding_ref"`
}

// OwnershipRuleBits reserves a bounded rule identity in each connection mark.
// MaximumOwnershipEpoch leaves the reserved all-ones generation unavailable;
// the durable counter must never wrap into a previously admitted connection.
const (
	OwnershipRuleBits     = 10
	MaximumOwnershipEpoch = uint32(math.MaxUint32>>OwnershipRuleBits) - 1
)

// OwnershipSnapshot is an independent diagnostic copy, not renewable evidence.
// Fingerprint excludes refresh timestamps so a routine observation does not
// look like a different owner. A changed association or ownership episode does.
type OwnershipSnapshot struct {
	BaselineHash      string         `json:"baseline_hash"`
	BindingGeneration string         `json:"binding_generation"`
	CompiledAt        time.Time      `json:"compiled_at"`
	Fingerprint       string         `json:"fingerprint"`
	Epoch             uint32         `json:"epoch"`
	ExpiresAt         time.Time      `json:"expires_at"`
	Addresses         []OwnedAddress `json:"addresses"`
}

// Ownership is an immutable helper-local result with an elapsed-age anchor.
// A zero value supplies no evidence. It cannot be supplied by reader IPC or
// restored from persistence, and does not carry or renew a directory grant.
type Ownership struct {
	data *ownership
}

type ownership struct {
	snapshot OwnershipSnapshot
	anchor   time.Time
}

// InEpoch attaches a durably consumed helper-owned sequence to fresh physical
// evidence. The sequence is not a directory grant, nor a substitute for this
// evidence's baseline, binding episode or original expiry. Callers must obtain
// it from the locked persistent store before publishing connection state.
func (evidence Ownership) InEpoch(ctx context.Context, epoch uint32) (Ownership, error) {
	if ctx == nil || evidence.data == nil || epoch == 0 || epoch > MaximumOwnershipEpoch {
		return Ownership{}, errors.New("policy: missing ownership evidence or consumed sequence")
	}
	if err := ctx.Err(); err != nil {
		return Ownership{}, err
	}
	owned := *evidence.data
	owned.snapshot = evidence.data.snapshot
	owned.snapshot.Addresses = slices.Clone(owned.snapshot.Addresses)
	owned.snapshot.Epoch = epoch
	return Ownership{data: &owned}, nil
}

// CompileOwnership validates independently collected bindings without needing
// a directory observation. Callers must authenticate that producer and supply
// the same trusted UTC and monotonic clock boundary used for authorization.
// Unknown or management attachments supply no positive ownership tuples.
func (compiler *Compiler) CompileOwnership(
	ctx context.Context,
	snapshot binding.Snapshot,
	now time.Time,
	anchor AgeAnchor,
) (Ownership, error) {
	if compiler == nil || ctx == nil || compiler.baseline.NetworkModel == nil ||
		now.IsZero() || anchor.tick.IsZero() || time.Since(anchor.tick) < 0 {
		return Ownership{}, errors.New("policy: missing named ownership compiler or clock")
	}
	if err := ctx.Err(); err != nil {
		return Ownership{}, err
	}
	now = now.Round(0).UTC()
	lease := leaseDuration(compiler.baseline)
	if err := binding.Validate(snapshot, now, lease, compiler.baseline.MaximumDevices); err != nil {
		return Ownership{}, err
	}
	if !identifier.MatchString(snapshot.Generation) {
		return Ownership{}, errors.New("policy: invalid ownership binding generation")
	}
	result := OwnershipSnapshot{BaselineHash: compiler.hash, BindingGeneration: snapshot.Generation,
		CompiledAt: now, ExpiresAt: snapshot.ObservedAt.Add(lease), Addresses: []OwnedAddress{}}
	for _, record := range snapshot.Records {
		if err := ctx.Err(); err != nil {
			return Ownership{}, err
		}
		mac, err := CanonicalMAC(record.MAC)
		if err != nil || mac != record.MAC {
			return Ownership{}, errors.New("policy: invalid ownership MAC")
		}
		if compiler.bindingRole(record) == Unknown {
			continue
		}
		for _, address := range record.Addresses {
			if err := ctx.Err(); err != nil {
				return Ownership{}, err
			}
			if len(result.Addresses) >= compiler.baseline.MaximumTuples {
				return Ownership{}, errors.New("policy: ownership tuple capacity exceeded")
			}
			episode, err := json.Marshal([]any{record.MAC, record.NAS, record.Interface, record.VLAN,
				address.IP, record.AssociationID, address.OwnershipID})
			if err != nil {
				return Ownership{}, errors.New("policy: ownership episode encoding failed")
			}
			sum := sha256.Sum256(episode)
			result.Addresses = append(result.Addresses, OwnedAddress{
				MAC: mac, Interface: record.Interface, VLAN: record.VLAN, Address: address.IP,
				ExpiresAt: earliest(snapshot.ObservedAt.Add(lease), record.AssociatedAt.Add(lease),
					address.ObservedAt.Add(lease), address.ValidUntil), BindingRef: hex.EncodeToString(sum[:]),
			})
		}
	}
	slices.SortFunc(result.Addresses, func(left, right OwnedAddress) int {
		if compared := cmp.Compare(left.Interface, right.Interface); compared != 0 {
			return compared
		}
		if compared := cmp.Compare(left.MAC, right.MAC); compared != 0 {
			return compared
		}
		return left.Address.Compare(right.Address)
	})
	refs := make([]string, 0, len(result.Addresses))
	for _, address := range result.Addresses {
		refs = append(refs, address.BindingRef)
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		return Ownership{}, errors.New("policy: ownership fingerprint encoding failed")
	}
	sum := sha256.Sum256(encoded)
	result.Fingerprint = hex.EncodeToString(sum[:])
	if err := ctx.Err(); err != nil {
		return Ownership{}, err
	}
	return Ownership{data: &ownership{snapshot: result, anchor: anchor.tick}}, nil
}

// Snapshot returns a defensive copy without renewing any deadline.
func (evidence Ownership) Snapshot(ctx context.Context) (OwnershipSnapshot, error) {
	if ctx == nil || evidence.data == nil {
		return OwnershipSnapshot{}, errors.New("policy: missing ownership evidence or context")
	}
	if err := ctx.Err(); err != nil {
		return OwnershipSnapshot{}, err
	}
	result := evidence.data.snapshot
	result.Addresses = slices.Clone(result.Addresses)
	return result, nil
}

// Remaining clips current ownership by UTC expiry and time elapsed since the
// helper's original reading. A queue delay or clock rollback cannot renew it.
func (evidence Ownership) Remaining(index int, utc time.Time) (time.Duration, error) {
	if evidence.data == nil || utc.IsZero() || utc.Before(evidence.data.snapshot.CompiledAt) ||
		index < 0 || index >= len(evidence.data.snapshot.Addresses) {
		return 0, errors.New("policy: missing ownership evidence or invalid clock/index")
	}
	elapsed := time.Since(evidence.data.anchor)
	if elapsed < 0 {
		return 0, errors.New("policy: ownership elapsed clock regressed")
	}
	expires := evidence.data.snapshot.Addresses[index].ExpiresAt
	remaining := min(expires.Sub(utc), expires.Sub(evidence.data.snapshot.CompiledAt)-elapsed)
	if remaining <= 0 {
		return 0, errors.New("policy: ownership evidence expired")
	}
	return remaining, nil
}

// EpochRemaining limits a connection generation by the complete collection's
// original observation deadline and elapsed age, even if it has no addresses.
func (evidence Ownership) EpochRemaining(utc time.Time) (time.Duration, error) {
	if evidence.data == nil || evidence.data.snapshot.Epoch == 0 || utc.IsZero() ||
		utc.Before(evidence.data.snapshot.CompiledAt) {
		return 0, errors.New("policy: missing ownership epoch evidence or invalid clock")
	}
	elapsed := time.Since(evidence.data.anchor)
	if elapsed < 0 {
		return 0, errors.New("policy: ownership epoch elapsed clock regressed")
	}
	snapshot := evidence.data.snapshot
	remaining := min(snapshot.ExpiresAt.Sub(utc), snapshot.ExpiresAt.Sub(snapshot.CompiledAt)-elapsed)
	if remaining <= 0 {
		return 0, errors.New("policy: ownership epoch evidence expired")
	}
	return remaining, nil
}

// MarshalJSON refuses to persist or transport positive ownership evidence.
func (evidence Ownership) MarshalJSON() ([]byte, error) {
	return nil, errors.New("policy: ownership evidence cannot be serialized")
}

// UnmarshalJSON invalidates any old value and rejects restorable evidence.
func (evidence *Ownership) UnmarshalJSON(_ []byte) error {
	if evidence != nil {
		*evidence = Ownership{}
	}
	return errors.New("policy: ownership evidence cannot be deserialized")
}
