package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
)

// AuthorizationObservation is a diagnostic comparison with saved deny-only
// state. It is neither authorization nor restorable physical/directory evidence.
type AuthorizationObservation struct {
	DirectoryObservedAt time.Time
	DirectorySHA256     string
	LedgerSHA256        string
}

// DirectoryFingerprint retains the existing saved-observation byte digest.
// It cannot prove completeness/authentication or create a grant. The 16 MiB
// ceiling is the existing persistent state/observation publication bound.
func DirectoryFingerprint(snapshot DirectorySnapshot) (string, error) {
	return authorizationFingerprint(snapshot)
}

// LedgerFingerprint compares a validated ledger without making its observation
// or temporary deadlines renewable. Its digest carries no permission.
func LedgerFingerprint(ledger Ledger) (string, error) {
	owned, err := CloneLedger(ledger)
	if err != nil {
		return "", err
	}
	return authorizationFingerprint(owned)
}

func authorizationFingerprint(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 16<<20 {
		return "", errors.New("policy: authorization provenance exceeds state bounds")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func authorizationBindingReferences(ctx context.Context, candidate Candidate, snapshot binding.Snapshot) ([]string, error) {
	records := map[string]binding.Record{}
	for _, record := range snapshot.Records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		records[record.MAC] = record
	}
	type identity struct {
		mac     string
		address netip.Addr
	}
	known := map[identity]string{}
	refs := make([]string, len(candidate.Grants))
	for index, grant := range candidate.Grants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record := records[grant.MAC]
		if record.Interface != grant.Interface || record.VLAN != grant.VLAN {
			return nil, errors.New("policy: authorization lost its original placement")
		}
		key := identity{grant.MAC, grant.Device.Real}
		if reference := known[key]; reference != "" {
			refs[index] = reference
			continue
		}
		for _, address := range record.Addresses {
			if address.IP != grant.Device.Real {
				continue
			}
			if refs[index] != "" {
				return nil, errors.New("policy: ambiguous authorization ownership episode")
			}
			reference, err := ownershipBindingReference(record, address)
			if err != nil {
				return nil, err
			}
			refs[index] = reference
		}
		if refs[index] == "" {
			return nil, errors.New("policy: authorization lost its original address episode")
		}
		known[key] = refs[index]
	}
	return refs, ctx.Err()
}

// BindingReference identifies the original physical episode for this exact
// immutable grant. A current owner with the same MAC/IP but another association
// must not inherit it. The reference alone cannot authorize any packet.
func (authorization Authorization) BindingReference(ctx context.Context, index int) (string, error) {
	if ctx == nil || authorization.data == nil || index < 0 || index >= len(authorization.data.bindings) || len(authorization.data.bindings) != len(authorization.data.candidate.Grants) {
		return "", errors.New("policy: missing authorization binding origin")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return authorization.data.bindings[index], nil
}

// Observation returns comparison fingerprints from the original compiler
// result. It never reconstructs authorization from saved state or a listing.
func (authorization Authorization) Observation(ctx context.Context) (AuthorizationObservation, error) {
	if ctx == nil || authorization.data == nil {
		return AuthorizationObservation{}, errors.New("policy: missing original authorization observation")
	}
	if err := ctx.Err(); err != nil {
		return AuthorizationObservation{}, err
	}
	return authorization.data.observation, nil
}
