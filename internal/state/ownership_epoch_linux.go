package state

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/lanrith/router-policy-agent/internal/hostfs"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

const ownershipEpochFile = "ownership-epoch.json"

type ownershipEpoch struct {
	SchemaVersion int    `json:"schema_version"`
	Last          uint32 `json:"last"`
}

// InitializeOwnershipEpoch is an explicit first-install operation, never a
// runtime repair. The separate deny-only counter leaves the existing durable
// document unchanged. Migration of an existing
// installation must separately qualify counter initialization and conntrack
// retirement; neither operation is implied by loading existing policy history.
func (s *Store) InitializeOwnershipEpoch(ctx context.Context) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if _, err := s.load(ctx); err != nil {
		return err
	}
	if _, err := s.loadOwnershipEpoch(ctx); !errors.Is(err, ErrUninitialized) {
		if err != nil {
			return err
		}
		return errors.New("state: ownership sequence already initialized")
	}
	return s.writeOwnershipEpoch(ctx, 0)
}

// AdvanceOwnershipEpoch durably consumes a nonzero connection generation before
// the helper can publish it. Restarts and changed ownership episodes cannot
// reuse a prior value. Exhaustion, missing/corrupt state and unsafe metadata
// fail closed. This counter contains no current ownership or access grants.
func (s *Store) AdvanceOwnershipEpoch(ctx context.Context) (uint32, error) {
	if err := s.acquire(ctx); err != nil {
		return 0, err
	}
	defer s.release()
	if _, err := s.load(ctx); err != nil {
		return 0, err
	}
	previous, err := s.loadOwnershipEpoch(ctx)
	if err != nil {
		return 0, err
	}
	if previous >= policy.MaximumOwnershipEpoch {
		return 0, errors.New("state: ownership sequence exhausted; explicit migration is required")
	}
	next := previous + 1
	if err := s.writeOwnershipEpoch(ctx, next); err != nil {
		return 0, err
	}
	return next, nil
}

func (s *Store) loadOwnershipEpoch(ctx context.Context) (uint32, error) {
	file, err := hostfs.OpenRegular(ctx, s.root, hostfs.FileOptions{
		Name: ownershipEpochFile, OwnerUID: s.owner, MaximumSize: 128,
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrUninitialized
	}
	if err != nil {
		return 0, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 129))
	if err := errors.Join(readErr, file.Close(), ctx.Err()); err != nil {
		return 0, err
	}
	if err := strictjson.Object(data, []string{"schema_version", "last"}, nil, 128); err != nil {
		return 0, err
	}
	var document ownershipEpoch
	if err := strictjson.Decode(data, &document, 128); err != nil {
		return 0, err
	}
	if document.SchemaVersion != 1 {
		return 0, errors.New("state: unsupported ownership sequence")
	}
	return document.Last, nil
}

func (s *Store) writeOwnershipEpoch(ctx context.Context, last uint32) error {
	data, err := json.Marshal(ownershipEpoch{SchemaVersion: 1, Last: last})
	if err != nil {
		return err
	}
	return s.writeFile(ctx, ownershipEpochFile, data)
}
