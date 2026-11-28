package radius

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"syscall"
	"time"

	"github.com/lanrith/router-policy-agent/internal/binding"
)

const workerDirectory = "/run/lanrith-policy-evidence"

var (
	errAccounting = errors.New("radius: accounting unavailable")
	errLease      = errors.New("radius: lease source unavailable")
	errPlacement  = errors.New("radius: placement unavailable")
	errBudget     = errors.New("radius: collection budget exceeded")
	errChanged    = errors.New("radius: accounting changed")
)

func reasonCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, errBudget):
		return "budget"
	case errors.Is(err, errGap), errors.Is(err, errAccounting):
		return "accounting"
	case errors.Is(err, errLease):
		return "lease"
	case errors.Is(err, errPlacement):
		return "placement"
	case errors.Is(err, errChanged):
		return "changed"
	default:
		return "collector"
	}
}

// ServeBindingEvidence reads a single bounded request on a root-authenticated
// socket. The worker returns a candidate snapshot; it has no access to the
// helper's enrollment, IPC sockets or published bindings directory.
func ServeBindingEvidence(ctx context.Context, input *os.File, output io.Writer) error {
	if ctx == nil || input == nil || output == nil || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		return errRuntime
	}
	fd, err := fileDescriptor(input)
	if err != nil {
		return errRuntime
	}
	peer, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || peer.Uid != 0 {
		return errRuntime
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	data, err := io.ReadAll(io.LimitReader(input, maximumRuntimeConfig+1))
	if err != nil {
		return errRuntime
	}
	snapshot, err := collectWorker(ctx, data)
	response := struct {
		Snapshot *binding.Snapshot `json:"snapshot,omitempty"`
		Reason   string            `json:"reason,omitempty"`
	}{}
	if err != nil {
		response.Reason = reasonCode(err)
	} else {
		response.Snapshot = &snapshot
	}
	return json.NewEncoder(output).Encode(response)
}

func effectiveOwner() (uint32, error) {
	uid := os.Geteuid()
	if uid < 0 || uid > math.MaxUint32 {
		return 0, errors.New("radius: invalid worker user ID")
	}
	return uint32(uid), nil
}

func collectWorker(ctx context.Context, data []byte) (binding.Snapshot, error) {
	config, err := decodeBindingsRuntimeConfig(data)
	if err != nil {
		return binding.Snapshot{}, err
	}
	options, err := config.options()
	if err != nil {
		return binding.Snapshot{}, err
	}
	options.managedMACs = config.ManagedMACs
	owner, err := effectiveOwner()
	if err != nil {
		return binding.Snapshot{}, err
	}
	collection, err := withOwnedExport(ctx, workerDirectory, owner, func(root *os.Root) (Collection, error) {
		return collectBindingSources(ctx, root, owner, options)
	})
	if err != nil {
		return binding.Snapshot{}, err
	}
	publisher := BindingPublisherOptions{Collector: options, ManagedMACs: config.ManagedMACs, Directory: config.OutputDirectory}
	return collectedBindings(collection, publisher, time.Now().UTC())
}

func collectBindingSources(ctx context.Context, root *os.Root, owner uint32, options CollectorOptions) (Collection, error) {
	boot, err := currentBootID()
	if err != nil {
		return Collection{}, err
	}
	scope, err := json.Marshal(options)
	if err != nil {
		return Collection{}, err
	}
	scopeID := digest("binding-worker-v1", boot, string(scope))
	cp, loadErr := readCheckpoint(ctx, root, owner, scopeID)
	if loadErr != nil && !errors.Is(loadErr, errGap) {
		return Collection{}, loadErr
	}
	wall := time.Now().UTC()
	mono, err := monotonicNow()
	if err != nil {
		return Collection{}, err
	}
	stream := journalCheckpoint{root: root, owner: owner, cp: cp, offset: wall.Add(-mono.Sub(time.Unix(0, 0))), options: options.Journal}
	if errors.Is(loadErr, errGap) {
		stream.cp = newCheckpoint(scopeID)
		return Collection{}, stream.reset(ctx)
	}
	return collectNative(ctx, options, stream.capture)
}
