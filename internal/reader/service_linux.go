package reader

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"

	"github.com/lanrith/router-policy-agent/internal/directory"
	"github.com/lanrith/router-policy-agent/internal/hostfs"
	"github.com/lanrith/router-policy-agent/internal/ipc"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Run collects over the checked directory transport and submits fresh snapshots to the
// root helper. The process must have one non-root real/effective UID. It opens
// a private reader-owned directory, reads reader.json and optional ca.pem once,
// and reopens credentials.json on every collection to permit atomic rotation.
// No firewall, binding, state, shell or directory-write operation is available.
// Cancellation joins collection/submission I/O; diagnostics are fixed JSON
// outcomes on the supplied writer. Source/enforcement qualification is separate.
func Run(ctx context.Context, configDirectory string, diagnostics io.Writer) error {
	return run(ctx, configDirectory, diagnostics, "")
}

// CheckProvider qualifies one stage against the configured directory and helper.
// It obtains a new complete snapshot and requires a positive applied receipt for
// single-page and multi-page stages, or an applied zero-grant receipt for withdrawn.
func CheckProvider(ctx context.Context, configDirectory string, output io.Writer, stage string) error {
	switch stage {
	case "single-page", "multi-page", "withdrawn", "unpaged", "unpaged-withdrawn":
		return run(ctx, configDirectory, output, stage)
	default:
		return errRuntime
	}
}

func run(ctx context.Context, configDirectory string, diagnostics io.Writer, stage string) (result error) {
	if ctx == nil || diagnostics == nil || !privatePath(configDirectory, 4096) {
		return errRuntime
	}
	uid := os.Geteuid()
	if uid <= 0 || uint64(uid) > math.MaxUint32 {
		return errRuntime
	}
	if os.Getuid() != uid {
		return errRuntime
	}
	owner := uint32(uid)
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: configDirectory, OwnerUID: owner, Private: true})
	if err != nil {
		return errRuntime
	}
	defer func() {
		if err := root.Close(); err != nil {
			result = errRuntime
		}
	}()
	collector, socket, err := loadReader(ctx, root, owner)
	if err != nil {
		return errRuntime
	}
	submit := func(ctx context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
		return ipc.Submit(ctx, ipc.ClientOptions{
			Socket: socket, ServerUID: 0, Timeout: ipc.MaximumSubmissionTimeout,
		}, snapshot)
	}
	if stage != "" {
		collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
			if stage == "unpaged" || stage == "unpaged-withdrawn" {
				return collector.CheckUnpaged(ctx)
			}
			return collector.CheckProvider(ctx, stage != "single-page")
		}
		return checkProviderReceipt(ctx, collect, submit, diagnostics, stage == "withdrawn" || stage == "unpaged-withdrawn")
	}
	if err := runLoop(ctx, collector.Collect, submit, diagnostics); err != nil {
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return ctx.Err()
		}
		return errRuntime
	}
	return nil
}

func checkProviderReceipt(ctx context.Context, collect collectFunc, submit submitFunc, output io.Writer, withdrawn bool) error {
	attempt, err := runCycle(ctx, collect, submit)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(attempt); err != nil {
		return errRuntime
	}
	if attempt.Outcome != "applied" || (attempt.GrantCount == 0) != withdrawn {
		return errRuntime
	}
	return nil
}

// loadReader checks static configuration without connecting to the directory.
// The caller owns the checked root and keeps it open for credential reloads.
func loadReader(ctx context.Context, root *os.Root, owner uint32) (*directory.Reader, string, error) {
	data, err := readPrivate(ctx, root, owner, "reader.json", maximumConfig)
	if err != nil {
		return nil, "", errRuntime
	}
	configuration, err := decodeConfig(data)
	if err != nil {
		return nil, "", errRuntime
	}
	options := configuration.directoryConfig()
	if configuration.CustomCA {
		options.RootCAs, err = readCA(ctx, root, owner)
		if err != nil {
			return nil, "", errRuntime
		}
	}
	collector, err := directory.New(options, func(ctx context.Context) (directory.Credentials, error) {
		return readCredentials(ctx, root, owner)
	})
	if err != nil {
		return nil, "", errRuntime
	}
	return collector, configuration.HelperSocket, nil
}
