package tunpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lanrith/router-policy-agent/internal/hostfs"
)

// Executor owns checked executable descriptors for fixed nft and conntrack
// operations. The service must join publishers before closing these resources.
type Executor struct{ nft, conntrack *os.File }

// OpenExecutor pins root-owned ELF binaries without executing or changing state.
func OpenExecutor(ctx context.Context, nft, conntrack string) (*Executor, error) {
	n, err := openExecutable(ctx, nft)
	if err != nil {
		return nil, err
	}
	c, err := openExecutable(ctx, conntrack)
	if err != nil {
		return nil, errors.Join(err, n.Close())
	}
	return &Executor{nft: n, conntrack: c}, nil
}

func openExecutable(ctx context.Context, path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("tunpolicy: invalid executable path")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: filepath.Dir(path), OwnerUID: 0})
	if err != nil {
		return nil, err
	}
	file, openErr := hostfs.OpenExecutable(ctx, root, filepath.Base(path), 0)
	if err := errors.Join(openErr, root.Close()); err != nil {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		return nil, err
	}
	return file, nil
}

// Close releases descriptors after the serial publisher has stopped.
func (e *Executor) Close() error { return errors.Join(e.nft.Close(), e.conntrack.Close()) }

// Commit writes one atomically applied set-data batch, never an access program.
func (e *Executor) Commit(ctx context.Context, batch Batch) error {
	if batch.program == "" || len(batch.program) > 16<<20 {
		return errors.New("tunpolicy: missing or oversized data batch")
	}
	_, _, err := run(ctx, e.nft, batch.program, "-f", "-")
	return err
}

var emptyDelete = regexp.MustCompile(`^conntrack v[0-9]+(?:\.[0-9]+)* \(conntrack-tools\): 0 flow entries have been deleted\.\n$`)

// Invalidate deletes labelled identity connections in one scan per family.
// Startup additionally deletes the fixed policy marks. The cleanup label has
// no access meaning; neither unrelated entries nor conntrack zones are touched.
func (e *Executor) Invalidate(ctx context.Context, scope CleanupScope) error {
	if ctx == nil || (scope != IdentityConnections && scope != PolicyConnections) {
		return errors.New("tunpolicy: invalid cleanup request")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// conntrack-tools 1.4.8 batch mode crashes on label filters. Use two fixed
	// invocations, independent of the number of current endpoints. A successful
	// empty delete exits 1; accept only its exact zero-result diagnostic.
	for _, family := range []string{"ipv4", "ipv6"} {
		output, diagnostic, err := run(ctx, e.conntrack, "", "-D", "-f", family, "--label", "lanrith-identity")
		if err != nil {
			var failure *exec.ExitError
			empty := errors.As(err, &failure) && failure.ExitCode() == 1 && output == "" &&
				emptyDelete.MatchString(diagnostic)
			if !empty || ctx.Err() != nil {
				return err
			}
		}
	}
	if scope == IdentityConnections {
		return nil
	}
	var commands strings.Builder
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, mark := range []string{"0x4c520001", "0x4c520002", "0x4c520003"} {
			fmt.Fprintf(&commands, "-D -f %s --mark %s\n", family, mark)
		}
	}
	_, _, err := run(ctx, e.conntrack, commands.String(), "-R", "-")
	return err
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 16<<20 {
		return 0, errors.New("tunpolicy: command output exceeds bound")
	}
	return b.Buffer.Write(data)
}

func run(ctx context.Context, executable *os.File, input string, args ...string) (string, string, error) {
	if ctx == nil || executable == nil {
		return "", "", errors.New("tunpolicy: missing command owner")
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/proc/self/fd/3", args...) //nolint:gosec // Pinned root-owned ELF; arguments come only from fixed operations and validated addresses.
	command.ExtraFiles = []*os.File{executable}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.Stdin = strings.NewReader(input)
	command.WaitDelay = 250 * time.Millisecond
	var output, diagnostic limitedBuffer
	command.Stdout, command.Stderr = &output, &diagnostic
	err := command.Run()
	if err != nil {
		err = fmt.Errorf("tunpolicy: fixed command failed: %w", err)
	}
	return output.String(), diagnostic.String(), errors.Join(err, bounded.Err())
}

var _ io.Writer = (*limitedBuffer)(nil)

// Inspect compares the current program with the independently built digest.
func (e *Executor) Inspect(ctx context.Context, expected string) error {
	_, err := e.listing(ctx, expected)
	return err
}

func (e *Executor) listing(ctx context.Context, expected string) ([]byte, error) {
	output, _, err := run(ctx, e.nft, "", "-j", "-n", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	actual, err := ProgramDigest([]byte(output))
	if err != nil {
		return nil, err
	}
	if actual != expected {
		return nil, errors.New("tunpolicy: installed program differs from image")
	}
	return []byte(output), ctx.Err()
}

// Observe verifies the pinned program and counts its current delegated tuples
// from the same kernel listing. This read-only count cannot renew permission.
func (e *Executor) Observe(ctx context.Context, expected string) (int, error) {
	output, err := e.listing(ctx, expected)
	if err != nil {
		return 0, err
	}
	var listing struct {
		Objects []struct {
			Set *struct {
				Family, Table, Name string
				Elements            json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return 0, err
	}
	count := 0
	for _, object := range listing.Objects {
		set := object.Set
		if set == nil || set.Family != "inet" || set.Table != "lanrith" {
			continue
		}
		switch set.Name {
		case "tp_grants4", "tp_grants6", "tp_echo4", "tp_echo6":
			var elements []json.RawMessage
			if len(set.Elements) != 0 {
				if err := json.Unmarshal(set.Elements, &elements); err != nil {
					return 0, err
				}
			}
			if len(elements) > maximumElements {
				return 0, errors.New("tunpolicy: kernel tuple count exceeds capacity")
			}
			count += len(elements)
		}
	}
	return count, ctx.Err()
}
