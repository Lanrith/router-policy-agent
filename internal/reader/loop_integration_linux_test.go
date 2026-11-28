//go:build integration && linux

package reader

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/ipc"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// Exercise both deployed request limits over a real authenticated Unix socket.
// Collection latency and backend work are controlled independently. Delaying
// accept consumes the client's delivery allowance before the helper starts.
func TestReaderReceivesDelayedHelperReceipt(t *testing.T) {
	for _, test := range []struct {
		name                                        string
		devices                                     int
		collection, queue, processing, requestLimit time.Duration
	}{
		{"ordinary", 64, 7 * time.Second, 0, 4 * time.Second, 5 * time.Second},
		{"translation", 4096, 5 * time.Second, 2 * time.Second, 8500 * time.Millisecond, 10 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			socket := filepath.Join(t.TempDir(), "helper.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			// #nosec G302 -- Group write is required by the authenticated Unix socket contract.
			if err := os.Chmod(socket, 0o660); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Geteuid()) //nolint:gosec // Linux effective UIDs fit in uint32.
			type commit struct {
				observed, entered, completed time.Time
				devices                      int
			}
			committed := make(chan commit, 1)
			server, err := ipc.NewServer(ipc.ServerOptions{ReaderUID: uid, Timeout: test.requestLimit},
				func(ctx context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
					entered := time.Now()
					select {
					case <-ctx.Done():
						return ipc.Receipt{}, ctx.Err()
					case <-time.After(test.processing):
					}
					committed <- commit{snapshot.ObservedAt, entered, time.Now(), len(snapshot.Devices)}
					return testReceipt(ipc.StatusApplied), nil
				})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			handoff := make(chan struct{})
			stopped := make(chan error, 1)
			go func() {
				select {
				case <-ctx.Done():
				case <-handoff:
					time.Sleep(test.queue)
				}
				stopped <- server.Serve(ctx, listener)
			}()
			t.Cleanup(func() {
				cancel()
				if err := <-stopped; !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
			})

			var observed, submitted time.Time
			collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
				observed = time.Now()
				snapshot := testSnapshot(observed.UTC())
				for i := range test.devices {
					snapshot.Devices = append(snapshot.Devices, policy.Device{
						ID: fmt.Sprintf("device-%04d", i), MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256),
						Active: true, GroupIDs: []string{},
					})
				}
				time.Sleep(test.collection)
				return snapshot, ctx.Err()
			}
			submit := func(ctx context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
				submitted = time.Now()
				close(handoff)
				return ipc.Submit(ctx, ipc.ClientOptions{Socket: socket, ServerUID: uid, Timeout: ipc.MaximumSubmissionTimeout}, snapshot)
			}
			outcome, err := runCycle(ctx, collect, submit)
			received := time.Now()
			if err != nil || outcome.Outcome != "applied" || outcome.GrantCount != 2 {
				t.Fatalf("delayed helper receipt: %#v, %v", outcome, err)
			}
			result := <-committed
			if !observed.Equal(result.observed) || result.devices != test.devices || received.Sub(submitted) > ipc.MaximumSubmissionTimeout {
				t.Fatal("evidence or submission deadline changed")
			}
			t.Logf("devices=%d collection=%s submit_to_processor=%s processor=%s return=%s receipt=%s grants=%d",
				result.devices, submitted.Sub(observed), result.entered.Sub(submitted),
				result.completed.Sub(result.entered), received.Sub(result.completed), outcome.Outcome, outcome.GrantCount)
		})
	}
}
