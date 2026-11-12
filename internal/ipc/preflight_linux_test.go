package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestServerPreflightIsReadOnlyAndRejectsUnsafeListeners(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "preflight.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	calls := 0
	server, err := NewServer(ServerOptions{ReaderUID: 1000, Timeout: time.Second}, func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
		calls++
		return Receipt{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.CheckListener(t.Context(), listener); err != nil || calls != 0 {
		t.Fatal("safe preflight failed or invoked a processor", err)
	}
	if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- Deliberately unsafe fixture must be rejected.
		t.Fatal(err)
	}
	if err := server.CheckListener(t.Context(), listener); err == nil || calls != 0 {
		t.Fatal("unsafe socket was accepted or processed")
	}
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal("preflight consumed or closed caller-owned listener", err)
	}
	if err := server.CheckListener(t.Context(), &net.UnixListener{}); err == nil {
		t.Fatal("zero-value listener was accepted")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.CheckListener(t.Context(), listener); err == nil {
		t.Fatal("closed listener was accepted")
	}
}
