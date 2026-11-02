package firewall

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifyReadyUsesOnlyTheSupervisorSocket(t *testing.T) {
	directory, err := os.MkdirTemp("", "rpa-notify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(directory, "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notifyReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 128)
	count, _, err := listener.ReadFromUnix(data)
	if err != nil || string(data[:count]) != "READY=1\n" {
		t.Fatal("unexpected supervisor notification", err)
	}
}

func TestNotifyReadyRejectsInvalidOrCanceledInputs(t *testing.T) {
	for _, path := range []string{"relative.sock", "/run/../tmp/socket", "@", "/run/socket\n"} {
		t.Run(path, func(t *testing.T) {
			t.Setenv("NOTIFY_SOCKET", path)
			if err := notifyReady(t.Context()); err == nil {
				t.Fatal("invalid notification address accepted")
			}
		})
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifyReady(t.Context()); err != nil {
		t.Fatal("standalone helper acquired a supervisor dependency", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := notifyReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled startup declared readiness", err)
	}
	if err := notifyReady(nil); err == nil { //nolint:staticcheck // Deliberately test the invalid API boundary.
		t.Fatal("nil readiness context accepted")
	}
}
