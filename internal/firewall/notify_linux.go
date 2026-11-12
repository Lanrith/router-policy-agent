package firewall

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// notifyReady uses only the supervisor's notification address. With no notify
// socket the existing standalone interface is retained. systemd authenticates
// the sender PID; this fixed datagram carries no caller data or policy authority.
func notifyReady(ctx context.Context) (result error) {
	if ctx == nil {
		return errors.New("firewall: missing readiness context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	filesystem := filepath.IsAbs(path) && filepath.Clean(path) == path
	abstract := strings.HasPrefix(path, "@") && len(path) > 1
	if (!filesystem && !abstract) || len(path) > 107 || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("firewall: invalid supervisor notification address")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unixgram", path)
	if err != nil {
		return errors.New("firewall: supervisor notification unavailable")
	}
	defer func() { result = errors.Join(result, connection.Close()) }()
	deadline, _ := bounded.Deadline() // WithTimeout above always supplies a deadline.
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	const message = "READY=1\n"
	written, err := connection.Write([]byte(message))
	if err != nil || written != len(message) {
		return errors.New("firewall: supervisor readiness notification failed")
	}
	return nil
}
