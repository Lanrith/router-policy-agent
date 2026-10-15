//go:build integration

package directory

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestExplicitPlaintextCollectsOriginalEntriesWithoutTLSFallback(t *testing.T) {
	t.Parallel()
	server := startConnectionFixture(t, func(_ context.Context, connection net.Conn) error {
		id, operation, _, err := readWire(connection)
		if err != nil {
			return err
		}
		if operation.Tag != 0 || len(operation.Children) != 3 {
			return errors.New("synthetic plaintext bind missing")
		}
		if err := sendWire(connection, wireResult(id, 1, ldap.LDAPResultSuccess)); err != nil {
			return err
		}
		groups, users := fixtureEntries()
		for index := range 2 {
			id, operation, _, err := readWire(connection)
			if err != nil {
				return err
			}
			if operation.Tag != 3 {
				return errors.New("synthetic plaintext search missing")
			}
			entry := groups[0]
			if index == 1 {
				entry = users[0]
			}
			if err := sendWire(connection, wireEntry(id, entry)); err != nil {
				return err
			}
			if err := sendWire(connection, wireResult(id, 5, ldap.LDAPResultSuccess, ldap.NewControlPaging(2))); err != nil {
				return err
			}
		}
		var one [1]byte
		if _, err := connection.Read(one[:]); !errors.Is(err, io.EOF) {
			return errors.New("plaintext client failed to close")
		}
		return nil
	})
	config := fixtureConfig()
	config.URL = "ldap://" + server.listener.Addr().String()
	config.PlaintextUntil = time.Now().UTC().Add(time.Hour)
	reader, err := New(config, func(context.Context) (Credentials, error) {
		return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-test-only"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.Collect(t.Context())
	if err != nil || !snapshot.Complete || len(snapshot.Groups) != 1 || len(snapshot.Devices) != 1 {
		t.Fatal("explicit plaintext collection failed or returned partial data")
	}
}

func TestPlaintextDeadlineDuringBindReturnsNoSnapshot(t *testing.T) {
	t.Parallel()
	server := startConnectionFixture(t, func(_ context.Context, connection net.Conn) error {
		if _, _, _, err := readWire(connection); err != nil {
			return err
		}
		// Withhold the bind response. The transport exception must interrupt
		// the real socket, rather than waiting for the longer read timeout.
		var one [1]byte
		if _, err := connection.Read(one[:]); !errors.Is(err, io.EOF) {
			return errors.New("expired plaintext connection remained open")
		}
		return nil
	})
	config := fixtureConfig()
	config.URL = "ldap://" + server.listener.Addr().String()
	config.Timeout = 5 * time.Second
	config.PlaintextUntil = time.Now().UTC().Add(500 * time.Millisecond)
	reader, err := New(config, func(context.Context) (Credentials, error) {
		return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-test-only"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	snapshot, err := reader.Collect(t.Context())
	if !errors.Is(err, ErrRead) || snapshot.Complete || time.Since(started) > 3*time.Second {
		t.Fatal("expired plaintext bind returned data or outlived its bounded exception")
	}
}
