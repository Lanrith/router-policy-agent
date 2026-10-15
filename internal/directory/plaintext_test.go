package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestPlaintextRequiresExplicitBoundedPrivateTransport(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*Config)
		valid  bool
	}{
		{name: "explicit private ipv4", valid: true},
		{name: "explicit private ipv6", change: func(c *Config) { c.URL = "ldap://[fdca:1a2b::10]:389" }, valid: true},
		{name: "loopback", change: func(c *Config) { c.URL = "ldap://127.0.0.1:389" }, valid: true},
		{name: "no exception", change: func(c *Config) { c.PlaintextUntil = time.Time{} }},
		{name: "expired", change: func(c *Config) { c.PlaintextUntil = time.Now().Add(-time.Second) }},
		{name: "too long", change: func(c *Config) { c.PlaintextUntil = time.Now().Add(25 * time.Hour) }},
		{name: "dns hostname", change: func(c *Config) { c.URL = "ldap://directory.example.test:389" }},
		{name: "public ipv4", change: func(c *Config) { c.URL = "ldap://8.8.8.8:389" }},
		{name: "public ipv6", change: func(c *Config) { c.URL = "ldap://[2606:4700:4700::1111]:389" }},
		{name: "wrong scheme", change: func(c *Config) { c.URL = "http://10.77.23.10:389" }},
		{name: "mapped ipv6", change: func(c *Config) { c.URL = "ldap://[::ffff:10.77.23.10]:389" }},
		{name: "link-local ipv6", change: func(c *Config) { c.URL = "ldap://[fe80::10]:389" }},
		{name: "scoped ipv6", change: func(c *Config) { c.URL = "ldap://[fdca:1a2b::10%25eth0]:389" }},
		{name: "conflicting ca", change: func(c *Config) { c.RootCAs = x509.NewCertPool() }},
		{name: "tls with exception", change: func(c *Config) { c.URL = "ldaps://directory.example.test:636" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := fixtureConfig()
			config.URL = "ldap://10.77.23.10:389"
			config.PlaintextUntil = time.Now().UTC().Add(time.Hour)
			if test.change != nil {
				test.change(&config)
			}
			reader, err := New(config, func(context.Context) (Credentials, error) { return Credentials{}, nil })
			if (err == nil) != test.valid || (reader != nil) != test.valid {
				t.Fatal("plaintext exception boundary differs")
			}
		})
	}
}

func TestPlaintextExpiryRejectsBeforeCredentials(t *testing.T) {
	t.Parallel()
	config := fixtureConfig()
	config.URL = "ldap://127.0.0.1:389"
	config.PlaintextUntil = time.Now().UTC().Add(time.Hour)
	calls := 0
	reader, err := New(config, func(context.Context) (Credentials, error) { calls++; return Credentials{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	reader.now = func() time.Time { return config.PlaintextUntil }
	if snapshot, err := reader.Collect(t.Context()); !errors.Is(err, ErrRead) || snapshot.Complete || calls != 0 {
		t.Fatal("expired exception fetched credentials or returned a snapshot")
	}
}
