package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRunReaderArgumentsAndRedaction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, output string
		args         []string
		code, calls  int
	}{
		{name: "help", args: []string{"-help"}, output: "Collect fresh LDAPS", code: 0},
		{name: "version", args: []string{"-version"}, output: Version, code: 0},
		{name: "missing directory", code: 2},
		{name: "unknown provider stage", args: []string{"-config-directory", "/synthetic/private", "-check-provider", "other"}, code: 2},
		{name: "empty provider stage", args: []string{"-config-directory", "/synthetic/private", "-check-provider="}, code: 2},
		{name: "root directory", args: []string{"-config-directory", "/"}, code: 2},
		{name: "relative directory", args: []string{"-config-directory", "private"}, code: 2},
		{name: "unclean directory", args: []string{"-config-directory", "/synthetic/../private"}, code: 2},
		{name: "control character", args: []string{"-config-directory", "/synthetic/\nprivate"}, code: 2},
		{name: "oversize path", args: []string{"-config-directory", "/" + strings.Repeat("a", 4096)}, code: 2},
		{name: "unknown flag", args: []string{"-private-token", "synthetic-private-value"}, code: 2},
		{name: "positional argument", args: []string{"synthetic-private-value"}, code: 2},
		{name: "runtime failure", args: []string{"-config-directory", "/synthetic/private"}, code: 1, calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out, diagnostics bytes.Buffer
			var calls int
			run := func(ctx context.Context, directory string, writer io.Writer) error {
				calls++
				if ctx != t.Context() || directory != "/synthetic/private" || writer != &diagnostics {
					t.Error("reader wiring changed the context, path or diagnostic sink")
				}
				return errors.New("synthetic-private-value in an upstream failure")
			}
			code := runReader(t.Context(), test.args, CheckIO{Out: &out, Err: &diagnostics}, run)
			if code != test.code || calls != test.calls || test.output != "" && !strings.Contains(out.String(), test.output) {
				t.Fatal("unexpected reader command outcome")
			}
			if strings.Contains(diagnostics.String(), "synthetic-private-value") || test.code != 0 && out.Len() != 0 {
				t.Fatal("reader leaked raw errors or wrote runtime diagnostics to stdout")
			}
		})
	}
}

func TestRunReaderShutdownAndBrokenStreams(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	run := func(ctx context.Context, _ string, _ io.Writer) error { return ctx.Err() }
	args := []string{"-config-directory", "/synthetic/private"}
	if runReader(ctx, args, CheckIO{Out: io.Discard, Err: io.Discard}, run) != 0 {
		t.Fatal("orderly parent cancellation was not successful")
	}
	unrelatedCancellation := func(context.Context, string, io.Writer) error { return context.Canceled }
	if runReader(t.Context(), args, CheckIO{Out: io.Discard, Err: io.Discard}, unrelatedCancellation) != 1 {
		t.Fatal("internal cancellation was treated as orderly shutdown")
	}
	for _, args := range [][]string{{"-help"}, {"-version"}} {
		if runReader(t.Context(), args, CheckIO{Out: failedWriter{}, Err: io.Discard}, run) != 1 {
			t.Fatal("reader ignored failed stdout")
		}
	}
	if runReader(t.Context(), []string{}, CheckIO{Out: io.Discard, Err: failedWriter{}}, run) != 1 {
		t.Fatal("reader ignored failed diagnostics")
	}
	var missingContext context.Context
	if runReader(missingContext, args, CheckIO{Out: io.Discard, Err: io.Discard}, run) != 2 ||
		runReader(t.Context(), args, CheckIO{}, run) != 2 ||
		runReader(t.Context(), args, CheckIO{Out: io.Discard, Err: io.Discard}, nil) != 2 {
		t.Fatal("reader accepted missing dependencies")
	}
	if RunReader(t.Context(), []string{"-config-directory", "/synthetic/not-present"},
		CheckIO{Out: io.Discard, Err: io.Discard}) != 1 {
		t.Fatal("actual reader accepted missing configuration or privileged identity")
	}
}

func TestRunReaderOfflineCheck(t *testing.T) {
	t.Parallel()
	const config = `{"schema_version":1,"directory_url":"ldaps://offline.invalid:636","base_dn":"dc=example","custom_ca":true,"helper_socket":"/absent/private.sock"}`
	const bind = "cn=synthetic-private,ou=users,dc=example"
	for _, test := range []struct {
		name string
		args []string
		doc  string
		code int
	}{
		{name: "static configuration", args: []string{"-check-config"}, doc: config},
		{name: "valid lookup", args: []string{"-check-config", "-check-bind-dn", bind}, doc: config},
		{name: "wrong lookup", args: []string{"-check-config", "-check-bind-dn", "cn=synthetic-private,dc=other"}, doc: config, code: 1},
		{name: "empty lookup", args: []string{"-check-config", "-check-bind-dn="}, doc: config, code: 2},
		{name: "repeated lookup", args: []string{"-check-config", "-check-bind-dn", bind, "-check-bind-dn", bind}, doc: config, code: 2},
		{name: "invalid document", args: []string{"-check-config"}, doc: `{"private":"synthetic-private"}`, code: 1},
		{name: "trailing input", args: []string{"-check-config"}, doc: config + "{}", code: 1},
		{name: "mixed provider check", args: []string{"-check-provider", "unpaged", "-check-config"}, doc: config, code: 2},
		{name: "mixed directory", args: []string{"-check-config", "-config-directory", "/absent"}, doc: config, code: 2},
		{name: "mixed empty directory", args: []string{"-check-config", "-config-directory="}, doc: config, code: 2},
		{name: "mixed version", args: []string{"-version", "-check-config"}, doc: config, code: 2},
		{name: "orphan lookup", args: []string{"-config-directory", "/absent", "-check-bind-dn", bind}, code: 2},
		{name: "mixed runtime and version", args: []string{"-version", "-config-directory", "/absent"}, code: 2},
		{name: "extra path", args: []string{"-check-config", "synthetic-private"}, doc: config, code: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			streams := CheckIO{In: strings.NewReader(test.doc), Out: &out, Err: &diagnostics}
			code := runReader(t.Context(), test.args, streams, func(context.Context, string, io.Writer) error {
				t.Fatal("offline command invoked the runtime")
				return nil
			})
			if code != test.code {
				t.Fatalf("exit code %d, want %d", code, test.code)
			}
			if code == 0 && (out.String() != "{\"result\":\"pass\"}\n" || diagnostics.Len() != 0) ||
				code != 0 && (out.Len() != 0 || diagnostics.Len() == 0 || strings.Contains(diagnostics.String(), "synthetic-private")) {
				t.Fatal("unexpected output or disclosure")
			}
		})
	}
}
