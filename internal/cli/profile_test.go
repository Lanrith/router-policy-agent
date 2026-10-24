package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func profileListingFixture(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ruleset.json")
	data := map[string]any{"nftables": []any{
		map[string]any{"metainfo": map[string]any{
			"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1,
		}},
		map[string]any{"table": map[string]any{"family": "inet", "name": "floor", "handle": 1}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": "floor", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop", "handle": 2}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": "floor", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop", "handle": 3}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": "floor", "name": "output", "type": "filter", "hook": "output", "prio": 0, "policy": "drop", "handle": 4}},
	}}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunProfileWritesOnlyDerivedArtifacts(t *testing.T) {
	t.Parallel()
	output := t.TempDir()
	var stdout, diagnostics bytes.Buffer
	code := RunProfile(t.Context(), []string{
		"-baseline", "../../examples/baseline.json",
		"-ruleset", profileListingFixture(t),
		"-output-directory", output,
	}, CheckIO{Out: &stdout, Err: &diagnostics})
	if code != 0 || stdout.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("exit %d: stdout=%s stderr=%s", code, &stdout, &diagnostics)
	}
	for _, name := range []string{profileFilename, guardsFilename, metadataFilename} {
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
			t.Fatalf("invalid derived artifact %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(output, "baseline.json")); !os.IsNotExist(err) {
		t.Fatal("build-only baseline was copied into the output directory")
	}
	// Exact outputs are immutable: rerunning cannot replace their pins.
	if code := RunProfile(t.Context(), []string{
		"-baseline", "../../examples/baseline.json", "-ruleset", profileListingFixture(t),
		"-output-directory", output,
	}, CheckIO{Out: &stdout, Err: &diagnostics}); code != 1 {
		t.Fatal("existing immutable artifacts were overwritten")
	}
}

func TestRunProfileUsageAndFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		args   []string
		code   int
		output string
	}{
		{name: "help", args: []string{"-help"}, code: 0, output: "source router YAML is not accepted"},
		{name: "version", args: []string{"-version"}, code: 0, output: Version},
		{name: "missing", args: nil, code: 2},
		{name: "positional", args: []string{"unexpected"}, code: 2},
		{name: "missing baseline", args: []string{"-baseline", "/does/not/exist", "-ruleset", "/does/not/exist", "-output-directory", t.TempDir()}, code: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out, diagnostics bytes.Buffer
			code := RunProfile(t.Context(), test.args, CheckIO{Out: &out, Err: &diagnostics})
			if code != test.code || test.output != "" && !strings.Contains(out.String(), test.output) {
				t.Fatalf("code %d; stdout=%s stderr=%s", code, &out, &diagnostics)
			}
			if code != 0 && out.Len() != 0 {
				t.Fatal("failure diagnostic corrupted stdout")
			}
		})
	}
}
