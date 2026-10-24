package hostfs

import (
	"os"
	"testing"
)

func TestCheckReadOnlyFileAllowsReadButNeverWritePermissions(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/runtime.json"
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil { // #nosec G306 -- the test must begin with a world-readable, non-writable file.
		t.Fatal(err)
	}
	file, err := os.Open(path) // #nosec G304 -- path is beneath t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := CheckReadOnlyFile(file, uint32(os.Getuid()), 16); err != nil { // #nosec G115 -- kernel UIDs are unsigned.
		t.Fatal("root-owned read-only runtime evidence rejected", err)
	}
	if err := os.Chmod(path, 0o664); err != nil { // #nosec G302 -- the test deliberately introduces unsafe group write access.
		t.Fatal(err)
	}
	if err := CheckReadOnlyFile(file, uint32(os.Getuid()), 16); err == nil { // #nosec G115 -- kernel UIDs are unsigned.
		t.Fatal("group-writable runtime evidence accepted")
	}
}
