package state

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/policy"
)

func TestOwnershipSequenceIsExplicitDurableAndDoesNotRewriteHistory(t *testing.T) {
	t.Parallel()
	options := storeOptions(t)
	store := openStore(t, options)
	if err := store.InitializeOwnershipEpoch(t.Context()); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("sequence initialization without history: %v", err)
	}
	if err := store.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdvanceOwnershipEpoch(t.Context()); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("missing sequence was initialized implicitly: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(options.Directory, filename))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InitializeOwnershipEpoch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.InitializeOwnershipEpoch(t.Context()); err == nil {
		t.Fatal("existing sequence reset")
	}
	for wanted := uint32(1); wanted <= 3; wanted++ {
		if actual, err := store.AdvanceOwnershipEpoch(t.Context()); err != nil || actual != wanted {
			t.Fatalf("durable sequence %d: actual %d, %v", wanted, actual, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := openStore(t, options)
	if actual, err := restarted.AdvanceOwnershipEpoch(t.Context()); err != nil || actual != 4 {
		t.Fatalf("restart reused a connection generation: %d, %v", actual, err)
	}
	after, err := os.ReadFile(filepath.Join(options.Directory, filename))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("ownership sequence changed the older release's policy history", err)
	}
	info, err := os.Stat(filepath.Join(options.Directory, ownershipEpochFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("sequence metadata is unsafe", err)
	}
}

func TestOwnershipSequenceRejectsCorruptionExhaustionAndUnsafeMetadata(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"duplicate key", func(t *testing.T, path string) { writeEpochFixture(t, path, `{"schema_version":1,"last":1,"last":2}`) }},
		{"unknown field", func(t *testing.T, path string) {
			writeEpochFixture(t, path, `{"schema_version":1,"last":1,"grant":true}`)
		}},
		{"wrong version", func(t *testing.T, path string) { writeEpochFixture(t, path, `{"schema_version":2,"last":1}`) }},
		{"negative", func(t *testing.T, path string) { writeEpochFixture(t, path, `{"schema_version":1,"last":-1}`) }},
		{"noninteger", func(t *testing.T, path string) { writeEpochFixture(t, path, `{"schema_version":1,"last":1.5}`) }},
		{"overflow", func(t *testing.T, path string) { writeEpochFixture(t, path, `{"schema_version":1,"last":4294967296}`) }},
		{"exhaustion", func(t *testing.T, path string) { writeEpochFixture(t, path, `{"schema_version":1,"last":4294967294}`) }},
		{"oversize", func(t *testing.T, path string) { writeEpochFixture(t, path, string(bytes.Repeat([]byte("x"), 129))) }},
		{"readable", func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- Deliberately unsafe fixture.
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filename, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := storeOptions(t)
			store := openStore(t, options)
			if err := errors.Join(store.Initialize(t.Context()), store.InitializeOwnershipEpoch(t.Context())); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(options.Directory, ownershipEpochFile)
			test.mutate(t, path)
			if value, err := store.AdvanceOwnershipEpoch(t.Context()); err == nil || value != 0 {
				t.Fatal("unsafe sequence supplied a generation", value, err)
			}
			if err := store.InitializeOwnershipEpoch(t.Context()); err == nil {
				t.Fatal("unsafe sequence was repaired by initialization")
			}
		})
	}
}

func writeEpochFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOwnershipSequenceSerializesConcurrentConsumersAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	store := openStore(t, storeOptions(t))
	if err := errors.Join(store.Initialize(t.Context()), store.InitializeOwnershipEpoch(t.Context())); err != nil {
		t.Fatal(err)
	}
	const count = 32
	results := make(chan uint32, count)
	var consumers sync.WaitGroup
	for range count {
		consumers.Go(func() {
			value, err := store.AdvanceOwnershipEpoch(t.Context())
			if err != nil {
				t.Error(err)
			}
			results <- value
		})
	}
	consumers.Wait()
	close(results)
	seen := map[uint32]bool{}
	for value := range results {
		if value == 0 || value > count || seen[value] {
			t.Fatal("concurrent consumers reused a generation", value)
		}
		seen[value] = true
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := store.AdvanceOwnershipEpoch(ctx); !errors.Is(err, context.Canceled) || value != 0 {
		t.Fatal("canceled consumer acquired a generation", value, err)
	}
	if value, err := store.AdvanceOwnershipEpoch(t.Context()); err != nil || value != count+1 {
		t.Fatal("canceled consumer changed durable state", value, err)
	}
}

func TestOwnershipSequenceExhaustionCannotWrapIntoConnectionRuleBits(t *testing.T) {
	t.Parallel()
	options := storeOptions(t)
	store := openStore(t, options)
	if err := store.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.writeOwnershipEpoch(t.Context(), policy.MaximumOwnershipEpoch-1); err != nil {
		t.Fatal(err)
	}
	if value, err := store.AdvanceOwnershipEpoch(t.Context()); err != nil || value != policy.MaximumOwnershipEpoch {
		t.Fatal("last supported generation was lost", value, err)
	}
	if value, err := store.AdvanceOwnershipEpoch(t.Context()); err == nil || value != 0 {
		t.Fatal("generation overflow reused a connection identity", value, err)
	}
}
