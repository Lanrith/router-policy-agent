package binding

import (
	"errors"
	"testing"
	"time"
)

func TestIncompletePublicationIsExplicitAndNeverValid(t *testing.T) {
	t.Parallel()
	data := []byte(`{"schema_version":1,"generation":"collecting","observed_at":"2026-01-01T00:00:00Z","complete":false,"records":[]}`)
	if _, err := decodeSnapshot(data); !errors.Is(err, ErrIncomplete) {
		t.Fatal("negative producer publication lost its typed boundary", err)
	}
	snapshot := Snapshot{SchemaVersion: 1, Generation: "collecting",
		ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Complete: false, Records: []Record{}}
	if err := Validate(snapshot, snapshot.ObservedAt, time.Minute, 64); !errors.Is(err, ErrIncomplete) {
		t.Fatal("incomplete evidence was accepted or misclassified", err)
	}
	if _, err := decodeSnapshot([]byte(`{"schema_version":2,"generation":"bad","observed_at":"2026-01-01T00:00:00Z","complete":false,"records":[]}`)); err == nil || errors.Is(err, ErrIncomplete) {
		t.Fatal("invalid schema was hidden as a pending collection", err)
	}
}
