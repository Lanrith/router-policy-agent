package reader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/lanrith/router-policy-agent/internal/ipc"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

func testSnapshot(at time.Time) policy.DirectorySnapshot {
	return policy.DirectorySnapshot{ObservedAt: at, Complete: true,
		Groups: []policy.Group{}, Devices: []policy.Device{}}
}

func testReceipt(status ipc.Status) ipc.Receipt {
	return ipc.Receipt{SchemaVersion: 1, Status: status, BaselineHash: strings.Repeat("a", 64),
		CompiledAt: time.Now().UTC(), GrantCount: 2, DenialCount: 1}
}

func TestLoopAlwaysRecollectsAndNeverReplaysFailedSubmission(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var diagnostics bytes.Buffer
		var collections, submissions atomic.Int64
		observations := []time.Time{}
		commits := make(chan time.Time, 2)
		collect := func(context.Context) (policy.DirectorySnapshot, error) {
			count := collections.Add(1)
			snapshot := testSnapshot(time.Now().UTC())
			if count == 2 {
				// Even a populated partial result alongside an error is discarded.
				return snapshot, errors.New("synthetic-private-directory-diagnostic")
			}
			observations = append(observations, snapshot.ObservedAt)
			return snapshot, nil
		}
		submit := func(ctx context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
			count := submissions.Add(1)
			if !reflect.DeepEqual(snapshot, testSnapshot(observations[count-1])) {
				t.Error("snapshot changed between collection and submission")
			}
			// Model a successful commit followed by a missing receipt. The lease
			// is anchored to collection and survives independently in the helper.
			commits <- snapshot.ObservedAt.Add(90 * time.Second)
			if count == 1 {
				<-ctx.Done()
				return ipc.Receipt{}, ctx.Err()
			}
			return testReceipt(ipc.StatusApplied), nil
		}
		done := make(chan error, 1)
		go func() { done <- runLoop(ctx, collect, submit, &diagnostics) }()
		synctest.Wait()
		if collections.Load() != 1 || submissions.Load() != 1 {
			t.Fatal("startup did not make exactly one collection and submission")
		}
		firstExpiry := <-commits
		time.Sleep(refreshInterval)
		synctest.Wait()
		if len(commits) != 0 || time.Until(firstExpiry) != 60*time.Second {
			t.Fatal("the missing receipt or failed collection moved the committed lease")
		}
		if collections.Load() != 2 || submissions.Load() != 1 {
			t.Fatal("failed collection submitted or lost receipt retried")
		}
		time.Sleep(refreshInterval)
		synctest.Wait()
		if collections.Load() != 3 || submissions.Load() != 2 {
			t.Fatal("recovery did not submit a newly collected observation")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("reader cancellation did not join its loop")
		}
		if !observations[1].After(observations[0]) {
			t.Fatal("recovered observation was not fresh")
		}
		decoder := json.NewDecoder(&diagnostics)
		for _, outcome := range []string{"submission_failed", "collection_failed", "applied"} {
			var result attempt
			if err := decoder.Decode(&result); err != nil || result.Outcome != outcome {
				t.Fatal("unexpected diagnostic outcome")
			}
		}
		var extra attempt
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			t.Fatal("extra poll or unbounded diagnostic payload")
		}
	})
}

func TestCycleReservesTimeForHelperReceipt(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		original := testSnapshot(started.UTC())
		collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
			time.Sleep(9 * time.Second)
			return original, ctx.Err()
		}
		submit := func(ctx context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
			if !reflect.DeepEqual(snapshot, original) {
				t.Fatal("submission changed the original evidence")
			}
			time.Sleep(11 * time.Second)
			return testReceipt(ipc.StatusApplied), ctx.Err()
		}
		result, err := runCycle(t.Context(), collect, submit)
		if err != nil || result.Outcome != "applied" || result.GrantCount != 2 ||
			time.Since(started) != 20*time.Second {
			t.Fatalf("slow collection and timely submission returned %#v, %v", result, err)
		}
	})
}

func TestCycleRejectsLateReceipt(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		collect := func(context.Context) (policy.DirectorySnapshot, error) {
			time.Sleep(9 * time.Second)
			return testSnapshot(started.UTC()), nil
		}
		submit := func(ctx context.Context, _ policy.DirectorySnapshot) (ipc.Receipt, error) {
			<-ctx.Done()
			return testReceipt(ipc.StatusApplied), nil
		}
		result, err := runCycle(t.Context(), collect, submit)
		if err != nil || result.Outcome != "submission_failed" || result.GrantCount != 0 ||
			time.Since(started) != 21*time.Second {
			t.Fatalf("late receipt returned %#v, %v after %v", result, err, time.Since(started))
		}
	})
}

func TestCycleDoesNotSubmitAfterCollectionDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
			<-ctx.Done()
			return testSnapshot(time.Now().UTC()), nil
		}
		submit := func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error) {
			t.Error("expired collection reached helper")
			return testReceipt(ipc.StatusApplied), nil
		}
		result, err := runCycle(t.Context(), collect, submit)
		if err != nil || result.Outcome != "collection_failed" {
			t.Fatal("collection timeout was not a failed attempt")
		}
	})
}

func TestCycleReportsOnlyFixedOutcomes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, outcome string
		receipt       ipc.Receipt
		err           error
	}{
		{name: "shadow is not applied", outcome: "shadow", receipt: testReceipt(ipc.StatusShadow)},
		{name: "applied", outcome: "applied", receipt: testReceipt(ipc.StatusApplied)},
		{name: "rejection", outcome: "rejected", err: errors.Join(ipc.ErrRejected, errors.New("synthetic-private-error"))},
		{name: "submission failure", outcome: "submission_failed", err: errors.New("synthetic-private-error")},
		{name: "unknown status", outcome: "submission_failed", receipt: ipc.Receipt{Status: "synthetic-private-status"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			collect := func(context.Context) (policy.DirectorySnapshot, error) { return testSnapshot(time.Now().UTC()), nil }
			submit := func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error) { return test.receipt, test.err }
			result, err := runCycle(t.Context(), collect, submit)
			if err != nil || result.Outcome != test.outcome {
				t.Fatal("incorrect cycle outcome")
			}
			data, err := json.Marshal(result)
			if err != nil || bytes.Contains(data, []byte("synthetic-private")) {
				t.Fatal("upstream details escaped to diagnostics")
			}
		})
	}
}

func TestLoopCancellationJoinsActiveOperation(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"collection", "submission"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var diagnostics bytes.Buffer
				var joined bool
				collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
					if stage == "collection" {
						<-ctx.Done()
						joined = true
						return policy.DirectorySnapshot{}, ctx.Err()
					}
					return testSnapshot(time.Now().UTC()), nil
				}
				submit := func(ctx context.Context, _ policy.DirectorySnapshot) (ipc.Receipt, error) {
					<-ctx.Done()
					joined = true
					return ipc.Receipt{}, ctx.Err()
				}
				done := make(chan error, 1)
				go func() { done <- runLoop(ctx, collect, submit, &diagnostics) }()
				synctest.Wait()
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) || !joined || diagnostics.Len() != 0 {
					t.Fatal("cancellation returned before active work stopped or emitted a success")
				}
			})
		})
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-private-output-error")
}

func TestLoopRejectsInvalidDependenciesAndOutputFailure(t *testing.T) {
	t.Parallel()
	collect := func(context.Context) (policy.DirectorySnapshot, error) { return testSnapshot(time.Now().UTC()), nil }
	submit := func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error) {
		return testReceipt(ipc.StatusShadow), nil
	}
	for _, test := range []struct {
		name        string
		hasContext  bool
		collect     collectFunc
		submit      submitFunc
		diagnostics io.Writer
	}{
		{name: "missing context", collect: collect, submit: submit, diagnostics: io.Discard},
		{name: "missing collector", hasContext: true, submit: submit, diagnostics: io.Discard},
		{name: "missing submitter", hasContext: true, collect: collect, diagnostics: io.Discard},
		{name: "missing diagnostics", hasContext: true, collect: collect, submit: submit},
		{name: "failed diagnostics", hasContext: true, collect: collect, submit: submit, diagnostics: failedWriter{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var ctx context.Context
			if test.hasContext {
				ctx = t.Context()
			}
			if err := runLoop(ctx, test.collect, test.submit, test.diagnostics); !errors.Is(err, errRuntime) {
				t.Fatal("invalid dependency or diagnostic failure ignored")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runLoop(ctx, collect, submit, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal("already-canceled loop started work")
	}
}

func TestProviderCheckRequiresFreshAppliedReceipt(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    ipc.Status
		grants    int
		withdrawn bool
		pass      bool
	}{
		{"positive applied", ipc.StatusApplied, 1, false, true},
		{"positive absent", ipc.StatusApplied, 0, false, false},
		{"positive shadow", ipc.StatusShadow, 1, false, false},
		{"withdrawal", ipc.StatusApplied, 0, true, true},
		{"grant still present", ipc.StatusApplied, 1, true, false},
		{"shadow zero", ipc.StatusShadow, 0, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			collect := func(context.Context) (policy.DirectorySnapshot, error) {
				return policy.DirectorySnapshot{ObservedAt: time.Now().UTC(), Complete: true}, nil
			}
			submit := func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error) {
				receipt := testReceipt(test.status)
				receipt.GrantCount = test.grants
				return receipt, nil
			}
			if err := checkProviderReceipt(t.Context(), collect, submit, io.Discard, test.withdrawn); (err == nil) != test.pass {
				t.Fatal("unexpected provider qualification from helper receipt")
			}
		})
	}
}
