package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestSnapshotBudgetExhaustedIsRetryableNotTerminal pins how the publication classifies an abort caused by
// running out of lease budget.
//
// The projection guard refuses to start a chunk it cannot finish so the run can be retried on a fresh lease,
// rather than burning the whole lease and blocking every advisory writer for its duration. That intent only
// holds if the caller treats the abort as transient. vulnerabilitymonitor routes shared.ErrValidation to
// finishFailure (terminal StateFailed) and context.DeadlineExceeded to retryLeaseLoss (retried), so reporting
// this abort as a validation error made a snapshot that is merely large permanently unpublishable, and
// mislabelled a timing failure as invalid input.
//
// The decision is tested as a pure function rather than by racing a real publication against a short
// deadline: a wall-clock race lands the timeout wherever it happens to land, most often inside a query, which
// exercises a different path and makes the test flaky.
func TestSnapshotBudgetExhaustedIsRetryableNotTerminal(t *testing.T) {
	// Two chunks took 200ms, so the next is projected at 100ms; only 10ms of deadline remains.
	err := snapshotBudgetExhausted(200*time.Millisecond, 2, 10*time.Millisecond, 256, 1024)
	if err == nil {
		t.Fatal("a chunk that cannot finish inside the remaining deadline must be refused")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a lease-budget abort must report context.DeadlineExceeded so the caller retries it, got %v", err)
	}
	if errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a lease-budget abort must not be a validation error: that routes the run to a terminal StateFailed, got %v", err)
	}
	// The message must stay attributable: how far the snapshot got, and why it stopped.
	for _, want := range []string{"100ms", "10ms", "256 of 1024"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("abort message %q omits %q", err.Error(), want)
		}
	}
}

func TestSnapshotBudgetExhaustedAllowsAffordableChunks(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		elapsed   time.Duration
		chunks    int
		remaining time.Duration
	}{
		{"ample budget", 200 * time.Millisecond, 2, 10 * time.Second},
		{"exactly enough", 200 * time.Millisecond, 2, 100 * time.Millisecond},
		{"no measured chunk yet", 0, 0, time.Nanosecond},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := snapshotBudgetExhausted(testCase.elapsed, testCase.chunks, testCase.remaining, 0, 1024); err != nil {
				t.Fatalf("an affordable chunk must proceed, got %v", err)
			}
		})
	}
}
