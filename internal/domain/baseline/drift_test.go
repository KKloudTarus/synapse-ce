package baseline

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSeasonBucketDeterministicAndPeriodic(t *testing.T) {
	// Unix epoch (Thu 1970-01-01 00:00 UTC) is hour 72 of a Monday-started week.
	if got := SeasonBucket(0); got != 72 {
		t.Fatalf("epoch bucket = %d, want 72", got)
	}
	// +1 hour advances the bucket by one.
	if got := SeasonBucket(nanosPerHour); got != 73 {
		t.Fatalf("epoch+1h bucket = %d, want 73", got)
	}
	// Exactly one week later is the SAME bucket (periodicity — the point of seasonality).
	weekNanos := int64(HoursPerWeek) * nanosPerHour
	if SeasonBucket(0) != SeasonBucket(weekNanos) || SeasonBucket(5*nanosPerHour) != SeasonBucket(5*nanosPerHour+weekNanos) {
		t.Fatal("same hour-of-week one week apart must map to the same bucket")
	}
	// Always in range, and deterministic for a fixed input.
	for _, ns := range []int64{0, nanosPerHour, 123 * nanosPerHour, 9999 * nanosPerHour} {
		b := SeasonBucket(ns)
		if b < 0 || b >= HoursPerWeek {
			t.Fatalf("bucket %d out of range for %d", b, ns)
		}
		if b != SeasonBucket(ns) {
			t.Fatal("SeasonBucket must be deterministic")
		}
	}
	if g := SeasonalGroup("web-tier", 0); g != "web-tier|hw=72" {
		t.Fatalf("seasonal group = %q, want web-tier|hw=72", g)
	}
}

func TestDriftTrackerHysteresis(t *testing.T) {
	// Sustained divergence declares drift at the threshold.
	d, err := NewDriftTracker(65, 3)
	if err != nil {
		t.Fatal(err)
	}
	if d.Observe(90) || d.Observe(90) {
		t.Fatal("must not drift before the threshold of consecutive divergent windows")
	}
	if !d.Observe(90) {
		t.Fatal("third consecutive divergent window must declare drift")
	}
	if !d.Drifted() {
		t.Fatal("drift must latch")
	}
	// Latches even if a subsequent window is normal.
	if !d.Observe(5) {
		t.Fatal("drift must stay latched until Reset")
	}
	d.Reset()
	if d.Drifted() || d.Run() != 0 {
		t.Fatal("Reset must clear drift + run")
	}
}

func TestDriftTrackerTransientBlipDoesNotDrift(t *testing.T) {
	d, _ := NewDriftTracker(65, 3)
	// A blip (one divergent window) then a normal window resets the run — never reaches threshold.
	for i := 0; i < 10; i++ {
		if d.Observe(90) { // divergent
			t.Fatalf("unexpected drift at iter %d", i)
		}
		if d.Observe(10) { // normal -> resets run
			t.Fatalf("unexpected drift at iter %d after reset", i)
		}
	}
	if d.Drifted() {
		t.Fatal("alternating blip/normal must never declare drift (hysteresis)")
	}
}

func TestDriftTrackerDefaultsAndValidation(t *testing.T) {
	// Zero args fall back to defaults.
	d, err := NewDriftTracker(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < DefaultDriftThreshold-1; i++ {
		if d.Observe(DefaultDriftScore) {
			t.Fatal("must not drift before default threshold")
		}
	}
	if !d.Observe(DefaultDriftScore) {
		t.Fatal("must drift at the default threshold")
	}
	// Invalid inputs rejected.
	if _, err := NewDriftTracker(riskassessment.Score(200), 3); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("out-of-range drift score must be rejected, got %v", err)
	}
	if _, err := NewDriftTracker(65, -1); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("negative threshold must be rejected, got %v", err)
	}
}

func TestDriftTrackerRehydration(t *testing.T) {
	// Rehydrate mid-run: a persisted run of 2/3 continues to drift on the next divergent window.
	d, err := NewDriftTrackerFrom(65, 3, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if d.Run() != 2 || d.Drifted() {
		t.Fatalf("rehydrated state wrong: run=%d drifted=%v", d.Run(), d.Drifted())
	}
	if !d.Observe(90) {
		t.Fatal("a rehydrated run of 2/3 must drift on the next divergent window")
	}
	// Rehydrate an already-drifted tracker.
	d2, err := NewDriftTrackerFrom(65, 3, 3, true)
	if err != nil {
		t.Fatal(err)
	}
	if !d2.Drifted() {
		t.Fatal("rehydrated drifted tracker must report drifted")
	}
	// Invariant violations rejected.
	if _, err := NewDriftTrackerFrom(65, 3, 4, true); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("run above threshold must be rejected, got %v", err)
	}
	if _, err := NewDriftTrackerFrom(65, 3, 3, false); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("run at threshold with drifted=false must be rejected, got %v", err)
	}
	if _, err := NewDriftTrackerFrom(65, 3, -1, false); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("negative run must be rejected, got %v", err)
	}
}
