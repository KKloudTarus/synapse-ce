package baseline

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// HoursPerWeek is the seasonality period: behavior is bucketed by hour-of-week so a legitimately periodic
// load (a nightly batch job, a Monday-morning spike) is compared against the same hour on other weeks
// rather than being scored as anomalous.
const HoursPerWeek = 168

// nanosPerHour is 1 hour in Unix nanoseconds.
const nanosPerHour int64 = 3600 * 1_000_000_000

// SeasonBucket returns the hour-of-week (0..167) for an observation timestamp given as Unix NANOSECONDS.
// It is PURE ARITHMETIC over the passed timestamp — it never reads the wall clock — so it is deterministic
// and reproducible for evidence. The week is anchored to Monday 00:00 UTC (the Unix epoch, 1970-01-01, is
// a Thursday = hour 72 of a Monday-started week). The result is normalized into [0,167] for any int64; the
// arithmetic is exact for positive (post-1970) timestamps, which is all real telemetry. Callers must bucket
// on the sensor-observed occurred-at, never a client-influenced field.
func SeasonBucket(unixNanos int64) int {
	hours := unixNanos / nanosPerHour
	hw := (hours + 72) % HoursPerWeek
	if hw < 0 {
		hw += HoursPerWeek
	}
	return int(hw)
}

// SeasonalGroup composes a base group id with its hour-of-week bucket, so a caller can key a baseline per
// (group, season) and keep periodic load from contaminating the off-peak baseline. A caller that does not
// want seasonality simply uses the plain group id. Deterministic (SeasonBucket is pure).
func SeasonalGroup(group string, unixNanos int64) string {
	return fmt.Sprintf("%s|hw=%d", group, SeasonBucket(unixNanos))
}

// DefaultDriftScore is the anomaly-score floor (≈ >2σ, band 2) at or above which a scoring window counts
// as divergent for drift purposes.
const DefaultDriftScore riskassessment.Score = 65

// DefaultDriftThreshold is how many CONSECUTIVE divergent windows must be seen before drift is declared —
// the hysteresis that keeps a single transient blip from flapping an active baseline into re-baselining.
const DefaultDriftThreshold = 3

// DriftTracker decides when an active baseline has genuinely drifted (concept drift), as opposed to seeing
// a one-off anomalous window. It counts CONSECUTIVE divergent windows and declares drift only once a
// sustained run reaches the threshold; any non-divergent window resets the run (hysteresis). It is a
// deterministic, clock-free STATEFUL accumulator mutated through its pointer receivers (do not copy it
// mid-run, or you fork its state). The usecase feeds it each window's anomaly score and, when it reports
// drift, drives the baseline active -> drifted transition (then a clean re-baseline).
type DriftTracker struct {
	driftScore riskassessment.Score
	threshold  int
	run        int
	drifted    bool
}

// NewDriftTracker builds a tracker. A zero/omitted driftScore or threshold falls back to the defaults; an
// out-of-range driftScore is rejected.
func NewDriftTracker(driftScore riskassessment.Score, threshold int) (*DriftTracker, error) {
	if driftScore == 0 {
		driftScore = DefaultDriftScore
	}
	if threshold == 0 {
		threshold = DefaultDriftThreshold
	}
	if !driftScore.Valid() {
		return nil, fmt.Errorf("%w: drift score %d out of range", shared.ErrValidation, driftScore)
	}
	if threshold < 1 {
		return nil, fmt.Errorf("%w: drift threshold must be >= 1", shared.ErrValidation)
	}
	return &DriftTracker{driftScore: driftScore, threshold: threshold}, nil
}

// NewDriftTrackerFrom rehydrates a tracker to a persisted (run, drifted) state, so drift progress survives
// a process restart / worker-lease handoff instead of restarting from zero. It validates the same bounds
// as NewDriftTracker plus the latch invariant: run is in [0, threshold], and a run at the threshold is
// consistent only with drifted=true.
func NewDriftTrackerFrom(driftScore riskassessment.Score, threshold, run int, drifted bool) (*DriftTracker, error) {
	d, err := NewDriftTracker(driftScore, threshold)
	if err != nil {
		return nil, err
	}
	if run < 0 || run > d.threshold {
		return nil, fmt.Errorf("%w: drift run %d out of range [0,%d]", shared.ErrValidation, run, d.threshold)
	}
	if run >= d.threshold && !drifted {
		return nil, fmt.Errorf("%w: a run at the threshold must be drifted", shared.ErrValidation)
	}
	d.run = run
	d.drifted = drifted
	return d, nil
}

// Observe folds one window's anomaly score and reports whether the baseline has drifted. A window at or
// above the drift score extends the divergent run; anything below resets it (hysteresis). Once drift is
// declared it latches until Reset (a re-baseline).
func (d *DriftTracker) Observe(anomaly riskassessment.Score) bool {
	if d.drifted {
		return true
	}
	if anomaly >= d.driftScore {
		d.run++
	} else {
		d.run = 0
	}
	if d.run >= d.threshold {
		d.drifted = true
	}
	return d.drifted
}

// Drifted reports the latched drift state.
func (d *DriftTracker) Drifted() bool { return d.drifted }

// Run reports the current consecutive-divergent-window count (for observability/persistence).
func (d *DriftTracker) Run() int { return d.run }

// Reset clears the tracker for a fresh baseline (call alongside a reset_pending -> learning re-baseline).
func (d *DriftTracker) Reset() {
	d.run = 0
	d.drifted = false
}
