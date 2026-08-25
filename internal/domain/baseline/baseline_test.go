package baseline

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func key() Key { return Key{Tenant: "t1", Group: "web-tier"} }

func obs(spawn, fanout, newexec, priv, files int64) Observation {
	return Observation{Values: [numFeatures]int64{spawn, fanout, newexec, priv, files}}
}

// okWin is a clean, well-covered learning window (eligible).
func okWin() LearnWindow { return LearnWindow{Coverage: 90, MinCoverage: 60} }

func mustBaseline(t *testing.T) *Baseline {
	t.Helper()
	b, err := NewBaseline(key())
	if err != nil {
		t.Fatalf("new baseline: %v", err)
	}
	return b
}

// learnSteady folds n copies of a steady observation (through the eligibility gate) and activates.
func learnSteady(t *testing.T, b *Baseline, n int, o Observation) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := b.Fold(o, okWin()); err != nil {
			t.Fatalf("fold: %v", err)
		}
	}
	if err := b.Transition(StateActive); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

func TestStateMachine(t *testing.T) {
	for _, s := range []State{StateLearning, StateStale, StateDrifted, StatePoisoned, StateResetPending, StateDisabled} {
		if s.Scoreable() {
			t.Fatalf("%s must not be scoreable", s)
		}
	}
	if !StateActive.Scoreable() {
		t.Fatal("active must be scoreable")
	}
	b := mustBaseline(t)
	for _, to := range []State{StateActive, StateDrifted, StateResetPending, StateLearning, StateActive} {
		if err := b.Transition(to); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
	if err := b.Transition(StateDisabled); err != nil {
		t.Fatalf("active->disabled: %v", err)
	}
	if !b.State().Terminal() {
		t.Fatal("disabled must be terminal")
	}
	if b.Transition(StateLearning) == nil {
		t.Fatal("no transition out of disabled")
	}
	b2 := mustBaseline(t)
	if err := b2.Transition(StateDrifted); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("learning->drifted must be illegal, got %v", err)
	}
	if err := b2.Transition("bogus"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown state must be rejected, got %v", err)
	}
}

func TestFoldIsReorderInvariant(t *testing.T) {
	obsSeq := []Observation{obs(2, 5, 1, 0, 3), obs(3, 4, 0, 1, 2), obs(1, 6, 2, 0, 4), obs(4, 5, 1, 0, 3)}
	fwd := mustBaseline(t)
	for _, o := range obsSeq {
		if err := fwd.Fold(o, okWin()); err != nil {
			t.Fatal(err)
		}
	}
	rev := mustBaseline(t)
	for i := len(obsSeq) - 1; i >= 0; i-- {
		if err := rev.Fold(obsSeq[i], okWin()); err != nil {
			t.Fatal(err)
		}
	}
	if fwd.Summary() != rev.Summary() {
		t.Fatalf("fold not reorder-invariant:\n fwd=%+v\n rev=%+v", fwd.Summary(), rev.Summary())
	}
	if fwd.ObservationCount() != 4 {
		t.Fatalf("obs count = %d, want 4", fwd.ObservationCount())
	}
}

func TestColdStartAbstains(t *testing.T) {
	b := mustBaseline(t)
	for i := 0; i < 5; i++ {
		if err := b.Fold(obs(2, 5, 1, 0, 3), okWin()); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := b.Anomaly(obs(99, 99, 9, 9, 99)); ok {
		t.Fatal("a learning baseline must abstain from scoring")
	}
	if b.ReadyToActivate(10) {
		t.Fatal("5 obs must not be ready to activate at min 10")
	}
	if !b.ReadyToActivate(5) {
		t.Fatal("5 obs must be ready to activate at min 5")
	}
}

func TestAnomalyMonotonicAndScoreableGate(t *testing.T) {
	b := mustBaseline(t)
	seq := []Observation{obs(2, 5, 1, 0, 3), obs(2, 5, 1, 0, 3), obs(3, 4, 1, 0, 3), obs(1, 6, 1, 0, 3), obs(2, 5, 1, 0, 3), obs(2, 5, 1, 0, 3)}
	for _, o := range seq {
		if err := b.Fold(o, okWin()); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Transition(StateActive); err != nil {
		t.Fatal(err)
	}
	near, ok := b.Anomaly(obs(2, 5, 1, 0, 3))
	if !ok {
		t.Fatal("active baseline must be scoreable")
	}
	mild, _ := b.Anomaly(obs(4, 7, 1, 0, 3))
	wild, _ := b.Anomaly(obs(50, 80, 20, 9, 40))
	if !(near <= mild && mild <= wild) {
		t.Fatalf("anomaly must be monotonic in deviation: near=%d mild=%d wild=%d", near, mild, wild)
	}
	if !near.Valid() || !wild.Valid() {
		t.Fatal("scores must be in range")
	}
	if wild < 65 {
		t.Fatalf("a wild deviation must score high, got %d", wild)
	}
}

// TestAnomalyLargeValueDoesNotWrapToNormal is the overflow-evasion regression: a maximally large valid
// feature value against a small-valued baseline must score in the TOP band, never wrap to band 0 "normal".
func TestAnomalyLargeValueDoesNotWrapToNormal(t *testing.T) {
	b := mustBaseline(t)
	learnSteady(t, b, 20, obs(2, 5, 1, 0, 3))
	// A single feature slammed to the max — with wrapping int64 math this could have collapsed to band 0.
	huge := obs(MaxFeatureValue, 5, 1, 0, 3)
	score, ok := b.Anomaly(huge)
	if !ok {
		t.Fatal("active baseline must score")
	}
	if score < 65 {
		t.Fatalf("a max-value deviation must score in a high band, got %d (overflow wrap?)", score)
	}
}

func TestFoldThroughEligibilityGateRejectsTaintedWindow(t *testing.T) {
	b := mustBaseline(t)
	// An incident-active window must be refused before any mutation.
	if err := b.Fold(obs(2, 5, 1, 0, 3), LearnWindow{IncidentActive: true, Coverage: 90, MinCoverage: 60}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("fold through incident window must be rejected, got %v", err)
	}
	if b.ObservationCount() != 0 {
		t.Fatalf("a rejected fold must not mutate; obs=%d", b.ObservationCount())
	}
	// The true zero-value window (no coverage floor established) is also refused.
	if err := b.Fold(obs(2, 5, 1, 0, 3), LearnWindow{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("fold through zero-value window must be rejected, got %v", err)
	}
	if b.ObservationCount() != 0 {
		t.Fatalf("zero-value window must not mutate; obs=%d", b.ObservationCount())
	}
}

func TestReBaselineClearsAccumulators(t *testing.T) {
	b := mustBaseline(t)
	learnSteady(t, b, 8, obs(9, 9, 9, 9, 9)) // learn a (hypothetically poisoned) high baseline
	// Drift → request reset → re-baseline.
	if err := b.Transition(StateDrifted); err != nil {
		t.Fatal(err)
	}
	if err := b.Transition(StateResetPending); err != nil {
		t.Fatal(err)
	}
	if err := b.Transition(StateLearning); err != nil {
		t.Fatal(err)
	}
	if b.ObservationCount() != 0 {
		t.Fatalf("re-baseline must clear observations, got %d", b.ObservationCount())
	}
	var zero [numFeatures]FeatureSummary
	for f := 0; f < numFeatures; f++ {
		zero[f] = FeatureSummary{Feature: Feature(f)}
	}
	if b.Summary() != zero {
		t.Fatalf("re-baseline must zero the accumulators, got %+v", b.Summary())
	}
}

func TestFoldRejectedInNonLearningState(t *testing.T) {
	b := mustBaseline(t)
	learnSteady(t, b, 3, obs(2, 5, 1, 0, 3))
	if err := b.Transition(StateDrifted); err != nil {
		t.Fatal(err)
	}
	if err := b.Fold(obs(2, 5, 1, 0, 3), okWin()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("folding into a drifted baseline must be rejected, got %v", err)
	}
}

func TestObservationAndKeyValidation(t *testing.T) {
	if _, err := NewBaseline(Key{Group: "g"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing tenant must be rejected")
	}
	if _, err := NewBaseline(Key{Tenant: "t"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing group must be rejected")
	}
	b := mustBaseline(t)
	if err := b.Fold(Observation{Values: [numFeatures]int64{1, -1, 0, 0, 0}}, okWin()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("negative feature value must be rejected, got %v", err)
	}
	if err := b.Fold(obs(MaxFeatureValue+1, 0, 0, 0, 0), okWin()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("feature value above MaxFeatureValue must be rejected, got %v", err)
	}
}

func TestNewBaselineFromNearCapAndVarianceCheck(t *testing.T) {
	// A near-cap but VALID row: every observation = MaxFeatureValue (variance 0). obs*sumSq and sum^2 both
	// reach ~1e24 and overflow int64 — the big.Int integrity check must NOT wrongly reject it.
	valid := make([]FeatureSummary, NumFeatures)
	for f := 0; f < NumFeatures; f++ {
		valid[f] = FeatureSummary{
			Feature: Feature(f),
			Count:   MaxObservations,
			Sum:     MaxObservations * MaxFeatureValue,
			SumSq:   MaxObservations * MaxFeatureValue * MaxFeatureValue,
			Min:     MaxFeatureValue,
			Max:     MaxFeatureValue,
		}
	}
	if _, err := NewBaselineFrom(key(), StateActive, valid); err != nil {
		t.Fatalf("a valid near-cap baseline must rehydrate (no int64 overflow in the variance check): %v", err)
	}
	// A genuinely negative-variance row (obs*sumSq < sum^2) must be rejected.
	bad := make([]FeatureSummary, NumFeatures)
	for f := 0; f < NumFeatures; f++ {
		bad[f] = FeatureSummary{Feature: Feature(f), Count: 10, Sum: 100, SumSq: 500, Min: 0, Max: 10}
	}
	if _, err := NewBaselineFrom(key(), StateActive, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a negative-variance row must be rejected, got %v", err)
	}
	// An inverted min/max must be rejected.
	inv := make([]FeatureSummary, NumFeatures)
	for f := 0; f < NumFeatures; f++ {
		inv[f] = FeatureSummary{Feature: Feature(f), Count: 1, Sum: 2, SumSq: 4, Min: 5, Max: 2}
	}
	if _, err := NewBaselineFrom(key(), StateActive, inv); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("inverted min/max must be rejected, got %v", err)
	}
}

func TestLearnEligibilityFailClosed(t *testing.T) {
	if ok, why := okWin().Eligible(); !ok {
		t.Fatalf("clean window must be eligible, got %q", why)
	}
	for name, w := range map[string]LearnWindow{
		"incident":        {IncidentActive: true, Coverage: 90, MinCoverage: 60},
		"emulation":       {Emulation: true, Coverage: 90, MinCoverage: 60},
		"active-response": {ActiveResponse: true, Coverage: 90, MinCoverage: 60},
		"degraded":        {SensorDegraded: true, Coverage: 90, MinCoverage: 60},
		"low-coverage":    {Coverage: 40, MinCoverage: 60},
		"zero-value":      {},
		"no-floor":        {Coverage: 90},
		"no-coverage":     {MinCoverage: 60},
	} {
		if ok, why := w.Eligible(); ok {
			t.Fatalf("%s window must be ineligible", name)
		} else if why == "" {
			t.Fatalf("%s window must carry a reason", name)
		}
	}
}
