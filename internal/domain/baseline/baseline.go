package baseline

import (
	"fmt"
	"math/big"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// MaxObservations caps how many observations a single baseline accumulates before it must be re-baselined.
// It bounds the int64 sum/sumSq accumulators (MaxObservations * MaxFeatureValue^2 stays under MaxInt64) and
// models the reality that a baseline is a bounded rolling window, not an infinite accumulator. Fold refuses
// past this ceiling so the usecase rolls/decays rather than silently overflowing.
const MaxObservations int64 = 1_000_000

// Key identifies what a baseline is learned for: a tenant plus a group, where the group is either
// a peer-group id (peer-group baselining) or a single entity id. Peer-group baselining is first-class so a
// brand-new workload inherits its group's normal rather than cold-starting from nothing.
type Key struct {
	Tenant shared.ID
	Group  string
}

// Validate enforces a well-formed key.
func (k Key) Validate() error {
	if k.Tenant.IsZero() {
		return fmt.Errorf("%w: baseline key requires a tenant", shared.ErrValidation)
	}
	if k.Group == "" {
		return fmt.Errorf("%w: baseline key requires a group (peer-group or entity id)", shared.ErrValidation)
	}
	return nil
}

// FeatureSummary is the deterministic per-feature accumulation of a baseline: enough to compute mean and
// population variance exactly in integer arithmetic (no floats, so it hashes/compares reproducibly). Count
// is shared across features (one observation contributes one value per feature) but carried per-summary
// for a self-describing persisted row.
type FeatureSummary struct {
	Feature Feature
	Count   int64
	Sum     int64
	SumSq   int64
	Min     int64
	Max     int64
}

// Baseline is the per-key behavioral baseline aggregate: its lifecycle state plus a deterministic,
// REORDER-INVARIANT fold of eligible observations (count/sum/sumSq/min/max are all order-independent, so
// re-folding the same observations in any order yields a byte-identical summary — the property Phase-C
// evidence needs). Construct with NewBaseline; advance state only via Transition.
type Baseline struct {
	key   Key
	state State
	obs   int64
	sum   [numFeatures]int64
	sumSq [numFeatures]int64
	min   [numFeatures]int64
	max   [numFeatures]int64
}

// NewBaseline starts a baseline in StateLearning for a validated key.
func NewBaseline(key Key) (*Baseline, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return &Baseline{key: key, state: StateLearning}, nil
}

// NewBaselineFrom rehydrates a baseline from a persisted key + state + per-feature summaries, so a store
// can reload one without re-folding raw observations. summaries must be exactly NumFeatures entries in
// feature order. It validates integrity fail-closed: a consistent shared observation count within
// [0, MaxObservations], non-negative bounded sums, and non-negative variance (obs*sumSq >= sum^2) — a
// crafted/corrupt row that violates these is rejected rather than loaded into the scorer.
func NewBaselineFrom(key Key, state State, summaries []FeatureSummary) (*Baseline, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if !state.Valid() {
		return nil, fmt.Errorf("%w: unknown baseline state %q", shared.ErrValidation, state)
	}
	if len(summaries) != numFeatures {
		return nil, fmt.Errorf("%w: baseline needs %d feature summaries, got %d", shared.ErrValidation, numFeatures, len(summaries))
	}
	b := &Baseline{key: key, state: state}
	obs := summaries[0].Count
	if obs < 0 || obs > MaxObservations {
		return nil, fmt.Errorf("%w: baseline observation count %d out of range [0,%d]", shared.ErrValidation, obs, MaxObservations)
	}
	b.obs = obs
	for f := 0; f < numFeatures; f++ {
		s := summaries[f]
		if s.Feature != Feature(f) {
			return nil, fmt.Errorf("%w: summary %d is for feature %q, expected %q", shared.ErrValidation, f, s.Feature.Name(), Feature(f).Name())
		}
		if s.Count != obs {
			return nil, fmt.Errorf("%w: feature %s count %d disagrees with observation count %d", shared.ErrValidation, Feature(f).Name(), s.Count, obs)
		}
		if s.Sum < 0 || s.SumSq < 0 || s.Min < 0 || s.Max < 0 {
			return nil, fmt.Errorf("%w: feature %s has a negative accumulator", shared.ErrValidation, Feature(f).Name())
		}
		if s.Max > MaxFeatureValue || s.Min > s.Max {
			return nil, fmt.Errorf("%w: feature %s has an out-of-range or inverted min/max", shared.ErrValidation, Feature(f).Name())
		}
		if s.Sum > obs*MaxFeatureValue || s.SumSq > obs*MaxFeatureValue*MaxFeatureValue {
			return nil, fmt.Errorf("%w: feature %s accumulator exceeds the bound for %d observations", shared.ErrValidation, Feature(f).Name(), obs)
		}
		// Non-negative variance: obs*sumSq >= sum^2. Checked in math/big because both products can exceed
		// int64 near the accumulator cap (obs*sumSq up to ~1e24) — the same overflow discipline as the
		// scorer's featureBand, so the integrity gate cannot be defeated by wraparound.
		lhs := new(big.Int).Mul(big.NewInt(obs), big.NewInt(s.SumSq))
		if lhs.Cmp(new(big.Int).Mul(big.NewInt(s.Sum), big.NewInt(s.Sum))) < 0 {
			return nil, fmt.Errorf("%w: feature %s has negative variance (obs*sumSq < sum^2)", shared.ErrValidation, Feature(f).Name())
		}
		b.sum[f] = s.Sum
		b.sumSq[f] = s.SumSq
		b.min[f] = s.Min
		b.max[f] = s.Max
	}
	return b, nil
}

// Key returns the baseline's identity.
func (b *Baseline) Key() Key { return b.key }

// State returns the current lifecycle state.
func (b *Baseline) State() State { return b.state }

// ObservationCount returns how many observations have been folded.
func (b *Baseline) ObservationCount() int64 { return b.obs }

// Scoreable reports whether the baseline may currently yield an anomaly score (state == active).
func (b *Baseline) Scoreable() bool { return b.state.Scoreable() }

// ReadyToActivate reports whether enough observations have accrued to leave cold-start. The caller drives
// the learning -> active transition; the baseline only reports readiness (it never self-advances).
func (b *Baseline) ReadyToActivate(minObservations int64) bool {
	return minObservations > 0 && b.obs >= minObservations
}

// Transition advances the lifecycle state, rejecting an illegal transition. Entering StateLearning (only
// reachable from reset_pending) ZEROES the accumulators: a re-baseline must start clean so it can never
// keep folding onto the prior, possibly-poisoned, sums.
func (b *Baseline) Transition(to State) error {
	if err := requireTransition(b.state, to); err != nil {
		return err
	}
	b.state = to
	if to == StateLearning {
		b.reset()
	}
	return nil
}

// reset zeroes the accumulators for a clean (re-)baseline. State is not touched here.
func (b *Baseline) reset() {
	b.obs = 0
	b.sum = [numFeatures]int64{}
	b.sumSq = [numFeatures]int64{}
	b.min = [numFeatures]int64{}
	b.max = [numFeatures]int64{}
}

// Fold accumulates one observation captured under window w. It FOLDS THROUGH THE ELIGIBILITY GATE: an
// ineligible window (incident/emulation/active-response/degraded/low-coverage — see LearnWindow.Eligible)
// is rejected before any mutation, so tainted data cannot be folded even by a caller that forgot to check
// (the anti-poisoning gate is enforced here, not by convention). Folding is further allowed ONLY in a
// learning-capable state (learning/active/stale) — a drifted/poisoned/reset_pending/disabled baseline must
// NOT keep learning — and is refused past MaxObservations so the accumulators cannot overflow.
func (b *Baseline) Fold(o Observation, w LearnWindow) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if ok, why := w.Eligible(); !ok {
		return fmt.Errorf("%w: window not eligible for learning: %s", shared.ErrValidation, why)
	}
	switch b.state {
	case StateLearning, StateActive, StateStale:
		// learning-capable
	default:
		return fmt.Errorf("%w: cannot fold into a %s baseline", shared.ErrValidation, b.state)
	}
	if b.obs >= MaxObservations {
		return fmt.Errorf("%w: baseline observation cap (%d) reached; re-baseline required", shared.ErrValidation, MaxObservations)
	}
	first := b.obs == 0
	b.obs++
	for f := 0; f < numFeatures; f++ {
		v := o.Values[f]
		b.sum[f] += v
		b.sumSq[f] += v * v
		if first || v < b.min[f] {
			b.min[f] = v
		}
		if first || v > b.max[f] {
			b.max[f] = v
		}
	}
	return nil
}

// Summary returns the per-feature accumulation in fixed feature order (deterministic).
func (b *Baseline) Summary() [numFeatures]FeatureSummary {
	var out [numFeatures]FeatureSummary
	for f := 0; f < numFeatures; f++ {
		out[f] = FeatureSummary{Feature: Feature(f), Count: b.obs, Sum: b.sum[f], SumSq: b.sumSq[f], Min: b.min[f], Max: b.max[f]}
	}
	return out
}

// Anomaly scores how far observation o deviates from the learned baseline as a 0..100 Score, and reports
// whether the baseline was scoreable at all. It abstains (0, false) unless the baseline is active with at
// least one observation — a non-active baseline must NOT fabricate a score (coverage-honesty).
//
// The score is the WORST per-feature deviation band, measured in standard deviations using EXACT integer
// arithmetic (no mean truncation, no sqrt, no division): with mean = sum/obs and population variance var,
// the test (v-mean)^2 <= k*var is equivalent to (obs*v - sum)^2 <= k*(obs*sumSq - sum^2), and obs^2*var =
// obs*sumSq - sum^2. A variance floor of 1 unit^2 (adding obs^2) keeps a zero-variance feature from
// screaming at a ±1 wobble. The comparison is done in math/big so it CANNOT overflow — a wild deviation
// can never wrap into a low band and read as "normal" (a detector-evasion this safety path must prevent).
func (b *Baseline) Anomaly(o Observation) (riskassessment.Score, bool) {
	if !b.state.Scoreable() || b.obs <= 0 {
		return 0, false
	}
	if err := o.Validate(); err != nil {
		return 0, false
	}
	worst := 0
	for f := 0; f < numFeatures; f++ {
		band := b.featureBand(f, o.Values[f])
		if band > worst {
			worst = band
		}
	}
	return bandScore(worst), true
}

// featureBand returns 0 (<=1σ), 1 (<=2σ), 2 (<=3σ), or 3 (>3σ) for feature f at value v. It uses
// arbitrary-precision integers so the exact-variance comparison is overflow-free and deterministic:
// there is no int64 product that could wrap and collapse a large deviation to band 0.
func (b *Baseline) featureBand(f int, v int64) int {
	obs := big.NewInt(b.obs)
	sum := big.NewInt(b.sum[f])
	// num = obs*sumSq - sum^2 = obs^2 * variance, always >= 0.
	num := new(big.Int).Mul(obs, big.NewInt(b.sumSq[f]))
	num.Sub(num, new(big.Int).Mul(sum, sum))
	// Variance floor of 1 unit^2: num >= obs^2.
	if obs2 := new(big.Int).Mul(obs, obs); num.Cmp(obs2) < 0 {
		num = obs2
	}
	// d = obs*(v - mean); lhs = d^2 = obs^2 * (v-mean)^2.
	d := new(big.Int).Sub(new(big.Int).Mul(obs, big.NewInt(v)), sum)
	lhs := new(big.Int).Mul(d, d)
	switch {
	case lhs.Cmp(num) <= 0:
		return 0
	case lhs.Cmp(new(big.Int).Mul(big.NewInt(4), num)) <= 0:
		return 1
	case lhs.Cmp(new(big.Int).Mul(big.NewInt(9), num)) <= 0:
		return 2
	default:
		return 3
	}
}

// bandScore maps a deviation band to a 0..100 anomaly score, monotonic in the band.
func bandScore(band int) riskassessment.Score {
	switch band {
	case 0:
		return 10
	case 1:
		return 35
	case 2:
		return 65
	default:
		return 90
	}
}

// Clone returns a deep copy (the arrays are values, so a struct copy is a full copy) — a safe seam for a
// persistence layer to hand out without aliasing internal state.
func (b *Baseline) Clone() *Baseline {
	cp := *b
	return &cp
}
