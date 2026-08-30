// Package baselineuc is the Phase D behavioral-baseline usecase (#594, D5 #738): it drives the pure-domain
// baseline lifecycle over a persistent store and produces the coverage-honest RiskContext.Behavior factor.
// It is the ONLY place a Behavior anomaly becomes a risk factor, and it stays a FACTOR: it never sets Risk
// or a disposition and never touches the Confidence axis. Learning is anti-poisoning-gated (it folds an
// observation only through the domain eligibility gate), and it is coverage-honest — a not-yet-trustworthy
// baseline abstains (Scoreable=false), which the caller routes to lower Coverage, never to fabricate Risk.
package baselineuc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Policy is the deterministic configuration of the baseline lifecycle. DriftScore/DriftThreshold are the
// drift-tracker config (service policy, not per-baseline state); MinObservations is the cold-start floor
// before a learning baseline may become active.
type Policy struct {
	MinObservations int64
	DriftScore      riskassessment.Score
	DriftThreshold  int
}

// DefaultPolicy is the shipped baseline policy.
func DefaultPolicy() Policy {
	return Policy{MinObservations: 30, DriftScore: baseline.DefaultDriftScore, DriftThreshold: baseline.DefaultDriftThreshold}
}

// Assessment is the outcome of observing one window: the Behavior factor for the risk scorer, whether it is
// trustworthy (Scoreable), the baseline's current state, and human reasons. Behavior is 0 whenever
// Scoreable is false — the caller places Behavior into RiskContext.Behavior ONLY when Scoreable, and
// otherwise reflects the gap in Coverage (never in Risk).
type Assessment struct {
	Behavior  riskassessment.Score
	Scoreable bool
	State     baseline.State
	Reasons   []string
}

// Service drives baselines over a store, auditing every lifecycle transition.
type Service struct {
	store  ports.BaselineStore
	audit  ports.AuditLogger
	now    func() time.Time
	policy Policy
}

// NewService constructs the baseline usecase. now supplies the persisted timestamp (injected for
// determinism). An invalid policy is rejected.
func NewService(store ports.BaselineStore, audit ports.AuditLogger, now func() time.Time, policy Policy) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: baseline service requires a store", shared.ErrValidation)
	}
	if audit == nil {
		return nil, fmt.Errorf("%w: baseline service requires an audit logger", shared.ErrValidation)
	}
	if now == nil {
		return nil, fmt.Errorf("%w: baseline service requires a clock", shared.ErrValidation)
	}
	if policy.MinObservations < 1 {
		return nil, fmt.Errorf("%w: policy MinObservations must be >= 1", shared.ErrValidation)
	}
	// Validate the drift config via the domain constructor (defaults zero fields, rejects out-of-range).
	if _, err := baseline.NewDriftTracker(policy.DriftScore, policy.DriftThreshold); err != nil {
		return nil, err
	}
	// Normalize the drift config to its EFFECTIVE (defaulted) values so the usecase's fold-gate uses the
	// same drift score the tracker does — otherwise a policy with DriftScore==0 would gate folding on
	// `anomaly >= 0` (always true) while the tracker used the default, silently disagreeing.
	if policy.DriftScore == 0 {
		policy.DriftScore = baseline.DefaultDriftScore
	}
	if policy.DriftThreshold == 0 {
		policy.DriftThreshold = baseline.DefaultDriftThreshold
	}
	return &Service{store: store, audit: audit, now: now, policy: policy}, nil
}

// Observe scores one window's observation against the entity/peer-group baseline and, if the window is
// eligible, folds it in to keep learning — advancing the lifecycle (cold-start -> active; sustained drift
// -> drifted). The returned Assessment carries the coverage-honest Behavior factor. The observation is
// SCORED against the CURRENT baseline BEFORE it is folded, so a window never scores against a baseline that
// already contains it.
func (s *Service) Observe(ctx context.Context, actor string, key baseline.Key, obs baseline.Observation, window baseline.LearnWindow) (Assessment, error) {
	if actor == "" {
		return Assessment{}, fmt.Errorf("%w: baseline observation requires an actor", shared.ErrValidation)
	}
	if err := key.Validate(); err != nil {
		return Assessment{}, err
	}
	if err := obs.Validate(); err != nil {
		return Assessment{}, err
	}

	b, dt, err := s.load(ctx, key)
	if err != nil {
		return Assessment{}, err
	}

	// 1) Score this observation against the current baseline (abstains unless active).
	anomaly, scoreable := b.Anomaly(obs)
	a := Assessment{State: b.State(), Behavior: 0}
	if scoreable {
		a.Behavior, a.Scoreable = anomaly, true
	} else {
		a.Reasons = append(a.Reasons, fmt.Sprintf("baseline not active (state=%s) — abstaining", b.State()))
	}

	// The single lifecycle transition (if any) this call makes; audited AFTER the durable save below.
	var pendingAudit string

	// 2) Drift: feed the anomaly to the tracker; on sustained drift, leave active for drifted.
	if scoreable && dt.Observe(anomaly) && b.State() == baseline.StateActive {
		if err := b.Transition(baseline.StateDrifted); err != nil {
			return Assessment{}, err
		}
		pendingAudit = "baseline.drifted"
		a.State = b.State()
		a.Reasons = append(a.Reasons, "sustained drift detected — re-baseline required")
	}

	// 3) Learn: fold through the eligibility gate, only while learning-capable and below the cap. An
	// observation that itself scores anomalous is NOT folded — absorbing it would let the baseline chase an
	// attacker's behavior (poisoning) or wash out genuine drift before the tracker can catch it; a real
	// change instead accumulates drift and re-baselines cleanly.
	if eligible, why := window.Eligible(); !eligible {
		a.Reasons = append(a.Reasons, "not learned: "+why)
	} else if scoreable && anomaly >= s.policy.DriftScore {
		a.Reasons = append(a.Reasons, "not learned: window is anomalous (possible drift or attack)")
	} else if !foldable(b.State()) {
		a.Reasons = append(a.Reasons, fmt.Sprintf("not learned: baseline is %s", b.State()))
	} else if b.ObservationCount() >= baseline.MaxObservations {
		a.Reasons = append(a.Reasons, "not learned: observation cap reached — re-baseline required")
	} else {
		if err := b.Fold(obs, window); err != nil {
			return Assessment{}, err
		}
		// 4) Cold-start complete: activate.
		if b.State() == baseline.StateLearning && b.ReadyToActivate(s.policy.MinObservations) {
			if err := b.Transition(baseline.StateActive); err != nil {
				return Assessment{}, err
			}
			pendingAudit = "baseline.activated"
			a.State = b.State()
		}
	}

	// Persist FIRST; the saved record carries the new state (the primary attributable change). Audit is a
	// secondary cross-cutting trail, so a lifecycle transition is audited only AFTER it is durable — a
	// failed save never leaves a false audit entry. On an audit-failure error the transition IS committed;
	// the caller must NOT blindly retry (Observe folds, so a retry double-counts) — treat it as
	// committed-but-unaudited and reconcile.
	if err := s.save(ctx, b, dt); err != nil {
		return Assessment{}, err
	}
	if pendingAudit != "" {
		if err := s.recordTransition(ctx, actor, key, pendingAudit); err != nil {
			return Assessment{}, err
		}
	}
	return a, nil
}

// Rebaseline drives a drifted/poisoned baseline through a clean re-baseline (reset_pending -> learning),
// zeroing its accumulators so it re-learns from fresh eligible windows. Audited.
func (s *Service) Rebaseline(ctx context.Context, actor string, key baseline.Key) error {
	if actor == "" {
		return fmt.Errorf("%w: re-baseline requires an actor", shared.ErrValidation)
	}
	b, dt, err := s.load(ctx, key)
	if err != nil {
		return err
	}
	switch b.State() {
	case baseline.StateDrifted, baseline.StatePoisoned:
		// eligible for re-baseline
	default:
		return fmt.Errorf("%w: baseline in state %s is not eligible for re-baseline", shared.ErrValidation, b.State())
	}
	if err := b.Transition(baseline.StateResetPending); err != nil {
		return err
	}
	if err := b.Transition(baseline.StateLearning); err != nil { // clears accumulators (domain reset)
		return err
	}
	dt.Reset()
	// Persist the clean re-baseline first, then audit (committed-but-unaudited on an audit error; do not
	// blindly retry).
	if err := s.save(ctx, b, dt); err != nil {
		return err
	}
	return s.recordTransition(ctx, actor, key, "baseline.rebaselined")
}

// load reads the persisted baseline + drift tracker, or fresh ones if none exists yet.
// Score evaluates an observation against the CURRENT baseline WITHOUT learning from it — a read-only
// anomaly for the risk scorer (#594 D). It abstains (Scoreable=false, Behavior=0) until the baseline is
// active, exactly like Observe's scoring step, but never folds or persists, so it is safe to call on the
// hot risk-assessment path (e.g. during an incident, when learning would poison the baseline anyway).
func (s *Service) Score(ctx context.Context, key baseline.Key, obs baseline.Observation) (Assessment, error) {
	if err := key.Validate(); err != nil {
		return Assessment{}, err
	}
	if err := obs.Validate(); err != nil {
		return Assessment{}, err
	}
	b, _, err := s.load(ctx, key)
	if err != nil {
		return Assessment{}, err
	}
	anomaly, scoreable := b.Anomaly(obs)
	a := Assessment{State: b.State(), Behavior: 0}
	if scoreable {
		a.Behavior, a.Scoreable = anomaly, true
	} else {
		a.Reasons = append(a.Reasons, fmt.Sprintf("baseline not active (state=%s) — abstaining", b.State()))
	}
	return a, nil
}

func (s *Service) load(ctx context.Context, key baseline.Key) (*baseline.Baseline, *baseline.DriftTracker, error) {
	rec, err := s.store.Load(ctx, key)
	if errors.Is(err, shared.ErrNotFound) {
		b, nerr := baseline.NewBaseline(key)
		if nerr != nil {
			return nil, nil, nerr
		}
		dt, derr := baseline.NewDriftTracker(s.policy.DriftScore, s.policy.DriftThreshold)
		if derr != nil {
			return nil, nil, derr
		}
		return b, dt, nil
	}
	if err != nil {
		return nil, nil, err
	}
	b, err := baseline.NewBaselineFrom(rec.Key, rec.State, rec.Summaries)
	if err != nil {
		return nil, nil, err
	}
	dt, err := baseline.NewDriftTrackerFrom(s.policy.DriftScore, s.policy.DriftThreshold, rec.DriftRun, rec.Drifted)
	if err != nil {
		return nil, nil, err
	}
	return b, dt, nil
}

// save persists the baseline + drift-tracker progress.
func (s *Service) save(ctx context.Context, b *baseline.Baseline, dt *baseline.DriftTracker) error {
	sum := b.Summary()
	return s.store.Save(ctx, ports.BaselineRecord{
		Key:       b.Key(),
		State:     b.State(),
		Summaries: append([]baseline.FeatureSummary(nil), sum[:]...),
		DriftRun:  dt.Run(),
		Drifted:   dt.Drifted(),
		UpdatedAt: s.now().UTC(),
	})
}

func (s *Service) recordTransition(ctx context.Context, actor string, key baseline.Key, action string) error {
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   action,
		Target:   key.Tenant.String() + "/" + key.Group,
		At:       s.now().UTC(),
		Metadata: map[string]string{"group": key.Group},
	}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}

// foldable reports whether the baseline may still learn in this state.
func foldable(st baseline.State) bool {
	switch st {
	case baseline.StateLearning, baseline.StateActive, baseline.StateStale:
		return true
	default:
		return false
	}
}
