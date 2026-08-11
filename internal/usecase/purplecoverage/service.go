// Package purplecoverage is the control plane that closes the purple loop (#426): it joins the offensive
// half of the ledger (an emulation.Run's per-technique coverage records — what each technique executed and
// EXPECTED to be detected, #421) with the defensive half (the detections that ACTUALLY fired on the same
// asset in the run window, #422/#423) and resolves a per-technique coverage verdict through the pure
// domain. Coverage is measured from the two independent halves, never claimed.
//
// The join and the verdict order (out_of_reach → unknown → covered → gap) live in the domain; this
// package supplies the two halves, persists the result tenant-scoped, and audits the computation. It is
// the same honest deferral as the rest of the blue-team pillar: the compute + store are real; the
// scheduler that triggers a run and streams its window is wired at the composition root later.
package purplecoverage

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service computes and serves purple coverage.
type Service struct {
	store      ports.PurpleCoverageStore
	detections ports.DetectionRecordStore
	audit      ports.AuditLogger
	clock      ports.Clock
}

// NewService validates its dependencies. All are required: without the detection ledger there is no
// defensive half to join against, and without the audit log a coverage computation would not be
// attributable.
func NewService(store ports.PurpleCoverageStore, detections ports.DetectionRecordStore, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if store == nil || detections == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: purple-coverage service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, detections: detections, audit: audit, clock: clock}, nil
}

// Window is the observation window a run's detections are joined over. It is explicit because an
// emulation.Run carries no timestamps: the caller (the scheduler that ran the emulation) owns when the
// run started and ended, and only detections observed inside [From,To] on the run's asset can count as
// coverage for that run. A detection outside the window is a different event, not this run's coverage.
type Window struct {
	From time.Time
	To   time.Time
}

// bounded reports whether the window is fully specified. Compute REQUIRES a bounded window: an
// unbounded window would join all-time detections for the engagement, so a detection from an unrelated
// or earlier run could mark this run's technique covered — a false-covered, exactly what #426 exists to
// prevent. A bounded window is the honest join key.
func (w Window) bounded() bool {
	return !w.From.IsZero() && !w.To.IsZero() && !w.To.Before(w.From)
}

func (w Window) contains(t time.Time) bool {
	return !t.Before(w.From) && !t.After(w.To)
}

// Result is one computation's honest outcome: the stored per-technique coverage, the bonus detections
// (fired but expected by no technique — reported, never hidden or counted as coverage), and the work
// items (one per gap).
type Result struct {
	Coverage []purplecoverage.Coverage
	Bonus    []string
	Gaps     []purplecoverage.WorkItem
}

// Compute joins an emulation run with the detections that fired on its asset in the window, resolves a
// verdict per technique, persists the coverage tenant-scoped, and audits the computation. The run's
// tenant/engagement must match the authenticated tenant on the context (fail closed) so a run cannot be
// scored into another tenant's ledger.
//
// Every technique in the run is emulatable by construction (it was in the catalogue and produced a
// record); out_of_reach is a domain verdict reserved for techniques the platform cannot emulate, which a
// run does not carry — so a run resolves only to covered/gap/unknown, and a non-executed technique is
// unknown, never a gap.
func (s *Service) Compute(ctx context.Context, run emulation.Run, window Window) (Result, error) {
	if run.EngagementID == "" || run.ID == "" {
		return Result{}, fmt.Errorf("%w: run is missing engagement/run scope", shared.ErrValidation)
	}
	// A run must name the asset it ran against: without it the join would count detections on ANY asset
	// in the engagement toward every technique — a cross-asset false-covered. Fail closed.
	if run.Target == "" {
		return Result{}, fmt.Errorf("%w: run has no target asset; coverage cannot be attributed to an asset", shared.ErrValidation)
	}
	// A bounded window is mandatory (see Window.bounded): an all-time join is a false-covered risk.
	if !window.bounded() {
		return Result{}, fmt.Errorf("%w: coverage needs a bounded observation window (from <= to, both set)", shared.ErrValidation)
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return Result{}, fmt.Errorf("%w: purple coverage requires a tenant in context", shared.ErrValidation)
	}
	if run.TenantID != "" && run.TenantID != tenant {
		return Result{}, fmt.Errorf("%w: run tenant %q does not match the authenticated tenant", shared.ErrForbidden, run.TenantID)
	}

	// Defensive half: the detections that actually fired for this engagement, filtered to the run's asset
	// and window. The store is tenant-scoped, so this can only see the authenticated tenant's ledger.
	records, err := s.detections.ListDetections(ctx, run.EngagementID)
	if err != nil {
		return Result{}, fmt.Errorf("load detections for %s: %w", run.EngagementID, err)
	}
	var actual []string
	for _, r := range records {
		if run.Target != "" && r.AssetID != run.Target {
			continue
		}
		if !window.contains(r.Detection.Observed) {
			continue
		}
		actual = append(actual, r.Detection.RuleID)
	}

	now := s.clock.Now().UTC()
	inputs := make([]purplecoverage.Input, 0, len(run.Coverage))
	coverage := make([]purplecoverage.Coverage, 0, len(run.Coverage))
	for _, rec := range run.Coverage {
		in := purplecoverage.Input{
			TechniqueID: rec.TechniqueID,
			TaxonomyRef: rec.TaxonomyRef,
			Expected:    rec.Expected,
			Emulatable:  true, // a run only carries techniques the platform emulated
			Executed:    rec.Executed,
			Actual:      actual,
		}
		inputs = append(inputs, in)
		c := purplecoverage.Coverage{
			TenantID:     tenant,
			EngagementID: run.EngagementID,
			RunID:        run.ID,
			AssetID:      run.Target,
			TechniqueID:  rec.TechniqueID,
			TaxonomyRef:  rec.TaxonomyRef,
			Expected:     rec.Expected,
			Actual:       actual,
			Verdict:      purplecoverage.Resolve(in),
			ComputedAt:   now,
		}
		if err := c.Validate(); err != nil {
			return Result{}, fmt.Errorf("coverage for %s: %w", rec.TechniqueID, err)
		}
		coverage = append(coverage, c)
	}

	res := Result{
		Coverage: coverage,
		Bonus:    purplecoverage.BonusDetections(inputs, actual),
		Gaps:     purplecoverage.WorkItems(coverage),
	}

	// Audit BEFORE persisting: the invariant is that no coverage row exists without an attributing audit
	// entry. If the audit write fails, nothing is stored, so a query can never surface an unattributable
	// coverage record. (The reverse order would leave rows queryable via Trend/WorkItems the instant the
	// audit failed.) The entry carries who/when and the honest headline numbers (gaps and bonus) so a
	// coverage claim can always be traced back to the run it was measured from.
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  run.Actor,
		Action: "purple.coverage_computed",
		Target: run.EngagementID.String(),
		At:     now,
		Metadata: map[string]string{
			"run":        run.ID.String(),
			"asset":      run.Target.String(),
			"techniques": fmt.Sprint(len(coverage)),
			"gaps":       fmt.Sprint(len(res.Gaps)),
			"bonus":      fmt.Sprint(len(res.Bonus)),
		},
	}); err != nil {
		return Result{}, fmt.Errorf("coverage computed but could not be audited (run=%s): %w", run.ID, err)
	}

	if err := s.store.SaveCoverage(ctx, coverage); err != nil {
		return Result{}, fmt.Errorf("save coverage for run %s: %w", run.ID, err)
	}

	return res, nil
}

// Trend returns an engagement's coverage across runs, oldest first, so a defender can see coverage
// improve (or regress) over time. Tenant-scoped through the store.
func (s *Service) Trend(ctx context.Context, engagementID shared.ID) ([]purplecoverage.Coverage, error) {
	if engagementID == "" {
		return nil, fmt.Errorf("%w: trend needs an engagement id", shared.ErrValidation)
	}
	cov, err := s.store.ListByEngagement(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("coverage trend for %s: %w", engagementID, err)
	}
	return cov, nil
}

// Regressions compares two runs' coverage and returns the techniques that went from covered to
// uncovered — a detection regression. Both runs are loaded tenant-scoped.
func (s *Service) Regressions(ctx context.Context, prevRun, currRun shared.ID) ([]purplecoverage.Regression, error) {
	if prevRun == "" || currRun == "" {
		return nil, fmt.Errorf("%w: regression needs two run ids", shared.ErrValidation)
	}
	prev, err := s.store.ListByRun(ctx, prevRun)
	if err != nil {
		return nil, fmt.Errorf("load prev run %s: %w", prevRun, err)
	}
	curr, err := s.store.ListByRun(ctx, currRun)
	if err != nil {
		return nil, fmt.Errorf("load curr run %s: %w", currRun, err)
	}
	return purplecoverage.Regressions(prev, curr), nil
}

// WorkItems returns one actionable item per gap in a run (the missing detection a human must write). It
// reads the stored coverage so it reflects what was measured, not a recomputation.
//
// The run is bound to engagementID: ListByRun is only tenant-scoped, so a run id belonging to a
// DIFFERENT engagement in the same tenant would otherwise be readable through an engagement the caller is
// authorized for. Any record whose EngagementID does not match is dropped, so a mismatched run resolves
// to no work items rather than leaking another engagement's gaps.
func (s *Service) WorkItems(ctx context.Context, engagementID, runID shared.ID) ([]purplecoverage.WorkItem, error) {
	if engagementID == "" || runID == "" {
		return nil, fmt.Errorf("%w: work items need an engagement id and a run id", shared.ErrValidation)
	}
	cov, err := s.store.ListByRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("load run %s: %w", runID, err)
	}
	bound := cov[:0]
	for _, c := range cov {
		if c.EngagementID == engagementID {
			bound = append(bound, c)
		}
	}
	return purplecoverage.WorkItems(bound), nil
}
