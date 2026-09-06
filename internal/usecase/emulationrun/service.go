// Package emulationrun orchestrates a governed adversary-emulation run for one engagement (#421/#823).
// It resolves the engagement's offensive rules of engagement, admits every technique through the SAME
// #418 offensive governance the exploitation chains use, executes each benign observable through the
// sandboxed step executor, persists the run, and computes purple coverage against the detections the
// host actually produced in the run window (#426). No offensive action runs outside a complete RoE and
// the authorization window, both derived here from authoritative engagement state.
package emulationrun

import (
	"context"
	"fmt"
	"strings"
	"time"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	pcovdom "github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	emuc "github.com/KKloudTarus/synapse-ce/internal/usecase/emulation"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/purplecoverage"
)

// defaultCoverageGrace pads each side of the run's own execution span when joining detections. The join
// window is anchored to the run (start .. end), not a floating lookback from "now": a wide lookback would
// count an unrelated detection that fired before the run as coverage. The grace only absorbs clock skew
// between the control plane and the reporting host and a little detection-ingest latency.
const defaultCoverageGrace = 2 * time.Minute

// EngagementReader loads authoritative engagement state (scope, window, offensive RoE), tenant-scoped.
type EngagementReader interface {
	Get(ctx context.Context, tenantID, id shared.ID) (*engagement.Engagement, error)
}

// Governance authorizes one offensive technique against the offensive policy. *offensivepolicyuc.Service
// satisfies it; the emulation admitter consults it per technique, exactly like an exploitation step.
type Governance interface {
	Authorize(ctx context.Context, req offensivepolicyuc.Request) (offensivepolicyuc.Decision, error)
}

// Coverage joins an emulation run with the detections observed on its asset and persists the result.
// *purplecoverage.Service satisfies it.
type Coverage interface {
	Compute(ctx context.Context, run demu.Run, window purplecoverage.Window) (purplecoverage.Result, error)
}

// Service runs a governed emulation and computes its coverage.
type Service struct {
	engagements EngagementReader
	gov         Governance
	exec        exploituc.StepExecutor
	runs        emuc.RunStore
	coverage    Coverage
	audit       ports.AuditLogger
	clock       ports.Clock
	ids         ports.IDGenerator
	window      time.Duration
}

// NewService validates its dependencies. window <= 0 uses the default coverage window.
func NewService(engagements EngagementReader, gov Governance, exec exploituc.StepExecutor, runs emuc.RunStore, coverage Coverage, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator, window time.Duration) (*Service, error) {
	if engagements == nil || gov == nil || exec == nil || runs == nil || coverage == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: emulation run service is missing a dependency", shared.ErrValidation)
	}
	if window <= 0 {
		window = defaultCoverageGrace
	}
	return &Service{engagements: engagements, gov: gov, exec: exec, runs: runs, coverage: coverage, audit: audit, clock: clock, ids: ids, window: window}, nil
}

// Summary is the outcome the caller reports: the run id, how many techniques executed, and the coverage
// breakdown after the detection join.
type Summary struct {
	RunID        string `json:"run_id"`
	EngagementID string `json:"engagement_id"`
	Target       string `json:"target"`
	Techniques   int    `json:"techniques"`
	Executed     int    `json:"executed"`
	Gaps         int    `json:"gaps"`
	Covered      int    `json:"covered"`
}

// Run authorizes and executes every catalogued emulation technique against target, then computes and
// persists the purple coverage for the run. target is the asset the run is attributed to (coverage is
// per-asset). allowLab opts in to lab-only techniques that have no benign proof.
func (s *Service) Run(ctx context.Context, engagementID, target shared.ID, actor string, allowLab bool) (Summary, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant == "" {
		return Summary{}, fmt.Errorf("%w: emulation run requires a tenant in context", shared.ErrValidation)
	}
	if engagementID == "" || target == "" {
		return Summary{}, fmt.Errorf("%w: emulation run needs an engagement and a target asset", shared.ErrValidation)
	}
	e, err := s.engagements.Get(ctx, tenant, engagementID)
	if err != nil {
		return Summary{}, fmt.Errorf("load engagement: %w", err)
	}
	// Lifecycle gate: the offensive policy checks the authorization window but not the engagement's
	// status, so a completed or archived engagement (assessment officially over) would still admit a run
	// until its window lapsed. Refuse it here, matching the execution guard every other tool path uses.
	if !e.AllowsExecution() {
		return Summary{}, fmt.Errorf("%w: engagement %s is %s and cannot run offensive actions", shared.ErrForbidden, engagementID, e.Status)
	}
	// Scope membership: the offensive policy checks only that a scope EXISTS, not that the target is in
	// it, so without this a run could be attributed to an out-of-scope (or foreign, same-tenant) asset.
	// Scope.Allows is the value-based, out-of-scope-wins check every other tool path enforces.
	if !e.Scope.Allows(target.String()) {
		return Summary{}, fmt.Errorf("%w: target %s is not within the engagement scope", shared.ErrForbidden, target)
	}
	// Enforce the offensive excluded-assets list against the run target. The policy gate records the
	// list but never tests membership, so without this the exclusion an operator entered would be
	// advisory only and the run could be attributed to an explicitly excluded asset.
	for _, ex := range e.RoE.Offensive.ExcludedAssets {
		if strings.TrimSpace(ex) == target.String() {
			return Summary{}, fmt.Errorf("%w: target %s is on the engagement's offensive excluded-assets list", shared.ErrForbidden, target)
		}
	}
	roe := rulesOfEngagement(e)
	admitter := exploituc.NewPolicyStepAdmitter(s.gov, roe, nil, s.clock.Now)
	emu, err := emuc.NewService(admitter, s.exec, s.runs, s.audit, s.clock, s.ids)
	if err != nil {
		return Summary{}, fmt.Errorf("build emulation service: %w", err)
	}
	start := s.clock.Now().UTC()
	run, err := emu.Emulate(ctx, tenant, engagementID, target, actor, emuc.Options{AllowLabOnly: allowLab})
	if err != nil {
		return Summary{}, fmt.Errorf("run emulation: %w", err)
	}
	// Anchor the detection-join window to the run's own execution span, padded by the grace, rather than
	// a fixed lookback from now: a lookback would count a detection that fired before the run started as
	// coverage for this run.
	end := s.clock.Now().UTC()
	result, err := s.coverage.Compute(ctx, run, purplecoverage.Window{From: start.Add(-s.window), To: end.Add(s.window)})
	if err != nil {
		return Summary{}, fmt.Errorf("compute coverage: %w", err)
	}
	// The Summary reports the coverage AFTER the detection join, so it is built from the resolved
	// verdicts, not from run.Coverage (whose actual-detection is empty until the join runs). Reading the
	// pre-join records would report every executed technique as a gap regardless of what fired.
	return summarize(run, result), nil
}

// rulesOfEngagement maps authoritative engagement state to the offensive RoE the governance gate checks:
// the in-scope targets, the authorization window, and the offensive contacts / risk ceiling / reviewed
// exclusions. A missing field leaves the gate refusing, which is the fail-closed default.
func rulesOfEngagement(e *engagement.Engagement) offensivepolicyuc.RulesOfEngagement {
	scope := make([]string, 0, len(e.Scope.InScope))
	for _, t := range e.Scope.InScope {
		scope = append(scope, t.Value)
	}
	var start, end time.Time
	if e.AuthorizedFrom != nil {
		start = *e.AuthorizedFrom
	}
	if e.AuthorizedTo != nil {
		end = *e.AuthorizedTo
	}
	o := e.RoE.Offensive
	return offensivepolicyuc.RulesOfEngagement{
		AuthorizedScope:   scope,
		WindowStart:       start,
		WindowEnd:         end,
		CustomerContact:   o.CustomerContact,
		EmergencyContact:  o.EmergencyContact,
		RiskCeiling:       o.RiskCeiling,
		ExcludedAssets:    o.ExcludedAssets,
		ExclusionsChecked: o.ExclusionsReviewed,
	}
}

// summarize builds the response from the resolved coverage verdicts. covered and gap both mean the
// technique executed; unknown means it was emulatable but did not run this time (refused or not
// executed). Techniques counts every technique the run evaluated.
func summarize(run demu.Run, result purplecoverage.Result) Summary {
	var executed, gaps, covered int
	for _, c := range result.Coverage {
		switch c.Verdict {
		case pcovdom.VerdictCovered:
			covered++
			executed++
		case pcovdom.VerdictGap:
			gaps++
			executed++
		}
	}
	return Summary{
		RunID: run.ID.String(), EngagementID: run.EngagementID.String(), Target: run.Target.String(),
		Techniques: len(run.Coverage), Executed: executed, Gaps: gaps, Covered: covered,
	}
}
