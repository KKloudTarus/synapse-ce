// Package purpleteam orchestrates a governed adversary-emulation run and turns it into purple-team
// coverage. It is the producer the #426 coverage read side was missing: it runs the emulation technique
// catalogue against an engagement's target under that engagement's rules of engagement (through the same
// #418 offensive policy the exploitation chains use), then joins the run's expected detections against the
// detections that actually fired, and persists the coverage the dashboard reads.
//
// Emulation executes through a no-host SimulationExecutor: the governed flow (admission, blast-radius,
// evidence) runs end-to-end without touching a host, so the coverage measurement is honest and testable.
// A real host executor stays a deliberate, review-gated extension point.
package purpleteam

import (
	"context"
	"fmt"
	"time"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	emulationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/emulation"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	purplecoverageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/purplecoverage"
)

// governanceAuthorizer is the offensive policy the per-step admitter authorizes against.
type governanceAuthorizer interface {
	Authorize(ctx context.Context, req offensivepolicyuc.Request) (offensivepolicyuc.Decision, error)
}

// EngagementReader loads an engagement so its rules of engagement can gate the run. Tenant-scoped.
type EngagementReader interface {
	GetByIDInTenant(ctx context.Context, tenantID, id shared.ID) (*engagement.Engagement, error)
}

// coverageComputer is the purple-coverage producer half.
type coverageComputer interface {
	Compute(ctx context.Context, run demu.Run, window purplecoverageuc.Window) (purplecoverageuc.Result, error)
}

// Service runs governed emulation and computes purple coverage. The offensive governance service, the
// no-host executor, the run store, the coverage computer, and the clock/ids are shared; the per-step
// admitter is built per run from the engagement's rules of engagement.
type Service struct {
	engagements EngagementReader
	gov         governanceAuthorizer
	exec        exploituc.StepExecutor
	runs        emulationuc.RunStore
	coverage    coverageComputer
	audit       ports.AuditLogger
	clock       ports.Clock
	ids         ports.IDGenerator
}

// NewService validates dependencies.
func NewService(engagements EngagementReader, gov governanceAuthorizer, exec exploituc.StepExecutor, runs emulationuc.RunStore, coverage coverageComputer, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if engagements == nil || gov == nil || exec == nil || runs == nil || coverage == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: purple-team service is missing a dependency", shared.ErrValidation)
	}
	return &Service{engagements: engagements, gov: gov, exec: exec, runs: runs, coverage: coverage, audit: audit, clock: clock, ids: ids}, nil
}

// Result is one emulation run and the purple coverage it produced.
type Result struct {
	Run      demu.Run                `json:"run"`
	Coverage purplecoverageuc.Result `json:"coverage"`
}

// coverageSettle is a small forward margin so a detection the run causes, observed a moment after the step
// returns, still lands inside the window. The window NEVER extends backward before the run start: a
// detection that fired before the run cannot have been caused by it, and counting it would falsely mark a
// technique covered, which is exactly the false-covered #426 exists to prevent.
const coverageSettle = 30 * time.Second

// RunEmulation runs the governed technique catalogue against target for the engagement, then computes and
// persists the purple coverage. It is tenant-scoped; a technique the engagement's rules of engagement do
// not permit is refused by the offensive policy and recorded as not executed (verdict unknown), never a
// silent success. Only production-safe, automatically-approvable techniques run here: the admitter is built
// with no recorded approvals, so a technique needing human sign-off is always refused. Lab-only techniques
// therefore stay unreachable until an approvals source is wired, which is a separate governance change.
func (s *Service) RunEmulation(ctx context.Context, tenantID, engagementID, target shared.ID, actor string) (Result, error) {
	if actor == "" {
		return Result{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if target.IsZero() {
		return Result{}, fmt.Errorf("%w: a target asset is required to attribute coverage", shared.ErrValidation)
	}
	tctx := shared.WithTenant(ctx, tenantID)
	eng, err := s.engagements.GetByIDInTenant(tctx, tenantID, engagementID)
	if err != nil {
		return Result{}, err
	}
	roe := offensivepolicyuc.RoEFromEngagement(*eng)
	admitter := exploituc.NewPolicyStepAdmitter(s.gov, roe, nil, func() time.Time { return s.clock.Now().UTC() })
	emu, err := emulationuc.NewService(admitter, s.exec, s.runs, s.audit, s.clock, s.ids)
	if err != nil {
		return Result{}, fmt.Errorf("build emulation service: %w", err)
	}
	start := s.clock.Now().UTC()
	// Lab-only techniques are not admitted here: they require human approval and the admitter carries none,
	// so opting them past the pre-check would only get them refused at admission. Keep the run to the
	// production-safe set.
	run, err := emu.Emulate(tctx, tenantID, engagementID, target, actor, emulationuc.Options{AllowLabOnly: false})
	if err != nil {
		return Result{}, fmt.Errorf("run emulation: %w", err)
	}
	window := purplecoverageuc.Window{From: start, To: s.clock.Now().UTC().Add(coverageSettle)}
	cov, err := s.coverage.Compute(tctx, run, window)
	if err != nil {
		return Result{}, fmt.Errorf("compute purple coverage: %w", err)
	}
	_ = s.audit.Record(tctx, ports.AuditEntry{Actor: actor, Action: "purpleteam.emulation_run", Target: engagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"run": run.ID.String(), "techniques": fmt.Sprint(len(run.Coverage))}})
	return Result{Run: run, Coverage: cov}, nil
}
