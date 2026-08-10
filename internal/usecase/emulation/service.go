// Package emulation runs adversary emulation (issue #421) as a SUBSET of the exploitation machine's
// guarantees, never a looser path.
//
// Each technique is admitted through the very same StepAdmitter the exploitation chains use — which
// consults the #418 offensive policy — and executed through the same sandboxed StepExecutor. What
// differs is the goal: emulation prefers a benign proof of the observable over a real effect, and its
// output is a coverage record (executed, expected detection, actual detection, gap), the offensive half
// of the purple ledger #426 consumes.
package emulation

import (
	"context"
	"fmt"
	"sort"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	dexploit "github.com/KKloudTarus/synapse-ce/internal/domain/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RunStore persists an emulation run and its per-technique coverage records.
type RunStore interface {
	SaveRun(ctx context.Context, run demu.Run) error
}

// Service executes emulation runs. It holds the SAME admitter and executor types the exploitation
// machine uses, so there is no second, looser admission path — an emulation technique goes through the
// identical governance gate.
type Service struct {
	admit exploituc.StepAdmitter
	exec  exploituc.StepExecutor
	store RunStore
	audit ports.AuditLogger
	clock ports.Clock
	ids   ports.IDGenerator
}

// NewService validates its dependencies.
func NewService(admit exploituc.StepAdmitter, exec exploituc.StepExecutor, store RunStore, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if admit == nil || exec == nil || store == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: emulation service is missing a dependency", shared.ErrValidation)
	}
	return &Service{admit: admit, exec: exec, store: store, audit: audit, clock: clock, ids: ids}, nil
}

// Options controls a run.
type Options struct {
	// AllowLabOnly opts in to techniques that are not production-safe (no benign variant). Without it,
	// a non-production-safe technique is refused before admission and recorded not-executed — a lab-only
	// technique must never run against a customer estate by default.
	AllowLabOnly bool
}

// Emulate runs every catalogued technique against the target and returns the coverage run.
//
// A technique never omitted: whether it is refused (lab-only without opt-in, or refused by the policy)
// or executes, it produces a coverage record. Actual detection is left empty here — matching expected
// against actual completes once the #422 detection engine exists — so an executed technique is a gap,
// which is the honest "coverage unproven" state rather than an assumed-clean one.
func (s *Service) Emulate(ctx context.Context, tenantID, engagementID, target shared.ID, actor string, opts Options) (demu.Run, error) {
	techniques, err := demu.Catalogue()
	if err != nil {
		return demu.Run{}, fmt.Errorf("emulation catalogue is invalid: %w", err)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	run := demu.Run{ID: s.ids.NewID(), TenantID: tenantID, EngagementID: engagementID, Target: target, Actor: actor}

	for _, tech := range techniques {
		record := s.emulateOne(ctx, tenantID, engagementID, target, actor, tech, opts)
		run.Coverage = append(run.Coverage, record)
	}
	// Deterministic order so a coverage trend compares like with like.
	sort.Slice(run.Coverage, func(i, j int) bool { return run.Coverage[i].TechniqueID < run.Coverage[j].TechniqueID })

	if err := s.store.SaveRun(ctx, run); err != nil {
		return demu.Run{}, fmt.Errorf("save emulation run: %w", err)
	}
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: actor, Action: "emulation.run", Target: target.String(), At: s.clock.Now().UTC(),
		Metadata: map[string]string{"run": run.ID.String(), "engagement": engagementID.String(),
			"techniques": fmt.Sprint(len(run.Coverage)), "gaps": fmt.Sprint(countGaps(run.Coverage))},
	})
	return run, nil
}

// emulateOne governs and runs a single technique, returning its coverage record. It never returns an
// error: a refusal is a not-executed record, not a run-ending failure — one un-runnable technique must
// not blind the coverage measurement of the rest.
func (s *Service) emulateOne(ctx context.Context, tenantID, engagementID, target shared.ID, actor string, tech demu.Technique, opts Options) demu.CoverageRecord {
	// Lab-only gate: a technique with no benign variant is not production-safe and is refused without
	// the explicit opt-in, BEFORE it ever reaches admission.
	if !tech.ProductionSafe && !opts.AllowLabOnly {
		_ = s.audit.Record(ctx, s.techEntry("emulation.technique.refused_lab_only", tech, engagementID))
		return demu.NewCoverageRecord(tech, false, "")
	}

	// Build a governed step and admit it through the SAME admitter the exploitation chains use. An
	// emulation technique that is not in the offensive-policy register is refused here, exactly like an
	// exploitation step would be — emulation is not a looser path.
	step := s.stepFor(tech, target, actor)
	chain, err := dexploit.NewChain(s.ids.NewID(), tenantID, engagementID, "emulation", []dexploit.Step{step})
	if err != nil {
		_ = s.audit.Record(ctx, s.techEntry("emulation.technique.unconstructable", tech, engagementID))
		return demu.NewCoverageRecord(tech, false, "")
	}
	if err := s.admit.AdmitStep(ctx, chain, step); err != nil {
		_ = s.audit.Record(ctx, s.techEntry("emulation.technique.refused", tech, engagementID))
		return demu.NewCoverageRecord(tech, false, "")
	}

	// Execute through the sandboxed executor. A benign technique proves its observable without a real
	// effect; the executor reports whether the observable was produced.
	outcome, err := s.exec.Execute(ctx, chain, step)
	if err != nil || !outcome.Succeeded {
		_ = s.audit.Record(ctx, s.techEntry("emulation.technique.not_observed", tech, engagementID))
		return demu.NewCoverageRecord(tech, false, "")
	}
	// Executed. Actual detection is empty until the #422 engine exists, so this is a gap — recorded, not
	// omitted.
	_ = s.audit.Record(ctx, s.techEntry("emulation.technique.executed", tech, engagementID))
	return demu.NewCoverageRecord(tech, true, "")
}

// stepFor builds the exploitation step an emulation technique admits and executes as. Emulation prefers
// the benign, read-only shape: a production-safe technique runs read-only with no cleanup. A lab-only
// technique keeps its declared radius so its governance (dual approval, cleanup) still applies.
func (s *Service) stepFor(tech demu.Technique, target shared.ID, actor string) dexploit.Step {
	radius := offensivepolicy.RadiusReadOnly
	var cleanup offensivepolicy.CleanupSpec
	if !tech.ProductionSafe {
		radius = offensivepolicy.RadiusStateChanging
		cleanup = offensivepolicy.CleanupSpec{Steps: []string{"restore the emulated change"}, Verification: "confirm the target is restored"}
	}
	return dexploit.Step{Ordinal: 0, Technique: tech.ID, Target: target, Proposer: actor, BlastRadius: radius, Cleanup: cleanup}
}

func (s *Service) techEntry(action string, tech demu.Technique, engagementID shared.ID) ports.AuditEntry {
	return ports.AuditEntry{Action: action, Target: tech.ID, At: s.clock.Now().UTC(),
		Metadata: map[string]string{"engagement": engagementID.String(), "taxonomy": tech.TaxonomyRef, "expected_detection": tech.Expected.DetectionID}}
}

func countGaps(records []demu.CoverageRecord) int {
	n := 0
	for _, r := range records {
		if r.Gap {
			n++
		}
	}
	return n
}
