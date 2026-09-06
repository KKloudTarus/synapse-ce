// Package chainrehearsal drives a governed exploitation chain as a no-host SIMULATION. The exploitation
// Machine (admission per the engagement's rules of engagement, per-step sealed evidence, a distinct
// verifier, cleanup obligations, and the kill switch) existed and was tested, but nothing constructed it
// outside tests, so the kill-switch registry was wired to chains that never ran and the "chained
// exploitation" capability was unreachable.
//
// This rehearses an operator-declared chain through the SAME governance the rest of the offensive pillar
// uses, executing each step with the no-host SimulationExecutor and verifying it with a distinct system
// verifier. The result is a governed, evidence-sealed SIMULATION that proves the chain is policy-admissible
// and its custody chain is sound; it is NOT a claim of real compromise. A real host executor and an
// independent verifier are the deliberate, review-gated extension point.
package chainrehearsal

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	dexploit "github.com/KKloudTarus/synapse-ce/internal/domain/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaxRehearsalSteps caps a rehearsal chain. The Machine re-persists the whole chain on each step
// transition (O(steps) writes per step, so O(steps^2) for the run), so an unbounded chain would let one
// authenticated request saturate the control plane's writes. A real attack chain is short; this ceiling is
// far above any legitimate rehearsal.
const MaxRehearsalSteps = 64

// EngagementReader loads an engagement so its rules of engagement gate the chain. Tenant-scoped.
type EngagementReader interface {
	GetByIDInTenant(ctx context.Context, tenantID, id shared.ID) (*engagement.Engagement, error)
}

// governanceAuthorizer is the offensive policy each step is admitted through.
type governanceAuthorizer interface {
	Authorize(ctx context.Context, req offensivepolicyuc.Request) (offensivepolicyuc.Decision, error)
}

// evidenceSealer seals one step's proof and returns its evidence id. The cmd root adapts the evidence
// service (which returns a full Evidence) to this shape.
type evidenceSealer interface {
	Seal(ctx context.Context, engagementID shared.ID, kind string, content []byte, createdBy string) (shared.ID, error)
}

// SealerFunc adapts a seal closure to the evidenceSealer the rehearsal (and the Machine) needs, so the
// composition root can pass the evidence service's Seal without a bespoke adapter type.
type SealerFunc func(ctx context.Context, engagementID shared.ID, kind string, content []byte, createdBy string) (shared.ID, error)

// Seal calls the wrapped function.
func (f SealerFunc) Seal(ctx context.Context, engagementID shared.ID, kind string, content []byte, createdBy string) (shared.ID, error) {
	return f(ctx, engagementID, kind, content, createdBy)
}

// StepSpec is one operator-declared step of a rehearsal chain. A state-changing step must carry a cleanup
// path (the domain enforces this at construction); a read-only step must not.
type StepSpec struct {
	Technique           string    `json:"technique"`
	Target              shared.ID `json:"target"`
	BlastRadius         string    `json:"blast_radius"` // read_only | state_changing
	Cleanup             []string  `json:"cleanup"`
	CleanupVerification string    `json:"cleanup_verification"`
}

// Service rehearses exploitation chains. The governance, registry, store, and sealer are shared; the
// per-step admitter is built per chain from the engagement's rules of engagement.
type Service struct {
	engagements EngagementReader
	gov         governanceAuthorizer
	register    *offensivepolicy.Register
	registry    *exploituc.ChainRegistry
	store       exploituc.ChainStore
	sealer      evidenceSealer
	audit       ports.AuditLogger
	clock       ports.Clock
	ids         ports.IDGenerator
}

// NewService validates dependencies. register is the offensive-policy register, used to reconcile a step's
// declared blast radius against the authoritative classification before the chain runs.
func NewService(engagements EngagementReader, gov governanceAuthorizer, register *offensivepolicy.Register, registry *exploituc.ChainRegistry, store exploituc.ChainStore, sealer evidenceSealer, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if engagements == nil || gov == nil || register == nil || registry == nil || store == nil || sealer == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: chain-rehearsal service is missing a dependency", shared.ErrValidation)
	}
	return &Service{engagements: engagements, gov: gov, register: register, registry: registry, store: store, sealer: sealer, audit: audit, clock: clock, ids: ids}, nil
}

// Result is a completed rehearsal: the final chain state and how many steps it carried. Simulated is
// always true; a rehearsal never touches a host.
type Result struct {
	ChainID   string `json:"chain_id"`
	State     string `json:"state"`
	Steps     int    `json:"steps"`
	Simulated bool   `json:"simulated"`
}

// RunChain rehearses the operator-declared chain against the engagement, tenant-scoped. Each step is
// admitted through the engagement's rules of engagement, so a step the policy refuses halts the chain and
// its cleanup runs, exactly as a real chain would; the difference is only that no host is touched.
func (s *Service) RunChain(ctx context.Context, tenantID, engagementID shared.ID, actor string, specs []StepSpec) (Result, error) {
	if actor == "" {
		return Result{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	if len(specs) == 0 {
		return Result{}, fmt.Errorf("%w: a rehearsal needs at least one step", shared.ErrValidation)
	}
	// Bound the chain length: the Machine persists the whole chain on each step transition, so an
	// unbounded chain would let one authenticated request drive quadratic write load on the control plane.
	if len(specs) > MaxRehearsalSteps {
		return Result{}, fmt.Errorf("%w: a rehearsal is limited to %d steps, got %d", shared.ErrValidation, MaxRehearsalSteps, len(specs))
	}
	tctx := shared.WithTenant(ctx, tenantID)
	eng, err := s.engagements.GetByIDInTenant(tctx, tenantID, engagementID)
	if err != nil {
		return Result{}, err
	}
	roe := offensivepolicyuc.RoEFromEngagement(*eng)
	admit := exploituc.NewPolicyStepAdmitter(s.gov, roe, nil, func() time.Time { return s.clock.Now().UTC() })

	steps := make([]dexploit.Step, len(specs))
	for i, sp := range specs {
		declared := offensivepolicy.Radius(sp.BlastRadius)
		// The register is authoritative on a technique's blast radius. Refuse a declaration that disagrees,
		// so a state-changing technique cannot be rehearsed as read-only (which would skip its cleanup
		// obligation) or vice versa. A technique absent from the register is left to admission to refuse.
		if p, ok := s.register.Lookup(sp.Technique); ok && p.BlastRadius != declared {
			return Result{}, fmt.Errorf("%w: step %d technique %q is classified %q by policy, not the declared %q", shared.ErrValidation, i, sp.Technique, p.BlastRadius, declared)
		}
		// Build the cleanup from the request unconditionally and let the domain enforce the invariant: a
		// read-only step must carry NO cleanup, a state-changing step MUST carry one. Zeroing it for a
		// read-only step (as an earlier version did) silently accepted an inconsistent step.
		cleanup := offensivepolicy.CleanupSpec{Steps: sp.Cleanup, Verification: sp.CleanupVerification}
		steps[i] = dexploit.Step{Ordinal: i, Technique: sp.Technique, Target: sp.Target, Proposer: actor, BlastRadius: declared, Cleanup: cleanup}
	}
	chain, err := dexploit.NewChain(s.ids.NewID(), tenantID, engagementID, "", steps)
	if err != nil {
		return Result{}, err
	}
	m, err := exploituc.NewMachine(chain, admit, exploituc.SimulationExecutor{}, exploituc.SimulationStepVerifier{}, exploituc.SimulationCleanupRunner{}, s.sealer, s.store, s.audit, s.clock)
	if err != nil {
		return Result{}, fmt.Errorf("build rehearsal machine: %w", err)
	}
	// RunTracked registers the machine so the offensive kill switch can halt it while it runs.
	state, err := s.registry.RunTracked(tctx, m)
	if err != nil {
		return Result{}, fmt.Errorf("rehearse chain: %w", err)
	}
	_ = s.audit.Record(tctx, ports.AuditEntry{Actor: actor, Action: "exploitation.chain.rehearsed", Target: engagementID.String(), At: s.clock.Now().UTC(), Metadata: map[string]string{"chain": chain.ID.String(), "state": string(state), "steps": fmt.Sprint(len(steps)), "simulated": "true"}})
	return Result{ChainID: chain.ID.String(), State: string(state), Steps: len(steps), Simulated: true}, nil
}
