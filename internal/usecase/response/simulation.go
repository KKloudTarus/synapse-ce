package response

import (
	"context"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SimulationExecutor is an Executor that EXECUTES NOTHING on any host. It exists so the full governed
// response loop — admission gate → human approval → execute → telemetry-verified post-condition (#638) —
// can be wired and exercised end-to-end WITHOUT crossing the execution-safety boundary. It reports a
// benign, single-target, in-radius outcome so a simulated action records as cleanly applied; it never
// signals AlreadyApplied, so idempotency is exercised by the ledger, not faked here.
//
// A REAL host executor is DELIBERATELY not provided. Running argv on a live endpoint is a hard-to-reverse
// outward action (Golden Rule 1/4): it must go through the same argv-only sandbox as every other tool,
// and wiring it requires a distinct execution-safety review plus explicit operator authorization. Until
// then the simulation executor keeps the governed loop honest and testable without ever touching a host.
type SimulationExecutor struct{}

var _ Executor = SimulationExecutor{}

// Identity names the non-effecting simulation principal for verifier-separation checks.
func (SimulationExecutor) Identity() string { return "simulation:response-executor" }

// Supports keeps the non-effecting simulation path available for every catalogued response kind.
func (SimulationExecutor) Supports(kind rdom.Kind) bool {
	_, ok := rdom.SpecFor(kind)
	return ok
}

// ResolveAgent identifies the non-effecting simulation principal. A live executor resolves the enrolled
// fleet-agent identity authenticated by its transport adapter for the requested target.
func (SimulationExecutor) ResolveAgent(context.Context, shared.ID, responsesaga.TargetFingerprint) (shared.ID, error) {
	return "simulation-response-executor", nil
}

// Halt is a no-op because this executor has no side-effect boundary or active host work.
func (SimulationExecutor) Halt(context.Context, shared.ID, int64) error { return nil }

// Execute performs no host action. It echoes the declared radius as the observed radius (so the
// blast-radius guard sees no violation) and reports a single affected entity (the one declared target).
func (SimulationExecutor) Execute(_ context.Context, req ExecRequest) (ExecOutcome, error) {
	return ExecOutcome{
		ObservedRadius: req.Declared, AffectedCount: 1, AlreadyApplied: false,
		EnforcedHaltGeneration: req.HaltGeneration,
	}, nil
}
