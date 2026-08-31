package response

import "context"

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

// Execute performs no host action. It echoes the declared radius as the observed radius (so the
// blast-radius guard sees no violation) and reports a single affected entity (the one declared target).
func (SimulationExecutor) Execute(_ context.Context, req ExecRequest) (ExecOutcome, error) {
	return ExecOutcome{ObservedRadius: req.Declared, AffectedCount: 1, AlreadyApplied: false}, nil
}
