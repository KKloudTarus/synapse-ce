package orchestrator

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RunRegistry tracks the agent runs executing IN THIS PROCESS so the offensive kill switch can reach
// them.
//
// The kill switch cancels queued and claimed work orders and, through the chain registry, exploitation
// chains running in memory. An LLM agent run was neither: it holds no work order and it is not a chain,
// so an operator who pulled the switch mid-run stopped everything except the one thing that was
// actively deciding what to do next. The budget caps and the approval gate bound that run, but bounding
// is not halting, and a kill switch that does less than the operator believes is the failure this
// contract cannot have.
//
// A registered run is cancelled by cancelling its context. The loop notices at its next boundary: the
// in-flight provider call returns, and the run ends before it can propose or execute another action.
// That is the meaningful guarantee, because the dangerous step is always the next one.
//
// Scope honesty, in the same terms the chain registry uses. This registry covers the process it lives
// in. In a single-process control plane that is the whole estate. Under horizontal scale a run lives on
// one node and a fleet-wide halt has to fan out to every node's registry; this type does not pretend to
// solve that and never claims to reach a run in another process.
type RunRegistry struct {
	mu      sync.Mutex
	running map[shared.ID]map[shared.ID]context.CancelFunc // tenant -> session -> cancel
}

// NewRunRegistry constructs an empty registry.
func NewRunRegistry() *RunRegistry {
	return &RunRegistry{running: map[shared.ID]map[shared.ID]context.CancelFunc{}}
}

// Track derives a cancellable context for one session's run and registers it. The returned release
// function unregisters and cancels; call it with defer so a run is haltable for exactly as long as it
// runs and never leaks into the registry afterwards.
func (r *RunRegistry) Track(ctx context.Context, sessionID shared.ID) (context.Context, func()) {
	if r == nil {
		return ctx, func() {}
	}
	tenant, _ := shared.TenantFrom(ctx)
	tenant = shared.TenantOrDefault(tenant)
	runCtx, cancel := context.WithCancel(ctx)

	r.mu.Lock()
	if r.running[tenant] == nil {
		r.running[tenant] = map[shared.ID]context.CancelFunc{}
	}
	r.running[tenant][sessionID] = cancel
	r.mu.Unlock()

	return runCtx, func() {
		r.mu.Lock()
		if set := r.running[tenant]; set != nil {
			delete(set, sessionID)
			if len(set) == 0 {
				delete(r.running, tenant)
			}
		}
		r.mu.Unlock()
		cancel()
	}
}

// HaltAgents cancels every agent run this process is executing for the tenant and reports how many it
// reached. It implements offensivepolicy.AgentHalter.
//
// The registry entries are left in place: each run's own release removes its entry as it unwinds, which
// keeps the "registered for exactly as long as it runs" invariant true whether the run ended normally or
// was halted.
func (r *RunRegistry) HaltAgents(_ context.Context, tenantID shared.ID, _, _ string) (int, error) {
	if r == nil {
		return 0, nil
	}
	tenant := shared.TenantOrDefault(tenantID)
	r.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(r.running[tenant]))
	for _, cancel := range r.running[tenant] {
		cancels = append(cancels, cancel)
	}
	r.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels), nil
}
