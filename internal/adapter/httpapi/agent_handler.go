package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// maxAgentStreamDuration bounds an SSE session-stream connection (the client reconnects).
const maxAgentStreamDuration = 30 * time.Minute

// agentDeps bundles the AI-orchestration dependencies the agent routes need. queue is optional: when
// set, a run is dispatched DURABLY to a worker; otherwise it runs inline in a bounded goroutine
// pool (dev – non-durable). The inline path is bounded by `sem` (backpressure → 503) and bound
// to a server-lifetime context so a run is cancelled on shutdown rather than orphaned.
type agentDeps struct {
	orch          *orchestrator.Orchestrator
	sessions      ports.AgentSessionStore
	approvals     *approval.Service
	approvalStore ports.ApprovalStore
	queue         ports.JobQueue
	decisions     ports.DecisionStore // structured decision log (read-only /decisions); optional
	plans         ports.PlanStore     // execution plan DAG (read-only /plan); optional
	sem           chan struct{}       // inline concurrency limiter (nil ⇒ durable path)
	queueDepth    int                 // durable-path admission cap (max not-yet-terminal jobs); 0 ⇒ uncapped
	runCtx        context.Context     // server-lifetime ctx for inline runs (set via SetAgentRunContext)
	wg            sync.WaitGroup      // tracks inline runs for graceful drain
}

// agentRetryAfterSeconds is the Retry-After hint returned on agent saturation (503).
const agentRetryAfterSeconds = 5

// EnableAgent wires the AI agent routes. concurrency bounds inline (non-durable) runs;
// queueDepth bounds the DURABLE path – the max number of not-yet-terminal agent jobs admitted
// before the API returns 503 (with Retry-After), so a flood / retry-storm / dead-letter
// re-drive cannot grow the jobs table without bound. Call after NewRouter; if never called the
// agent endpoints are not registered (fail-safe: SYNAPSE_AGENT_ENABLED=false leaves off).
func (rt *Router) EnableAgent(orch *orchestrator.Orchestrator, sessions ports.AgentSessionStore, approvals *approval.Service, approvalStore ports.ApprovalStore, queue ports.JobQueue, concurrency, queueDepth int) {
	if concurrency <= 0 {
		concurrency = 8
	}
	d := &agentDeps{orch: orch, sessions: sessions, approvals: approvals, approvalStore: approvalStore, queue: queue, queueDepth: queueDepth, runCtx: context.Background()}
	if queue == nil {
		d.sem = make(chan struct{}, concurrency) // inline path is bounded
	}
	rt.agent = d
}

// SetAgentRunContext binds inline agent runs to a server-lifetime context (cancelled on
// shutdown) so a SIGTERM stops in-flight runs instead of leaving detached goroutines.
func (rt *Router) SetAgentRunContext(ctx context.Context) {
	if rt.agent != nil {
		rt.agent.runCtx = ctx
	}
}

// SetAgentDecisionStore wires the read-only decision log behind GET …/decisions.
func (rt *Router) SetAgentDecisionStore(ds ports.DecisionStore) {
	if rt.agent != nil {
		rt.agent.decisions = ds
	}
}

// SetAgentPlanStore wires the read-only execution-plan view behind GET …/plan.
func (rt *Router) SetAgentPlanStore(ps ports.PlanStore) {
	if rt.agent != nil {
		rt.agent.plans = ps
	}
}

// admitAgent admits one unit of agent work without blocking, applying backpressure on BOTH
// paths. Inline: take a semaphore slot. Durable: reject once the queue holds queueDepth
// not-yet-terminal agent jobs, so the jobs table cannot grow without bound. ok=false ⇒
// saturated ⇒ the caller returns 503 + Retry-After. Admission is FAIL-CLOSED: if the durable
// depth cannot be measured (DB error), it rejects rather than piling work onto a struggling DB.
func (rt *Router) admitAgent(ctx context.Context) (release func(), ok bool) {
	d := rt.agent
	if d.sem != nil { // inline path: bounded by the semaphore
		select {
		case d.sem <- struct{}{}:
			return func() { <-d.sem }, true
		default:
			return nil, false // saturated
		}
	}
	// Durable path: the queue is the buffer, but bounded.
	if d.queue == nil || d.queueDepth <= 0 {
		return func() {}, true // no queue, or depth cap disabled
	}
	depth, err := d.queue.Depth(ctx, orchestrator.JobKind)
	if err != nil {
		rt.log.Error("agent queue depth check failed – rejecting (fail closed)", "err", err)
		return nil, false
	}
	if depth >= d.queueDepth {
		return nil, false
	}
	return func() {}, true
}

// writeAgentSaturated returns 503 with a Retry-After hint so a client (or retrying worker)
// backs off instead of hammering a saturated agent.
func (rt *Router) writeAgentSaturated(w http.ResponseWriter, msg string) {
	w.Header().Set("Retry-After", strconv.Itoa(agentRetryAfterSeconds))
	writeError(w, rt.log, fmt.Errorf("%w: %s", shared.ErrSaturated, msg))
}

// spawnAgent runs the job durably (enqueue) or inline (bounded goroutine on the run ctx),
// consuming the reserved slot. For the durable path the slot is a no-op and freed immediately.
func (rt *Router) spawnAgent(release func(), payload []byte) {
	if rt.agent.queue != nil {
		defer release()
		if _, err := rt.agent.queue.Enqueue(rt.agent.runCtx, orchestrator.JobKind, payload); err != nil {
			rt.log.Error("enqueue agent job failed", "err", err)
		}
		return
	}
	rt.agent.wg.Add(1)
	go func() {
		defer rt.agent.wg.Done()
		defer release()
		if err := rt.agent.orch.RunJob(rt.agent.runCtx, payload); err != nil {
			rt.log.Error("inline agent run failed", "err", err)
		}
	}()
}

// startAgentSession creates a session and dispatches it to run. The operator gets the session
// id back immediately; progress is read via the session stream + the approvals queue.
func (rt *Router) startAgentSession(w http.ResponseWriter, r *http.Request) {
	engID := r.PathValue("id")
	var body struct {
		Goal string `json:"goal"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	// Reserve an execution slot BEFORE creating the session, so a SATURATED server returns 503
	// without ever creating a session it can't drive. NOTE: this guards the saturation case
	// only – an inline (non-durable) run still does not survive a crash/shutdown mid-run (the
	// session is left `running` with no driver). Durable recovery requires SYNAPSE_AGENT_VIA_WORKER,
	// where synapse-worker's reconciler re-drives stranded `running` sessions.
	release, ok := rt.admitAgent(r.Context())
	if !ok {
		rt.writeAgentSaturated(w, "agent at capacity, retry shortly")
		return
	}
	sess, err := rt.agent.orch.Start(r.Context(), shared.ID(engID), PrincipalFrom(r.Context()), body.Goal)
	if err != nil {
		release()
		writeError(w, rt.log, err)
		return
	}
	payload, err := orchestrator.DriveJob(sess.ID)
	if err != nil {
		release()
		writeError(w, rt.log, err)
		return
	}
	rt.spawnAgent(release, payload)
	writeJSON(w, http.StatusAccepted, sess)
}

// listAgentSessions returns an engagement's agent sessions.
func (rt *Router) listAgentSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := rt.agent.sessions.ListByEngagement(r.Context(), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// getAgentSession returns one session + its transcript (engagement-scoped).
func (rt *Router) getAgentSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := rt.lookupSession(w, r)
	if !ok {
		return
	}
	msgs, err := rt.agent.sessions.Messages(r.Context(), sess.ID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sess, "transcript": msgs})
}

// listAgentDecisions returns the structured decision log for a session: why each tool
// was chosen, the outcome, the evidence-chain hashes it links to, and why the run stopped –
// answerable from stored data, no transcript parsing. Engagement-scoped + read-only.
func (rt *Router) listAgentDecisions(w http.ResponseWriter, r *http.Request) {
	sess, ok := rt.lookupSession(w, r)
	if !ok {
		return
	}
	if rt.agent.decisions == nil {
		writeJSON(w, http.StatusOK, map[string]any{"decisions": []any{}})
		return
	}
	decisions, err := rt.agent.decisions.ListBySession(r.Context(), sess.ID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": decisions})
}

// getAgentPlan returns the session's execution plan DAG: the proposed nodes, their
// dependencies, status, and risk – so an operator can see what the agent planned + how it
// settled. Engagement-scoped + read-only. Returns an empty object when the session has no plan
// (a reactive, non-plan run).
func (rt *Router) getAgentPlan(w http.ResponseWriter, r *http.Request) {
	sess, ok := rt.lookupSession(w, r)
	if !ok {
		return
	}
	if rt.agent.plans == nil {
		writeJSON(w, http.StatusOK, map[string]any{"plan": nil})
		return
	}
	plan, found, err := rt.agent.plans.GetBySession(r.Context(), sess.ID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusOK, map[string]any{"plan": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan})
}

// listAgentApprovals returns the pending diff-before-run proposals for the engagement.
func (rt *Router) listAgentApprovals(w http.ResponseWriter, r *http.Request) {
	pending, err := rt.agent.approvalStore.Pending(r.Context(), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, pending)
}

// decideAgentApproval records a human's approve/deny on a proposed action, then resumes the
// session (executing on approve, feeding back the denial on deny). Separation of duties is enforced
// by the route's PermReview gate: a machine role (mcp/agent) is granted nothing in the RBAC matrix,
// so it can never approve agent actions – the invariant holds the moment such a service principal
// is introduced.
func (rt *Router) decideAgentApproval(w http.ResponseWriter, r *http.Request) {
	engID := r.PathValue("id")
	actionID := shared.ID(r.PathValue("aid"))
	var body struct {
		Approve bool   `json:"approve"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	prop, _, err := rt.agent.approvalStore.Get(r.Context(), actionID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if prop.EngagementID.String() != engID {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "approval not found for this engagement"})
		return
	}
	// Reserve a slot before recording the decision so a saturated inline server returns 503
	// and the (idempotent) decision can be retried, rather than recording a decision the run
	// can't act on. The durable path always reserves successfully (the queue is the buffer).
	release, ok := rt.admitAgent(r.Context())
	if !ok {
		rt.writeAgentSaturated(w, "agent at capacity, retry the decision shortly")
		return
	}
	dec, err := rt.agent.approvals.Decide(r.Context(), PrincipalFrom(r.Context()), actionID, body.Approve, body.Reason)
	if err != nil {
		release()
		writeError(w, rt.log, err)
		return
	}
	// Resume either way: an approval executes the action; a denial is fed back and the loop
	// continues so the agent can adapt.
	payload, err := orchestrator.ResumeJob(prop.SessionID, actionID)
	if err != nil {
		release()
		writeError(w, rt.log, err)
		return
	}
	rt.spawnAgent(release, payload)
	writeJSON(w, http.StatusOK, dec)
}

// streamAgentSession streams a session's transcript as Server-Sent Events by polling the store
// (so it works whether the run executes in-process or on a separate worker). Reconnect via
// Last-Event-ID / ?lastEventId (the message sequence). Ends with an `event: done` when the
// session reaches a terminal state.
func (rt *Router) streamAgentSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := rt.lookupSession(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorBody{Error: "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx, cancel := context.WithTimeout(r.Context(), maxAgentStreamDuration)
	defer cancel()
	after := lastEventID(r) // already-seen message count
	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()

	for {
		msgs, err := rt.agent.sessions.Messages(ctx, sess.ID)
		if err == nil {
			for i := after; i < len(msgs); i++ {
				payload, _ := json.Marshal(msgs[i])
				_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", i+1, payload)
			}
			if len(msgs) > after {
				after = len(msgs)
				flusher.Flush()
			}
		}
		cur, err := rt.agent.sessions.GetSession(ctx, sess.ID)
		if err == nil && cur.Status.Terminal() {
			_, _ = fmt.Fprintf(w, "id: %d\nevent: done\ndata: {\"status\":%q}\n\n", after, cur.Status)
			flusher.Flush()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// lookupSession loads the session named by {sid} and verifies it belongs to {id}.
func (rt *Router) lookupSession(w http.ResponseWriter, r *http.Request) (agent.Session, bool) {
	engID := r.PathValue("id")
	sess, err := rt.agent.sessions.GetSession(r.Context(), shared.ID(r.PathValue("sid")))
	if err != nil {
		writeError(w, rt.log, err)
		return agent.Session{}, false
	}
	if sess.EngagementID.String() != engID {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "agent session not found for this engagement"})
		return agent.Session{}, false
	}
	return sess, true
}
