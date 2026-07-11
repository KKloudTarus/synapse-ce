package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
)

// drivePlan handles a propose_plan tool call: it dispatches it (the catalog mints node ids,
// classifies risk, validates the DAG), persists the plan (one per session), and hands off to
// the plan scheduler. A rejected plan or a duplicate is fed back to the model – never fatal.
func (o *Orchestrator) drivePlan(ctx context.Context, sess agent.Session, call agent.ToolCall) (agent.Session, error) {
	res, err := o.catalog.Dispatch(ctx, sess, call)
	if err != nil || res.Plan == nil {
		reason := "error: the proposed plan was rejected (it must be acyclic, within size limits, and use known tools/targets)"
		if err != nil {
			reason = "error: " + redact.String(err.Error(), nil)
		}
		return o.answerPlanCall(ctx, sess, call, reason)
	}
	if cerr := o.planStore.CreatePlan(ctx, *res.Plan); cerr != nil {
		if errors.Is(cerr, shared.ErrConflict) {
			// One plan per session: a second propose_plan is fed back, not fatal.
			return o.answerPlanCall(ctx, sess, call, "note: a plan already exists for this session; act on its results or summarize")
		}
		return o.fail(ctx, sess, fmt.Errorf("create plan: %w", cerr))
	}
	o.auditSessionMeta(ctx, sess, "agent.plan.created", map[string]string{
		"plan": res.Plan.ID.String(), "nodes": strconv.Itoa(len(res.Plan.Nodes)),
	})
	return o.planLoop(ctx, sess, *res.Plan)
}

// planLoop is the sequential plan scheduler (PR3; parallelism is PR5). It executes the DAG one
// ready node at a time: claim the node (Pending→Running via the revision CAS – the durable
// idempotency authority), re-admit it through safety.Gate exactly like a reactive proposal,
// execute + seal on approval, then settle the node and cascade skips behind any blocking
// terminal. It SUSPENDS the whole session when a node needs manual approval (resumable: the
// awaiting node is re-driven on Resume) and, when every node is settled, answers the originating
// propose_plan call with a summary and returns to the reactive loop for a final response.
//
// Crash-recovery + redelivery are safe: a NodeRunning node is re-driven through runProposal,
// whose fail-closed evidence idempotency (agent_intent/agent_step keyed on the node's stable
// ActionID) prevents a double-run against a live host; a lost CAS reloads the authoritative
// plan and re-derives the work.
func (o *Orchestrator) planLoop(ctx context.Context, sess agent.Session, plan agent.Plan) (agent.Session, error) {
	if o.cfg.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.cfg.MaxDuration)
		defer cancel()
	}
	transcript, err := o.sessions.Messages(ctx, sess.ID)
	if err != nil {
		return o.fail(ctx, sess, fmt.Errorf("load transcript: %w", err))
	}
	pendingCall, hasPending := lastPendingCall(transcript)
	if sess.Status != agent.StatusRunning {
		sess.Status = agent.StatusRunning
	}

	// Each successful iteration either claims one node or settles one; a lost CAS reloads. Bound
	// it well above 2×nodes so a logic bug can never spin forever (defensive backstop).
	maxIter := len(plan.Nodes)*4 + 16
	for iter := 0; !plan.AllSettled(); iter++ {
		if iter > maxIter {
			return o.fail(ctx, sess, fmt.Errorf("%w: plan loop exceeded %d iterations", shared.ErrValidation, maxIter))
		}
		if cerr := ctx.Err(); cerr != nil {
			return o.finish(ctx, sess, agent.StatusFailed, "plan wall-clock/context: "+cerr.Error())
		}

		// Pick work: a node already claimed (NodeRunning crash-recovery) or suspended-then-decided
		// (NodeAwaiting resume) first, else the next Ready node (deps met).
		nodeID := plan.FirstUnsettledClaimed()
		if nodeID == "" {
			// run independent RiskActive siblings CONCURRENTLY (bounded by MaxParallel). The
			// evidence service linearizes the concurrent seals (its own previous_hash CAS), so
			// VerifyChain stays intact; intrusive nodes are never batched (handled serially below,
			// one at a time → never two intrusive in flight).
			if o.cfg.MaxParallel > 1 {
				if batch := plan.ReadyActive(o.cfg.MaxParallel); len(batch) >= 2 {
					suspended, conflict, berr := o.runActiveBatch(ctx, sess, &plan, batch)
					if berr != nil {
						return o.fail(ctx, sess, berr)
					}
					if conflict {
						if rerr := o.reloadPlan(ctx, &plan); rerr != nil {
							return o.fail(ctx, sess, rerr)
						}
						continue
					}
					if suspended {
						return o.suspend(ctx, sess)
					}
					sess.UpdatedAt = o.clock.Now()
					_ = o.sessions.SaveSession(ctx, sess)
					continue
				}
			}
			ready := plan.Ready()
			if len(ready) == 0 {
				// Nothing runnable but not all settled ⇒ the rest are blocked behind a failure.
				if changed := plan.PropagateFailures(); len(changed) > 0 {
					if serr := o.savePlan(ctx, &plan); serr != nil {
						return o.planSaveFail(ctx, sess, &plan, serr)
					}
					continue
				}
				break // genuinely nothing left to do
			}
			nodeID = ready[0]
			if cerr := o.claimNode(ctx, &plan, nodeID); cerr != nil {
				if errors.Is(cerr, shared.ErrConflict) {
					if rerr := o.reloadPlan(ctx, &plan); rerr != nil {
						return o.fail(ctx, sess, rerr)
					}
					continue // another driver advanced the plan; re-pick from the fresh state
				}
				return o.fail(ctx, sess, cerr)
			}
		}

		node, ok := plan.Node(nodeID)
		if !ok {
			return o.fail(ctx, sess, fmt.Errorf("%w: plan node %q vanished", shared.ErrValidation, nodeID))
		}
		prop, perr := o.catalog.ProposeForNode(sess, node)
		if perr != nil {
			// Cannot even build the proposal (tool/target invalid now) → fail the node + cascade.
			_ = plan.SetNodeStatus(nodeID, agent.NodeFailed, redact.String(perr.Error(), nil))
			plan.PropagateFailures()
			if serr := o.savePlan(ctx, &plan); serr != nil {
				return o.planSaveFail(ctx, sess, &plan, serr)
			}
			continue
		}

		_, oc, rerr := o.runProposal(ctx, sess, planNodeCall(node), prop)
		if rerr != nil {
			return o.fail(ctx, sess, fmt.Errorf("plan node %s (%s): %w", node.ID, node.Tool, rerr))
		}
		switch oc {
		case outcomeSuspend:
			_ = plan.SetNodeStatus(nodeID, agent.NodeAwaiting, "")
			if serr := o.savePlan(ctx, &plan); serr != nil {
				return o.planSaveFail(ctx, sess, &plan, serr)
			}
			o.auditSessionMeta(ctx, sess, "agent.plan.node.awaiting", map[string]string{"node": node.ID, "action": prop.ID.String(), "risk": string(node.Risk)})
			return o.suspend(ctx, sess) // a human decides; Resume re-drives this node
		case outcomeDenied:
			_ = plan.SetNodeStatus(nodeID, agent.NodeDenied, "denied by scope/authorization/approval")
			plan.PropagateFailures()
		default: // outcomeExecuted (or a read, which a recon node never is)
			_ = plan.SetNodeStatus(nodeID, agent.NodeDone, "")
		}
		if serr := o.savePlan(ctx, &plan); serr != nil {
			return o.planSaveFail(ctx, sess, &plan, serr)
		}
		o.auditSessionMeta(ctx, sess, "agent.plan.node.settled", map[string]string{"node": node.ID, "status": string(mustNodeStatus(plan, nodeID))})
		sess.UpdatedAt = o.clock.Now()
		_ = o.sessions.SaveSession(ctx, sess) // liveness so the reconciler does not see a long plan as stale
	}

	plan.RecomputeStatus()
	if serr := o.savePlan(ctx, &plan); serr != nil {
		return o.planSaveFail(ctx, sess, &plan, serr)
	}
	o.auditSessionMeta(ctx, sess, "agent.plan.finished", map[string]string{"plan": plan.ID.String(), "status": string(plan.Status)})

	if !hasPending {
		return o.loop(ctx, sess) // the call was already answered (re-entry after settle) – continue
	}
	return o.answerPlanCall(ctx, sess, pendingCall, planSummary(plan))
}

// planSaveFail handles a SavePlan error in the loop: a stale CAS is benign (another driver
// advanced it – stop, the other driver owns it), anything else fails the session.
func (o *Orchestrator) planSaveFail(ctx context.Context, sess agent.Session, plan *agent.Plan, err error) (agent.Session, error) {
	if errors.Is(err, shared.ErrConflict) {
		// Another driver holds the truth; do not double-drive. The session stays running and a
		// later Drive (reconciler / redelivery) continues from the authoritative plan.
		o.auditSessionMeta(ctx, sess, "agent.plan.cas_conflict", map[string]string{"plan": plan.ID.String()})
		return sess, nil
	}
	return o.fail(ctx, sess, fmt.Errorf("save plan: %w", err))
}

// claimNode atomically moves a node Pending→Running via the revision CAS, so exactly one driver
// can claim it (the durable double-run guard). A lost CAS surfaces as shared.ErrConflict.
func (o *Orchestrator) claimNode(ctx context.Context, plan *agent.Plan, nodeID string) error {
	if err := plan.SetNodeStatus(nodeID, agent.NodeRunning, ""); err != nil {
		return err
	}
	return o.savePlan(ctx, plan)
}

// batchResult is one node's outcome from a parallel batch.
type batchResult struct {
	id       string
	oc       outcome
	buildErr error // ProposeForNode failed → node failed (non-fatal)
	runErr   error // runProposal failed → fatal (job retries)
}

// runActiveBatch claims a batch of ready RiskActive nodes (one CAS), runs their proposals
// CONCURRENTLY (bounded by MaxParallel), then settles them (one CAS). A single scheduler owns
// every plan write (no per-node CAS contention); the concurrency is in the recon EXECUTE +
// the per-node seals (which the evidence service linearizes). Returns (suspended, conflict,
// fatalErr): suspended ⇒ at least one node needs manual approval (the session suspends);
// conflict ⇒ a plan CAS was lost (caller reloads); fatalErr ⇒ an orchestration error.
func (o *Orchestrator) runActiveBatch(ctx context.Context, sess agent.Session, plan *agent.Plan, batch []string) (suspended, conflict bool, fatalErr error) {
	for _, id := range batch {
		if err := plan.SetNodeStatus(id, agent.NodeRunning, ""); err != nil {
			return false, false, err
		}
	}
	if err := o.savePlan(ctx, plan); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			return false, true, nil
		}
		return false, false, err
	}

	results := make([]batchResult, len(batch))
	sem := make(chan struct{}, o.cfg.MaxParallel)
	var wg sync.WaitGroup
	for i, id := range batch {
		node, ok := plan.Node(id)
		if !ok {
			results[i] = batchResult{id: id, runErr: fmt.Errorf("%w: plan node %q vanished", shared.ErrValidation, id)}
			continue
		}
		prop, perr := o.catalog.ProposeForNode(sess, node)
		if perr != nil {
			results[i] = batchResult{id: id, buildErr: perr}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, n agent.PlanNode, p agent.ProposedAction) {
			defer wg.Done()
			defer func() { <-sem }()
			// sess is passed by value (read-only); runProposal touches only stores/services,
			// each of which is concurrency-safe (the evidence chain self-linearizes its seals).
			_, oc, rerr := o.runProposal(ctx, sess, planNodeCall(n), p)
			results[idx] = batchResult{id: n.ID, oc: oc, runErr: rerr}
		}(i, node, prop)
	}
	wg.Wait()

	for _, r := range results {
		if r.runErr != nil {
			return false, false, fmt.Errorf("plan node %s: %w", r.id, r.runErr)
		}
		switch {
		case r.buildErr != nil:
			_ = plan.SetNodeStatus(r.id, agent.NodeFailed, redact.String(r.buildErr.Error(), nil))
		case r.oc == outcomeSuspend:
			_ = plan.SetNodeStatus(r.id, agent.NodeAwaiting, "")
			suspended = true
		case r.oc == outcomeDenied:
			_ = plan.SetNodeStatus(r.id, agent.NodeDenied, "denied by scope/authorization/approval")
		default: // outcomeExecuted
			_ = plan.SetNodeStatus(r.id, agent.NodeDone, "")
		}
		o.auditSessionMeta(ctx, sess, "agent.plan.node.settled", map[string]string{"node": r.id, "status": string(mustNodeStatus(*plan, r.id)), "parallel": "true"})
	}
	plan.PropagateFailures()
	if err := o.savePlan(ctx, plan); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			return false, true, nil
		}
		return false, false, err
	}
	return suspended, false, nil
}

// savePlan persists the plan via the optimistic-concurrency CAS and, on success, advances the
// in-memory revision to match the store's bump.
func (o *Orchestrator) savePlan(ctx context.Context, plan *agent.Plan) error {
	if err := o.planStore.SavePlan(ctx, *plan); err != nil {
		return err
	}
	plan.Revision++
	return nil
}

// reloadPlan replaces *plan with the authoritative stored copy (after a lost CAS).
func (o *Orchestrator) reloadPlan(ctx context.Context, plan *agent.Plan) error {
	fresh, found, err := o.planStore.GetBySession(ctx, plan.SessionID)
	if err != nil {
		return fmt.Errorf("reload plan: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: plan for session %s vanished", shared.ErrNotFound, plan.SessionID)
	}
	*plan = fresh
	return nil
}

// answerPlanCall appends a tool message answering the propose_plan call (idempotent: only if it
// is still unanswered) and re-enters the reactive loop so the model can produce a final summary.
func (o *Orchestrator) answerPlanCall(ctx context.Context, sess agent.Session, call agent.ToolCall, text string) (agent.Session, error) {
	transcript, err := o.sessions.Messages(ctx, sess.ID)
	if err != nil {
		return o.fail(ctx, sess, fmt.Errorf("load transcript: %w", err))
	}
	if _, pending := lastPendingCall(transcript); pending {
		if aerr := o.sessions.AppendMessage(ctx, sess.ID, len(transcript), toolMsg(call, text)); aerr != nil && !errors.Is(aerr, shared.ErrConflict) {
			return o.fail(ctx, sess, fmt.Errorf("answer plan call: %w", aerr))
		}
	}
	sess.Status = agent.StatusRunning
	sess.UpdatedAt = o.clock.Now()
	if serr := o.sessions.SaveSession(ctx, sess); serr != nil {
		return o.fail(ctx, sess, fmt.Errorf("save session: %w", serr))
	}
	return o.loop(ctx, sess)
}

// planNodeCall synthesizes the tool-call envelope runProposal needs to build its (discarded)
// tool message for a plan node. The plan answers the model with ONE summary, not per-node turns,
// so this id never enters the transcript.
func planNodeCall(node agent.PlanNode) agent.ToolCall {
	return agent.ToolCall{ID: "plannode:" + node.ID, Name: "start_recon"}
}

func mustNodeStatus(plan agent.Plan, id string) agent.NodeStatus {
	n, _ := plan.Node(id)
	return n.Status
}

// planSummary renders the settled plan's node outcomes as the tool answer fed back to the model.
// It carries only tool/target/status (no observation bytes – those are in the sealed evidence),
// so nothing untrusted or secret-bearing rides back in via this path.
func planSummary(plan agent.Plan) string {
	counts := map[agent.NodeStatus]int{}
	for _, n := range plan.Nodes {
		counts[n.Status]++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Plan %s (%s). Nodes: %d done, %d denied, %d skipped, %d failed of %d.\n",
		plan.ID, plan.Status, counts[agent.NodeDone], counts[agent.NodeDenied], counts[agent.NodeSkipped], counts[agent.NodeFailed], len(plan.Nodes))
	lines := make([]string, 0, len(plan.Nodes))
	for _, n := range plan.Nodes {
		line := fmt.Sprintf("- %s %s: %s", n.Tool, redact.String(n.Target, nil), n.Status)
		if n.Failure != "" {
			// Cap each failure line so the plan answer stays token-bounded regardless of node count.
			line += " (" + truncate(redact.String(n.Failure, nil), 160) + ")"
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	b.WriteString(strings.Join(lines, "\n"))
	b.WriteString("\nThe per-step results are sealed in the evidence chain. Summarize for the operator.")
	return b.String()
}
