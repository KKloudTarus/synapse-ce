package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	drecon "github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// fakeNaabu is a capability-sensitive recon tool (→ RiskIntrusive: always manual approval).
type fakeNaabu struct{}

func (fakeNaabu) Name() string                         { return "naabu" }
func (fakeNaabu) Binary() string                       { return "naabu" }
func (fakeNaabu) Action() string                       { return "recon.naabu" }
func (fakeNaabu) CapabilitySensitive() bool            { return true }
func (fakeNaabu) Accepts(k engagement.TargetKind) bool { return k == engagement.TargetDomain }
func (fakeNaabu) Parse([]byte) ([]drecon.Result, error) {
	return nil, nil
}
func (fakeNaabu) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: "naabu", Args: []string{"-silent", "-host", t.Value}}, nil
}

// newPlanOrch builds an orchestrator WITH planning enabled (catalog + plan store) over the same
// in-memory stack as newOrch, plus a capability-sensitive tool so intrusive nodes can be tested.
func newPlanOrch(t *testing.T, llm ports.LLM, exec orchestrator.Executor, mode agent.ApprovalMode, cfg orchestrator.Config) (
	*orchestrator.Orchestrator, *evidence.Service, *memory.AgentSessionStore, *memory.PlanStore, *approval.Service,
) {
	t.Helper()
	now := time.Unix(1_000_000, 0).UTC()
	clock := fixedClock{now}
	ids := &seqIDs{}
	audit := &fakeAudit{}
	guard, err := execution.NewGuard(&fakeEngRepo{eng: engAt(now)}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	apprStore := memory.NewApprovalStore()
	appr, err := approval.NewService(apprStore, audit, clock, mode, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := agenttools.New(emptyFindings{}, emptyEvidence{}, []ports.ReconTool{fakeRecon{}, fakeNaabu{}}, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	cat.EnablePlanning()
	sessions := memory.NewAgentSessionStore()
	planStore := memory.NewPlanStore()
	if cfg.Model == "" {
		cfg.Model = "test-model"
	}
	orch, err := orchestrator.New(llm, cat, gate, exec, ev, sessions, apprStore, audit, clock, ids, cfg)
	if err != nil {
		t.Fatal(err)
	}
	orch.SetPlanStore(planStore)
	return orch, ev, sessions, planStore, appr
}

func proposePlanCall(id, args string) agent.ToolCall {
	return toolCall(id, agenttools.ToolProposePlan, args)
}

// TestPlanLoop_ExecutesDependencyChainAndSeals: a 2-node in-scope plan (b depends on a) runs
// both nodes through the gate, seals one agent_step each, completes the plan, and the session
// succeeds after the model's final summary.
func TestPlanLoop_ExecutesDependencyChainAndSeals(t *testing.T) {
	plan := `{"nodes":[
		{"key":"a","tool":"subfinder","target":"app.acme.io","rationale":"enumerate"},
		{"key":"b","tool":"subfinder","target":"app.acme.io","depends_on":["a"],"rationale":"again"}
	]}`
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(proposePlanCall("c1", plan)),
		chatStop("done – 2 steps executed"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("a.app.acme.io"), Summary: "1 host"}}
	orch, ev, _, planStore, _ := newPlanOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "enumerate app.acme.io")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("status=%s, want succeeded", sess.Status)
	}
	if exec.calls != 2 {
		t.Fatalf("both plan nodes must execute, got %d", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 2 {
		t.Fatalf("expected 2 sealed agent_step, got %d", n)
	}
	// Every executed node was admitted by the gate (one admission seal each).
	if n := countKind(t, ev, "agent_admission"); n != 2 {
		t.Fatalf("expected 2 gate admissions, got %d", n)
	}
	p, found, _ := planStore.GetBySession(context.Background(), sess.ID)
	if !found || p.Status != agent.PlanComplete {
		t.Fatalf("plan status=%s found=%v, want complete", p.Status, found)
	}
	for _, n := range p.Nodes {
		if n.Status != agent.NodeDone {
			t.Fatalf("node %s=%s, want done", n.ID, n.Status)
		}
	}
}

// TestPlanLoop_OutOfScopeNodeSkipsDependents is the headline safety AC for the DAG: an
// out-of-scope node is DENIED by the gate (never executed) and its dependents are SKIPPED –
// 0 executor calls, 0 agent_step.
func TestPlanLoop_OutOfScopeNodeSkipsDependents(t *testing.T) {
	plan := `{"nodes":[
		{"key":"a","tool":"subfinder","target":"evil.com","rationale":"oops"},
		{"key":"b","tool":"subfinder","target":"app.acme.io","depends_on":["a"],"rationale":"after"}
	]}`
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(proposePlanCall("c1", plan)),
		chatStop("understood, the out-of-scope step was rejected"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("x"), Summary: "y"}}
	orch, ev, _, planStore, _ := newPlanOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "go")
	if err != nil {
		t.Fatal(err)
	}
	if exec.calls != 0 {
		t.Fatalf("an out-of-scope plan must execute NOTHING, got %d calls", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 0 {
		t.Fatalf("expected 0 sealed steps, got %d", n)
	}
	p, _, _ := planStore.GetBySession(context.Background(), sess.ID)
	a, _ := p.Node(p.Nodes[0].ID)
	b, _ := p.Node(p.Nodes[1].ID)
	if a.Status != agent.NodeDenied {
		t.Fatalf("out-of-scope node a=%s, want denied", a.Status)
	}
	if b.Status != agent.NodeSkipped {
		t.Fatalf("dependent node b=%s, want skipped", b.Status)
	}
	if p.Status != agent.PlanFailed {
		t.Fatalf("plan status=%s, want failed", p.Status)
	}
}

// TestPlanLoop_IntrusiveSuspendsThenResumes: an intrusive (capability-sensitive) node always
// requires manual approval even in auto mode – the session suspends; after a human approves,
// Resume re-drives the node and it executes exactly once.
func TestPlanLoop_IntrusiveSuspendsThenResumes(t *testing.T) {
	plan := `{"nodes":[{"key":"scan","tool":"naabu","target":"app.acme.io","rationale":"port scan"}]}`
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(proposePlanCall("c1", plan)),
		chatStop("scan complete"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("80/tcp open"), Summary: "1 port"}}
	orch, ev, _, planStore, appr := newPlanOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})
	ctx := context.Background()

	sess, err := orch.Run(ctx, "eng-1", "alice", "scan app.acme.io")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusAwaitingApproval {
		t.Fatalf("intrusive node must suspend, status=%s", sess.Status)
	}
	if exec.calls != 0 {
		t.Fatalf("nothing runs before approval, got %d calls", exec.calls)
	}
	p, _, _ := planStore.GetBySession(ctx, sess.ID)
	node := p.Nodes[0]
	if node.Status != agent.NodeAwaiting {
		t.Fatalf("node=%s, want awaiting", node.Status)
	}

	// Human approves the awaiting node's action, then Resume re-drives the plan.
	if _, derr := appr.Decide(ctx, "alice", node.ActionID, true, "ok"); derr != nil {
		t.Fatalf("decide: %v", derr)
	}
	resumed, err := orch.Resume(ctx, sess.ID, node.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != agent.StatusSucceeded {
		t.Fatalf("after approval the session must succeed, status=%s", resumed.Status)
	}
	if exec.calls != 1 {
		t.Fatalf("approved node must execute exactly once, got %d", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 1 {
		t.Fatalf("expected 1 sealed step, got %d", n)
	}
	p2, _, _ := planStore.GetBySession(ctx, sess.ID)
	if p2.Status != agent.PlanComplete {
		t.Fatalf("plan status=%s, want complete", p2.Status)
	}
}

// TestPlanLoop_RedeliveryNoDoubleRun: re-driving a session whose plan already completed must
// not re-execute any node (durable idempotency).
func TestPlanLoop_RedeliveryNoDoubleRun(t *testing.T) {
	plan := `{"nodes":[{"key":"a","tool":"subfinder","target":"app.acme.io","rationale":"enum"}]}`
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(proposePlanCall("c1", plan)),
		chatStop("done"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("h"), Summary: "1"}}
	orch, ev, _, _, _ := newPlanOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})
	ctx := context.Background()

	sess, err := orch.Run(ctx, "eng-1", "alice", "go")
	if err != nil || sess.Status != agent.StatusSucceeded {
		t.Fatalf("run: status=%s err=%v", sess.Status, err)
	}
	callsAfterRun, stepsAfterRun := exec.calls, countKind(t, ev, orchestrator.StepEvidenceKind)

	// Redeliver Drive on the now-terminal session.
	if _, derr := orch.Drive(ctx, sess.ID); derr != nil {
		t.Fatal(derr)
	}
	if exec.calls != callsAfterRun {
		t.Fatalf("redelivery re-executed a node: calls %d → %d", callsAfterRun, exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != stepsAfterRun {
		t.Fatalf("redelivery sealed extra steps: %d → %d", stepsAfterRun, n)
	}
}

// TestPlanLoop_NilPlanStoreRejectsPlanTool: with no plan store wired (legacy config), propose_plan
// is not dispatchable – the call is fed back as an error and nothing is executed. Proves the
// nil-plan-store path is safe (the byte-identical legacy loop never drives a plan).
func TestPlanLoop_NilPlanStoreRejectsPlanTool(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(proposePlanCall("c1", `{"nodes":[{"key":"a","tool":"subfinder","target":"app.acme.io"}]}`)),
		chatStop("ok, no planning available"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("x"), Summary: "y"}}
	// newOrch wires NO plan store and does NOT enable catalog planning.
	orch, ev, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "go")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("status=%s, want succeeded (error fed back, model stops)", sess.Status)
	}
	if exec.calls != 0 {
		t.Fatalf("no plan store ⇒ nothing executes via propose_plan, got %d", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 0 {
		t.Fatalf("expected 0 steps, got %d", n)
	}
}
