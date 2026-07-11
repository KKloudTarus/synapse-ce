package orchestrator_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// concExecutor records peak concurrency so a test can PROVE nodes ran in parallel.
type concExecutor struct {
	mu       sync.Mutex
	cur, max int
	calls    int
}

func (e *concExecutor) Execute(_ context.Context, _ safety.AdmittedAction) (orchestrator.Observation, error) {
	e.mu.Lock()
	e.cur++
	e.calls++
	if e.cur > e.max {
		e.max = e.cur
	}
	e.mu.Unlock()
	time.Sleep(25 * time.Millisecond) // hold the slot so concurrent calls overlap observably
	e.mu.Lock()
	e.cur--
	e.mu.Unlock()
	return orchestrator.Observation{Output: []byte("host"), Summary: "1 host"}, nil
}

func (e *concExecutor) peak() int  { e.mu.Lock(); defer e.mu.Unlock(); return e.max }
func (e *concExecutor) total() int { e.mu.Lock(); defer e.mu.Unlock(); return e.calls }

func verifyChainIntact(t *testing.T, ev *evidence.Service) {
	t.Helper()
	items, err := ev.List(context.Background(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := evdom.VerifyChain(items); err != nil {
		t.Fatalf("evidence chain broken after parallel run: %v", err)
	}
}

// TestPlanLoop_ParallelActiveSiblingsConcurrentChainIntact: three independent RiskActive nodes
// run CONCURRENTLY (peak concurrency > 1), every step seals, the hash chain stays intact
// (concurrent seals are linearized by the evidence service), and the plan completes.
func TestPlanLoop_ParallelActiveSiblingsConcurrentChainIntact(t *testing.T) {
	plan := `{"nodes":[
		{"key":"a","tool":"subfinder","target":"app.acme.io","rationale":"a"},
		{"key":"b","tool":"subfinder","target":"app.acme.io","rationale":"b"},
		{"key":"c","tool":"subfinder","target":"app.acme.io","rationale":"c"}
	]}`
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(proposePlanCall("c1", plan)),
		chatStop("done – 3 in parallel"),
	}}
	exec := &concExecutor{}
	orch, ev, _, planStore, _ := newPlanOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8, MaxParallel: 3})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "enumerate in parallel")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("status=%s, want succeeded", sess.Status)
	}
	if exec.total() != 3 {
		t.Fatalf("expected 3 executions, got %d", exec.total())
	}
	if exec.peak() < 2 {
		t.Fatalf("expected concurrent execution (peak ≥ 2), got peak=%d", exec.peak())
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 3 {
		t.Fatalf("expected 3 sealed steps, got %d", n)
	}
	verifyChainIntact(t, ev) // the headline safety AC: parallel seals do NOT break VerifyChain
	p, _, _ := planStore.GetBySession(context.Background(), sess.ID)
	if p.Status != agent.PlanComplete {
		t.Fatalf("plan status=%s, want complete", p.Status)
	}
}

// TestPlanLoop_IntrusiveNeverBatched: with active + intrusive ready siblings and MaxParallel=4,
// only the RiskActive nodes run concurrently; the intrusive node is NOT batched (it suspends for
// manual approval) – so two intrusive actions can never be in flight together.
func TestPlanLoop_IntrusiveNeverBatched(t *testing.T) {
	plan := `{"nodes":[
		{"key":"a","tool":"subfinder","target":"app.acme.io","rationale":"a"},
		{"key":"b","tool":"subfinder","target":"app.acme.io","rationale":"b"},
		{"key":"scan","tool":"naabu","target":"app.acme.io","rationale":"intrusive"}
	]}`
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(proposePlanCall("c1", plan)),
		chatStop("partial"),
	}}
	exec := &concExecutor{}
	orch, ev, _, planStore, _ := newPlanOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8, MaxParallel: 4})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "mixed")
	if err != nil {
		t.Fatal(err)
	}
	// The two active nodes ran (concurrently); the intrusive one suspended the session.
	if sess.Status != agent.StatusAwaitingApproval {
		t.Fatalf("status=%s, want awaiting_approval (intrusive node suspends)", sess.Status)
	}
	if exec.total() != 2 {
		t.Fatalf("only the 2 active nodes should execute, got %d", exec.total())
	}
	if exec.peak() > 2 {
		t.Fatalf("intrusive node must never be in the parallel batch, peak=%d", exec.peak())
	}
	verifyChainIntact(t, ev)
	p, _, _ := planStore.GetBySession(context.Background(), sess.ID)
	intrusive := p.Nodes[2]
	if intrusive.Status != agent.NodeAwaiting {
		t.Fatalf("intrusive node status=%s, want awaiting", intrusive.Status)
	}
}

// TestPlanLoop_ParallelRedeliveryNoDoubleRun: re-driving a completed parallel plan executes
// nothing again (node-CAS + fail-closed evidence idempotency hold under the batch path).
func TestPlanLoop_ParallelRedeliveryNoDoubleRun(t *testing.T) {
	plan := `{"nodes":[
		{"key":"a","tool":"subfinder","target":"app.acme.io"},
		{"key":"b","tool":"subfinder","target":"app.acme.io"}
	]}`
	llm := &scriptLLM{steps: []ports.ChatResponse{chatTool(proposePlanCall("c1", plan)), chatStop("done")}}
	exec := &concExecutor{}
	orch, ev, _, _, _ := newPlanOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8, MaxParallel: 2})
	ctx := context.Background()

	sess, err := orch.Run(ctx, "eng-1", "alice", "go")
	if err != nil || sess.Status != agent.StatusSucceeded {
		t.Fatalf("run: status=%s err=%v", sess.Status, err)
	}
	c1, s1 := exec.total(), countKind(t, ev, orchestrator.StepEvidenceKind)
	if _, derr := orch.Drive(ctx, sess.ID); derr != nil {
		t.Fatal(derr)
	}
	if exec.total() != c1 || countKind(t, ev, orchestrator.StepEvidenceKind) != s1 {
		t.Fatalf("redelivery double-ran: calls %d→%d steps %d→%d", c1, exec.total(), s1, countKind(t, ev, orchestrator.StepEvidenceKind))
	}
	verifyChainIntact(t, ev)
}
