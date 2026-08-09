package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// resumeHarness wires a real manual-mode gate + approval service so a session suspends, a human
// decides, and Resume continues the loop.
type resumeHarness struct {
	orch      *orchestrator.Orchestrator
	appr      *approval.Service
	apprStore *memory.ApprovalStore
	ev        *evidence.Service
	exec      *fakeExecutor
}

func newResumeHarness(t *testing.T, steps []ports.ChatResponse) resumeHarness {
	t.Helper()
	now := time.Unix(1_000_000, 0).UTC()
	clk := fixedClock{now}
	ids := &seqIDs{}
	audit := &fakeAudit{}
	guard, err := execution.NewGuard(&fakeEngRepo{eng: engAt(now)}, clk, audit)
	if err != nil {
		t.Fatal(err)
	}
	apprStore := memory.NewApprovalStore()
	appr, err := approval.NewService(apprStore, audit, clk, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clk, ids)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := agenttools.New(emptyFindings{}, emptyEvidence{}, []ports.ReconTool{fakeRecon{}}, audit, clk, ids)
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("a.app.acme.io"), Summary: "1 host"}}
	orch, err := orchestrator.New(&scriptLLM{steps: steps}, cat, gate, exec, ev, memory.NewAgentSessionStore(), apprStore, audit, clk, ids, orchestrator.Config{Model: "m", MaxSteps: 8})
	if err != nil {
		t.Fatal(err)
	}
	return resumeHarness{orch: orch, appr: appr, apprStore: apprStore, ev: ev, exec: exec}
}

// TestResumeAfterApprovalExecutesAndContinues: manual mode suspends a recon proposal; after a
// human approves, Resume executes it, seals the step, and the loop runs to completion.
func TestResumeAfterApprovalExecutesAndContinues(t *testing.T) {
	h := newResumeHarness(t, []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enum"}`)),
		chatStop("found hosts"),
	})
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)

	sess, err := h.orch.Run(ctx, "eng-1", "alice", "enumerate app.acme.io")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusAwaitingApproval {
		t.Fatalf("manual mode must suspend, got %s", sess.Status)
	}
	if h.exec.calls != 0 {
		t.Fatal("must not execute before approval")
	}

	pend, err := h.apprStore.Pending(ctx, "eng-1")
	if err != nil || len(pend) != 1 {
		t.Fatalf("expected exactly 1 pending action, got %d err=%v", len(pend), err)
	}
	actionID := pend[0].ID
	if _, err := h.appr.Decide(ctx, "bob", actionID, true, "looks fine"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	sess, err = h.orch.Resume(ctx, sess.ID, actionID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("after approval+resume+stop, want succeeded, got %s", sess.Status)
	}
	if h.exec.calls != 1 {
		t.Fatalf("the approved action must execute exactly once, got %d", h.exec.calls)
	}
	if n := countKind(t, h.ev, orchestrator.StepEvidenceKind); n != 1 {
		t.Fatalf("expected 1 sealed agent_step, got %d", n)
	}

	// Idempotent: resuming a now-terminal session is a safe no-op (no second execution).
	if _, err := h.orch.Resume(ctx, sess.ID, actionID); err != nil {
		t.Fatal(err)
	}
	if h.exec.calls != 1 {
		t.Fatalf("resuming a finished session must not re-execute, got %d", h.exec.calls)
	}
}

// TestResumeAfterDenialFeedsBackNeverExecutes: a denied action, on resume, is fed back and the
// loop continues WITHOUT executing it.
func TestResumeAfterDenialFeedsBackNeverExecutes(t *testing.T) {
	h := newResumeHarness(t, []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enum"}`)),
		chatStop("understood"),
	})
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	sess, _ := h.orch.Run(ctx, "eng-1", "alice", "enumerate")
	pend, _ := h.apprStore.Pending(ctx, "eng-1")
	actionID := pend[0].ID
	if _, err := h.appr.Decide(ctx, "bob", actionID, false, "too risky"); err != nil {
		t.Fatal(err)
	}
	sess, err := h.orch.Resume(ctx, sess.ID, actionID)
	if err != nil {
		t.Fatal(err)
	}
	if h.exec.calls != 0 {
		t.Fatalf("a denied action must never execute, got %d", h.exec.calls)
	}
	if n := countKind(t, h.ev, orchestrator.StepEvidenceKind); n != 0 {
		t.Fatalf("a denied action seals no step, got %d", n)
	}
	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("loop should continue after the denial was fed back, got %s", sess.Status)
	}
}

// TestRunJobDispatches: the durable handler drives a started session to completion.
func TestRunJobDispatches(t *testing.T) {
	h := newResumeHarness(t, []ports.ChatResponse{chatStop("nothing to do")})
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	sess, err := h.orch.Start(ctx, "eng-1", "alice", "just answer")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusRunning {
		t.Fatalf("Start must leave the session running, got %s", sess.Status)
	}
	payload, err := orchestrator.DriveJob(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.RunJob(ctx, payload); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
}
