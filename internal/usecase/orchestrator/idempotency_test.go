package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
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

// faultyVault wraps the real evidence service but can be made to fail List on demand – to
// exercise the FAIL-CLOSED idempotency path. Seal always delegates (so the gate's admission
// seal and the intent/step seals behave normally).
type faultyVault struct {
	inner   *evidence.Service
	listErr error
}

func (f *faultyVault) Seal(ctx context.Context, eng shared.ID, kind string, content []byte, by string) (evdom.Evidence, error) {
	return f.inner.Seal(ctx, eng, kind, content, by)
}
func (f *faultyVault) List(ctx context.Context, eng shared.ID) ([]evdom.Evidence, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.inner.List(ctx, eng)
}

// TestAlreadyExecutedFailsClosed: if the evidence chain cannot be read during the
// idempotency check, the action is NEITHER executed NOR marked done – the run fails (and a
// durable job would retry). This is the fix for the fail-open double-run-vs-live-host hazard.
func TestAlreadyExecutedFailsClosed(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	clk := fixedClock{now}
	ids := &seqIDs{}
	audit := &fakeAudit{}
	guard, err := execution.NewGuard(&fakeEngRepo{eng: engAt(now)}, clk, audit)
	if err != nil {
		t.Fatal(err)
	}
	apprStore := memory.NewApprovalStore()
	appr, err := approval.NewService(apprStore, audit, clk, agent.ModeAuto, time.Minute)
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
	vault := &faultyVault{inner: ev, listErr: errors.New("evidence store unavailable")}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("SHOULD NOT RUN"), Summary: "x"}}
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"x"}`)),
	}}
	orch, err := orchestrator.New(llm, cat, gate, exec, vault, memory.NewAgentSessionStore(), apprStore, audit, clk, ids, orchestrator.Config{Model: "m", MaxSteps: 4})
	if err != nil {
		t.Fatal(err)
	}

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "go")
	if err == nil {
		t.Fatal("a List error during the idempotency check must FAIL the run (fail-closed), not proceed")
	}
	if exec.calls != 0 {
		t.Fatalf("fail-closed must NOT execute the action, got %d executor calls", exec.calls)
	}
	if sess.Status != agent.StatusFailed {
		t.Fatalf("status = %s, want failed", sess.Status)
	}
}

// TestIntentMarkerSealedBeforeExecute: a successful in-scope run seals an agent_intent (keyed
// on the action) BEFORE the agent_step – the marker that prevents a double-run on a crash
// between execute and step-seal.
func TestIntentMarkerSealedBeforeExecute(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enum"}`)),
		chatStop("done"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("a.app.acme.io"), Summary: "1 host"}}
	orch, ev, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 6})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "enumerate")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusSucceeded || exec.calls != 1 {
		t.Fatalf("expected one execution to success, got status=%s calls=%d", sess.Status, exec.calls)
	}
	if n := countKind(t, ev, orchestrator.IntentEvidenceKind); n != 1 {
		t.Fatalf("expected exactly 1 sealed agent_intent (pre-execution marker), got %d", n)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 1 {
		t.Fatalf("expected exactly 1 sealed agent_step, got %d", n)
	}
}

// TestSealIntentDisabledSkipsMarker: the opt-out config skips the marker (fast revert lever).
func TestSealIntentDisabledSkipsMarker(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enum"}`)),
		chatStop("done"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("h"), Summary: "1"}}
	orch, ev, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 6, SealIntentDisabled: true})
	if _, err := orch.Run(context.Background(), "eng-1", "alice", "go"); err != nil {
		t.Fatal(err)
	}
	if n := countKind(t, ev, orchestrator.IntentEvidenceKind); n != 0 {
		t.Fatalf("SealIntentDisabled must seal no agent_intent, got %d", n)
	}
}
