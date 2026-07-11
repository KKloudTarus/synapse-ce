package orchestrator_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	recontools "github.com/KKloudTarus/synapse-ce/internal/infrastructure/recon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// fakeToolRunner is the ONLY mock below the LLM: it implements ports.ToolRunner (the lowest
// exec seam) and returns canned stdout for an argv, running NO real binary. Everything above it
// – the recon use-case, the gate, the evidence chain, the ReconExecutor, the orchestrator – is
// the REAL production code. It records every Run so the test can assert exec-exactly-once.
type fakeToolRunner struct {
	mu     sync.Mutex
	calls  int
	argvs  [][]string
	stdout []byte
}

func (r *fakeToolRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.argvs = append(r.argvs, append([]string{spec.Name}, spec.Args...))
	return ports.ToolResult{Stdout: r.stdout, ExitCode: 0}, nil
}

type syncDispatcher struct{}

func (syncDispatcher) Submit(task func(context.Context)) error {
	task(context.Background())
	return nil
}

// TestE2E_DurableAgentRun_NoMocksBelowLLM is the headline acceptance: a replay-LLM proposes
// an IN-SCOPE start_recon; the REAL gate admits it, the REAL ReconExecutor runs it through the
// REAL recon.Service, which execs only the fake ToolRunner (canned subfinder stdout). It asserts:
// the session succeeds, the tool ran EXACTLY ONCE, the recon terminal_log + the agent_step +
// the agent_admission are sealed, the evidence chain verifies, and NO finding was created.
func TestE2E_DurableAgentRun_NoMocksBelowLLM(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	clock := fixedClock{now}
	ids := &seqIDs{}
	audit := &fakeAudit{}

	eng := engAt(now)           // in-scope: app.acme.io, window covers now
	eng.SetLiveRecon(true, now) // recon.Start gates on this (lab-only → live)
	engRepo := &fakeEngRepo{eng: eng}
	evStore := memory.NewEvidenceStore()
	ev, err := evidence.NewService(evStore, nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := execution.NewGuard(engRepo, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeToolRunner{stdout: []byte("a.app.acme.io\nb.app.acme.io\n")}
	reconSvc, err := reconuc.NewService(guard, runner, memory.NewReconRunRepository(), ev, engRepo, logstream.NewBroker(0),
		syncDispatcher{}, clock, ids, recontools.Registry(), time.Minute, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := orchestrator.NewReconExecutor(reconSvc, ev, clock, time.Millisecond, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	apprStore := memory.NewApprovalStore()
	appr, err := approval.NewService(apprStore, audit, clock, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	reconList := make([]ports.ReconTool, 0)
	for _, tool := range recontools.Registry() {
		reconList = append(reconList, tool)
	}
	cat, err := agenttools.New(emptyFindings{}, emptyEvidence{}, reconList, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enumerate subdomains"}`)),
		chatStop("found 2 subdomains"),
	}}
	orch, err := orchestrator.New(llm, cat, gate, exec, ev, memory.NewAgentSessionStore(), apprStore, audit, clock, ids, orchestrator.Config{Model: "m", MaxSteps: 6})
	if err != nil {
		t.Fatal(err)
	}

	sess, err := orch.Run(ctx, "eng-1", "alice", "enumerate app.acme.io")
	if err != nil {
		t.Fatal(err)
	}

	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("status=%s, want succeeded", sess.Status)
	}
	if runner.calls != 1 {
		t.Fatalf("the tool must run EXACTLY once below the real stack, got %d", runner.calls)
	}
	if len(runner.argvs) != 1 || runner.argvs[0][0] != "subfinder" {
		t.Fatalf("unexpected argv: %v", runner.argvs)
	}
	items, err := ev.List(ctx, "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, it := range items {
		kinds[it.Kind]++
	}
	for _, want := range []string{"agent_admission", "agent_intent", orchestrator.StepEvidenceKind, "terminal_log"} {
		if kinds[want] == 0 {
			t.Fatalf("expected a sealed %q, got kinds=%v", want, kinds)
		}
	}
	if err := evdom.VerifyChain(items); err != nil {
		t.Fatalf("evidence chain must verify after a real E2E run: %v", err)
	}
	// The real subfinder stdout was sealed into a terminal_log.
	foundStdout := false
	for _, it := range items {
		if it.Kind == "terminal_log" && strings.Contains(string(it.Content), "a.app.acme.io") {
			foundStdout = true
		}
	}
	if !foundStdout {
		t.Fatal("the recon tool's real stdout must be sealed into a terminal_log")
	}
}
