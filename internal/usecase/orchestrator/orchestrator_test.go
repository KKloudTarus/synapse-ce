package orchestrator_test

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	drecon "github.com/KKloudTarus/synapse-ce/internal/domain/recon"
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

// --- shared fakes ---

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct {
	mu sync.Mutex
	n  int
}

// NewID is mutex-guarded: the parallel path calls it concurrently (evidence seals mint ids
// from several goroutines). The production idgen.RandomID is crypto/rand (already safe); this
// keeps the test double honest under -race.
func (g *seqIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID("id-" + strconv.Itoa(g.n))
}

// fakeAudit is mutex-guarded for the same reason (concurrent runProposal → gate → audit). The
// production audit loggers (file: sync.Mutex; postgres: pgxpool) are already concurrency-safe.
type fakeAudit struct {
	mu      sync.Mutex
	actions []string
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, e.Action)
	return nil
}

type fakeEngRepo struct{ eng *engagement.Engagement }

func (f *fakeEngRepo) Create(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Update(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Delete(context.Context, shared.ID) error              { return nil }
func (f *fakeEngRepo) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f *fakeEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f *fakeEngRepo) List(context.Context, shared.ID) ([]*engagement.Engagement, error) {
	return nil, nil
}

func engAt(now time.Time) *engagement.Engagement {
	e, _ := engagement.New(shared.ID("eng-1"), shared.ID(""), "Acme", "Acme", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	e.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.acme.io"}}}
	return e
}

// emptyFindings / emptyEvidence satisfy the catalog's read interfaces (no data needed here).
type emptyFindings struct{}

func (emptyFindings) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return nil, nil
}

type emptyEvidence struct{}

func (emptyEvidence) ListByEngagement(context.Context, shared.ID) ([]evdom.Evidence, error) {
	return nil, nil
}

// fakeRecon is a passive recon tool descriptor (subfinder-like) for the catalog.
type fakeRecon struct{}

func (fakeRecon) Name() string                         { return "subfinder" }
func (fakeRecon) Binary() string                       { return "subfinder" }
func (fakeRecon) Action() string                       { return "recon.subfinder" }
func (fakeRecon) CapabilitySensitive() bool            { return false }
func (fakeRecon) Accepts(k engagement.TargetKind) bool { return k == engagement.TargetDomain }
func (fakeRecon) Parse([]byte) ([]drecon.Result, error) {
	return nil, nil
}
func (fakeRecon) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: "subfinder", Args: []string{"-silent", "-json", "-d", t.Value}}, nil
}

// --- record/replay fake LLM (the offline CI driver) ---

type scriptLLM struct {
	steps []ports.ChatResponse
	i     int
	reqs  []ports.ChatRequest
}

func (l *scriptLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	l.reqs = append(l.reqs, req)
	if l.i >= len(l.steps) {
		return ports.ChatResponse{Content: "done", FinishReason: "stop", Usage: agent.Usage{TotalTokens: 5}}, nil
	}
	r := l.steps[l.i]
	l.i++
	return r, nil
}

// loopingLLM always proposes the same read tool – never stops (drives the budget/step-cap test).
type loopingLLM struct{ call agent.ToolCall }

func (l loopingLLM) Chat(_ context.Context, _ ports.ChatRequest) (ports.ChatResponse, error) {
	return ports.ChatResponse{ToolCalls: []agent.ToolCall{l.call}, FinishReason: "tool_calls", Usage: agent.Usage{TotalTokens: 10}}, nil
}

// --- fake executor ---

type fakeExecutor struct {
	calls   int
	targets []string
	out     orchestrator.Observation
	err     error
}

func (e *fakeExecutor) Execute(_ context.Context, adm safety.AdmittedAction) (orchestrator.Observation, error) {
	e.calls++
	e.targets = append(e.targets, adm.Action().Target.Value)
	if e.err != nil {
		return orchestrator.Observation{}, e.err
	}
	return e.out, nil
}

// --- harness ---

func newOrch(t *testing.T, llm ports.LLM, exec orchestrator.Executor, mode agent.ApprovalMode, cfg orchestrator.Config) (*orchestrator.Orchestrator, *evidence.Service, *memory.AgentSessionStore) {
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
	cat, err := agenttools.New(emptyFindings{}, emptyEvidence{}, []ports.ReconTool{fakeRecon{}}, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	sessions := memory.NewAgentSessionStore()
	if cfg.Model == "" {
		cfg.Model = "test-model"
	}
	orch, err := orchestrator.New(llm, cat, gate, exec, ev, sessions, apprStore, audit, clock, ids, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return orch, ev, sessions
}

func toolCall(id, name, args string) agent.ToolCall {
	return agent.ToolCall{ID: id, Name: name, Arguments: json.RawMessage(args)}
}

func chatTool(tc agent.ToolCall) ports.ChatResponse {
	return ports.ChatResponse{ToolCalls: []agent.ToolCall{tc}, FinishReason: "tool_calls", Usage: agent.Usage{TotalTokens: 10}}
}

func chatStop(text string) ports.ChatResponse {
	return ports.ChatResponse{Content: text, FinishReason: "stop", Usage: agent.Usage{TotalTokens: 5}}
}

func countKind(t *testing.T, ev *evidence.Service, kind string) int {
	t.Helper()
	items, err := ev.List(context.Background(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, it := range items {
		if it.Kind == kind {
			n++
		}
	}
	return n
}

// --- the AC tests ---

// TestInScopeProposalRunsAndSeals: a fake LLM proposes an IN-SCOPE start_recon; the gate
// admits it (auto mode), the executor runs it, and the step is sealed.
func TestInScopeProposalRunsAndSeals(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enumerate subdomains"}`)),
		chatStop("found 2 hosts"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("a.app.acme.io\nb.app.acme.io"), Summary: "2 hosts"}}
	orch, ev, sessions := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "enumerate app.acme.io")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("status = %s, want succeeded", sess.Status)
	}
	if exec.calls != 1 || len(exec.targets) != 1 || exec.targets[0] != "app.acme.io" {
		t.Fatalf("executor must run once against the in-scope target, got calls=%d targets=%v", exec.calls, exec.targets)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 1 {
		t.Fatalf("expected exactly 1 sealed agent_step, got %d", n)
	}
	// The gate also sealed an admission; the transcript was persisted with the fenced observation.
	if n := countKind(t, ev, "agent_admission"); n != 1 {
		t.Fatalf("expected the gate to seal 1 admission, got %d", n)
	}
	msgs, _ := sessions.Messages(context.Background(), sess.ID)
	if !hasFencedObservation(msgs, "a.app.acme.io") {
		t.Fatalf("transcript should contain the fenced observation; got %d messages", len(msgs))
	}
}

// TestOutOfScopeProposalDeniedNeverExecuted is the headline AC: an out-of-scope proposal is
// denied in Go and the executor is NEVER called; nothing is sealed as a step.
func TestOutOfScopeProposalDeniedNeverExecuted(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"evil.com","rationale":"oops"}`)),
		chatStop("understood, stopping"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("SHOULD NOT RUN")}}
	orch, ev, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "scan evil.com")
	if err != nil {
		t.Fatal(err)
	}
	if exec.calls != 0 {
		t.Fatalf("out-of-scope action must NEVER be executed, got %d executor calls", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 0 {
		t.Fatalf("an unexecuted action must seal no agent_step, got %d", n)
	}
	if n := countKind(t, ev, "agent_admission"); n != 0 {
		t.Fatalf("a denied action must not be admitted/sealed, got %d", n)
	}
	if sess.Status != agent.StatusSucceeded { // model stopped after the denial was fed back
		t.Fatalf("status = %s, want succeeded (denial fed back, model stopped)", sess.Status)
	}
}

// TestReadToolFeedsDataNoExecute: a read tool returns data; nothing is executed or sealed.
func TestReadToolFeedsDataNoExecute(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolListFindings, `{}`)),
		chatStop("no findings yet"),
	}}
	exec := &fakeExecutor{}
	orch, ev, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "list findings")
	if err != nil {
		t.Fatal(err)
	}
	if exec.calls != 0 {
		t.Fatalf("a read tool must not execute anything, got %d", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 0 {
		t.Fatalf("a read tool must seal no agent_step, got %d", n)
	}
	if sess.Status != agent.StatusSucceeded {
		t.Fatalf("status = %s, want succeeded", sess.Status)
	}
}

// TestManualModeSuspends: in manual mode an Active proposal is pending → the session suspends
// (awaiting_approval) and nothing executes.
func TestManualModeSuspends(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enum"}`)),
	}}
	exec := &fakeExecutor{}
	orch, ev, _ := newOrch(t, llm, exec, agent.ModeManual, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "enumerate")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusAwaitingApproval {
		t.Fatalf("status = %s, want awaiting_approval", sess.Status)
	}
	if exec.calls != 0 {
		t.Fatalf("a pending action must not execute, got %d", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 0 {
		t.Fatalf("a pending action seals no step, got %d", n)
	}
}

// TestStepBudgetTerminates: a model that never stops is bounded by MaxSteps → failed.
func TestStepBudgetTerminates(t *testing.T) {
	llm := loopingLLM{call: toolCall("c1", agenttools.ToolListFindings, `{}`)}
	exec := &fakeExecutor{}
	orch, _, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 3})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "loop forever")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusFailed {
		t.Fatalf("an unbounded model must hit the step cap and fail, got %s", sess.Status)
	}
	if sess.Steps != 3 {
		t.Fatalf("expected exactly MaxSteps=3 planning turns, got %d", sess.Steps)
	}
}

// TestOneActionPerTurn: if the model emits parallel tool calls in one turn, the orchestrator
// processes only the FIRST (the rest are dropped, to be re-proposed), so each turn stays
// balanced/replayable. Here the first is in-scope start_recon; a second (out-of-scope) call in
// the same turn must NOT be executed this turn.
func TestOneActionPerTurn(t *testing.T) {
	twoCalls := ports.ChatResponse{
		ToolCalls: []agent.ToolCall{
			toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"first"}`),
			toolCall("c2", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"second"}`),
		},
		FinishReason: "tool_calls", Usage: agent.Usage{TotalTokens: 10},
	}
	llm := &scriptLLM{steps: []ports.ChatResponse{twoCalls, chatStop("done")}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("h"), Summary: "1 host"}}
	orch, ev, sessions := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})

	sess, err := orch.Run(context.Background(), "eng-1", "alice", "go")
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one execution + one sealed step despite two proposed calls in the turn.
	if exec.calls != 1 {
		t.Fatalf("only the first of parallel calls should execute, got %d", exec.calls)
	}
	if n := countKind(t, ev, orchestrator.StepEvidenceKind); n != 1 {
		t.Fatalf("expected 1 sealed step, got %d", n)
	}
	// The persisted assistant turn must carry exactly ONE tool_call (balanced → replayable).
	msgs, _ := sessions.Messages(context.Background(), sess.ID)
	for _, m := range msgs {
		if m.Role == agent.RoleAssistant && len(m.ToolCalls) > 1 {
			t.Fatalf("a persisted assistant turn must carry at most one tool_call, got %d", len(m.ToolCalls))
		}
	}
}

func TestNewValidates(t *testing.T) {
	_, err := orchestrator.New(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, orchestrator.Config{})
	if err == nil {
		t.Fatal("nil deps must fail validation")
	}
}

// --- helpers ---

func hasFencedObservation(msgs []agent.Message, needle string) bool {
	for _, m := range msgs {
		if m.Role == agent.RoleTool && strings.Contains(m.Content, "untrusted-tool-output") && strings.Contains(m.Content, needle) {
			return true
		}
	}
	return false
}
