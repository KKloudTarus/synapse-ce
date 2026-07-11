package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	devidence "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	dfinding "github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	drecon "github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// --- compact fakes for the agent HTTP harness ---

type scriptLLMH struct {
	steps []ports.ChatResponse
	i     int
}

func (l *scriptLLMH) Chat(context.Context, ports.ChatRequest) (ports.ChatResponse, error) {
	if l.i >= len(l.steps) {
		return ports.ChatResponse{Content: "done", FinishReason: "stop", Usage: agent.Usage{TotalTokens: 3}}, nil
	}
	r := l.steps[l.i]
	l.i++
	return r, nil
}

type noExecH struct{ calls int }

func (e *noExecH) Execute(context.Context, safety.AdmittedAction) (orchestrator.Observation, error) {
	e.calls++
	return orchestrator.Observation{Output: []byte("ok"), Summary: "ok"}, nil
}

type engRepoH struct{ eng *engagement.Engagement }

func (engRepoH) Create(context.Context, *engagement.Engagement) error { return nil }
func (engRepoH) Update(context.Context, *engagement.Engagement) error { return nil }
func (engRepoH) Delete(context.Context, shared.ID) error              { return nil }
func (f engRepoH) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f engRepoH) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (engRepoH) List(context.Context, shared.ID) ([]*engagement.Engagement, error) { return nil, nil }

type findReadH struct{}

func (findReadH) ListByEngagement(context.Context, shared.ID) ([]dfinding.Finding, error) {
	return nil, nil
}

type emptyEvReadH struct{}

func (emptyEvReadH) ListByEngagement(context.Context, shared.ID) ([]devidence.Evidence, error) {
	return nil, nil
}

type auditH struct{}

func (auditH) Record(context.Context, ports.AuditEntry) error { return nil }

type reconToolH struct{}

func (reconToolH) Name() string                          { return "subfinder" }
func (reconToolH) Binary() string                        { return "subfinder" }
func (reconToolH) Action() string                        { return "recon.subfinder" }
func (reconToolH) CapabilitySensitive() bool             { return false }
func (reconToolH) Accepts(k engagement.TargetKind) bool  { return k == engagement.TargetDomain }
func (reconToolH) Parse([]byte) ([]drecon.Result, error) { return nil, nil }
func (reconToolH) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: "subfinder", Args: []string{"-d", t.Value}}, nil
}

func engAtH(now time.Time) *engagement.Engagement {
	e, _ := engagement.New("eng-1", "", "Acme", "Acme", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	e.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.acme.io"}}}
	return e
}

// agentTestRig wires a real orchestrator + stores into a Router with the agent routes enabled.
type agentTestRig struct {
	rt        *Router
	sessions  *memory.AgentSessionStore
	apprStore *memory.ApprovalStore
	exec      *noExecH
}

func newAgentRig(t *testing.T, mode agent.ApprovalMode, steps []ports.ChatResponse) agentTestRig {
	t.Helper()
	now := time.Now().UTC()
	clock := idgen.SystemClock{}
	ids := idgen.RandomID{}
	audit := auditH{}
	guard, err := execution.NewGuard(engRepoH{eng: engAtH(now)}, clock, audit)
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
	cat, err := agenttools.New(findReadH{}, emptyEvReadH{}, []ports.ReconTool{reconToolH{}}, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	sessions := memory.NewAgentSessionStore()
	exec := &noExecH{}
	orch, err := orchestrator.New(&scriptLLMH{steps: steps}, cat, gate, exec, ev, sessions, apprStore, audit, clock, ids, orchestrator.Config{Model: "m", MaxSteps: 6})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: logging.New("error")}
	rt.EnableAgent(orch, sessions, appr, apprStore, nil, 8, 256) // nil queue → bounded inline dispatch
	return agentTestRig{rt: rt, sessions: sessions, apprStore: apprStore, exec: exec}
}

// TestReserveAgentSlot_Backpressure proves the inline path is bounded: once concurrency slots
// are taken, a further reservation is refused (→ 503), and a release frees a slot.
func TestReserveAgentSlot_Backpressure(t *testing.T) {
	rt := &Router{log: logging.New("error")}
	rt.EnableAgent(nil, nil, nil, nil, nil, 1, 8) // inline (nil queue), concurrency 1
	rel, ok := rt.admitAgent(context.Background())
	if !ok {
		t.Fatal("first reservation should succeed")
	}
	if _, ok2 := rt.admitAgent(context.Background()); ok2 {
		t.Fatal("second reservation must be refused (saturated → 503)")
	}
	rel()
	if _, ok3 := rt.admitAgent(context.Background()); !ok3 {
		t.Fatal("a slot must free after release")
	}
}

// TestReserveAgentSlot_DurableUnbounded: the durable path (non-nil queue) never blocks on the
// inline semaphore – the queue is the buffer.
func TestReserveAgentSlot_DurableAlwaysReserves(t *testing.T) {
	rt := &Router{log: logging.New("error")}
	rt.EnableAgent(nil, nil, nil, nil, memory.NewJobQueue(idgen.RandomID{}, func() time.Time { return time.Unix(1, 0) }), 1, 8)
	for i := 0; i < 5; i++ {
		if _, ok := rt.admitAgent(context.Background()); !ok {
			t.Fatalf("durable path must always reserve, failed at %d", i)
		}
	}
}

func withPrincipal(req *http.Request, id, role string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: id, Name: id, Role: role}))
}

func TestStartAgentSessionReturnsSession(t *testing.T) {
	rig := newAgentRig(t, agent.ModeAuto, []ports.ChatResponse{{Content: "all done", FinishReason: "stop"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/agent/sessions", strings.NewReader(`{"goal":"enumerate"}`))
	req.SetPathValue("id", "eng-1")
	req = withPrincipal(req, "alice", "admin")
	rec := httptest.NewRecorder()

	rig.rt.startAgentSession(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
	var sess agent.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	if sess.ID == "" || sess.EngagementID != "eng-1" || sess.InitiatedBy != "alice" {
		t.Fatalf("unexpected session: %+v", sess)
	}
	// The inline dispatch drives the (immediately-stopping) run to completion shortly after.
	waitFor(t, func() bool {
		got, _ := rig.sessions.GetSession(context.Background(), sess.ID)
		return got.Status == agent.StatusSucceeded
	})
}

func TestDecideApprovalRejectsMachineRole(t *testing.T) {
	rig := newAgentRig(t, agent.ModeManual, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/agent/approvals/a1/decide", strings.NewReader(`{"approve":true}`))
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("aid", "a1")
	req = withPrincipal(req, "mcp-bot", "mcp")
	rec := httptest.NewRecorder()

	// Routed through the RBAC gate as in production: a machine role lacks PermReview → 403,
	// before the handler runs (separation of duties, now centralized in authz/the matrix).
	rig.rt.authz(userdom.PermReview, rig.rt.decideAgentApproval)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a machine role must not decide approvals: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgentSessionEngagementScoped(t *testing.T) {
	rig := newAgentRig(t, agent.ModeAuto, []ports.ChatResponse{{Content: "done", FinishReason: "stop"}})
	// Seed a session under eng-1.
	sess, err := rig.rt.agent.orch.Start(context.Background(), "eng-1", "alice", "go")
	if err != nil {
		t.Fatal(err)
	}
	// Request it under a DIFFERENT engagement id → 404 (no cross-engagement read).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-2/agent/sessions/"+sess.ID.String(), nil)
	req.SetPathValue("id", "eng-2")
	req.SetPathValue("sid", sess.ID.String())
	req = withPrincipal(req, "alice", "admin")
	rec := httptest.NewRecorder()
	rig.rt.getAgentSession(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-engagement session read must 404, got %d", rec.Code)
	}
}

func TestDecideApprovalExecutesOnResume(t *testing.T) {
	// Manual mode: the LLM proposes an in-scope recon, the session suspends, a human approves,
	// and decide → resume executes it.
	steps := []ports.ChatResponse{
		{ToolCalls: []agent.ToolCall{{ID: "c1", Name: agenttools.ToolStartRecon, Arguments: json.RawMessage(`{"tool":"subfinder","target":"app.acme.io","rationale":"enum"}`)}}, FinishReason: "tool_calls", Usage: agent.Usage{TotalTokens: 5}},
		{Content: "done", FinishReason: "stop"},
	}
	rig := newAgentRig(t, agent.ModeManual, steps)
	ctx := context.Background()
	sess, err := rig.rt.agent.orch.Run(ctx, "eng-1", "alice", "enumerate")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != agent.StatusAwaitingApproval {
		t.Fatalf("expected suspend, got %s", sess.Status)
	}
	pend, _ := rig.apprStore.Pending(ctx, "eng-1")
	if len(pend) != 1 {
		t.Fatalf("expected 1 pending approval, got %d", len(pend))
	}

	body := `{"approve":true,"reason":"ok"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/agent/approvals/"+pend[0].ID.String()+"/decide", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("aid", pend[0].ID.String())
	req = withPrincipal(req, "bob", "admin")
	rec := httptest.NewRecorder()
	rig.rt.decideAgentApproval(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Inline resume executes the approved action + completes.
	waitFor(t, func() bool {
		got, _ := rig.sessions.GetSession(ctx, sess.ID)
		return got.Status == agent.StatusSucceeded && rig.exec.calls == 1
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

// TestAdmitAgentDurableBackpressure covers the durable-path admission cap: once the queue
// holds queueDepth not-yet-terminal agent jobs, admission is refused (the handler returns
// 503 + Retry-After) so the jobs table cannot grow without bound.
func TestAdmitAgentDurableBackpressure(t *testing.T) {
	q := memory.NewJobQueue(idgen.RandomID{}, func() time.Time { return time.Unix(1, 0) })
	rt := &Router{log: logging.New("error"), agent: &agentDeps{queue: q, queueDepth: 2}}
	ctx := context.Background()
	if _, ok := rt.admitAgent(ctx); !ok {
		t.Fatal("must admit while under the queue-depth cap")
	}
	// Fill the queue to the cap with agent-kind jobs.
	if _, err := q.Enqueue(ctx, orchestrator.JobKind, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, orchestrator.JobKind, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if _, ok := rt.admitAgent(ctx); ok {
		t.Fatal("must REJECT once the queue is at/over the queueDepth cap (503)")
	}
	// The cap is per-kind: a fresh agent with a higher cap admits the same queue state,
	// and recon jobs never count against the agent cap.
	if _, err := q.Enqueue(ctx, "recon", []byte("r")); err != nil {
		t.Fatal(err)
	}
	high := &Router{log: logging.New("error"), agent: &agentDeps{queue: q, queueDepth: 3}}
	if _, ok := high.admitAgent(ctx); !ok {
		t.Fatal("agent cap counts only the 2 agent jobs (not the recon job), so depth 2 < cap 3 must admit")
	}
}
