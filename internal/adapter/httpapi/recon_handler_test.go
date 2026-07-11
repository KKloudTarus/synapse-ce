package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/logstream"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	reconuc "github.com/KKloudTarus/synapse-ce/internal/usecase/recon"
)

type syncDispatcher struct{}

func (syncDispatcher) Submit(task func(context.Context)) error {
	task(context.Background())
	return nil
}

type fakeReconRunner struct{ out string }

func (f fakeReconRunner) Run(context.Context, ports.ToolSpec) (ports.ToolResult, error) {
	return ports.ToolResult{Stdout: []byte(f.out)}, nil
}

type fakeReconTool struct{}

func (fakeReconTool) Name() string                     { return "subfinder" }
func (fakeReconTool) Binary() string                   { return "subfinder" }
func (fakeReconTool) Action() string                   { return "recon.subfinder" }
func (fakeReconTool) CapabilitySensitive() bool        { return false }
func (fakeReconTool) Accepts(k engdom.TargetKind) bool { return k == engdom.TargetDomain }
func (fakeReconTool) BuildArgs(t engdom.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: "subfinder", Args: []string{"-d", t.Value}}, nil
}
func (fakeReconTool) Parse([]byte) ([]recon.Result, error) {
	return []recon.Result{
		{Kind: recon.ResultSubdomain, Value: "www.example.com"},
		{Kind: recon.ResultSubdomain, Value: "out.attacker.test"},
	}, nil
}

func newReconRouter(t *testing.T, liveRecon bool) *Router {
	t.Helper()
	clock := fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	audit := &fakeAudit{}
	engRepo := memory.NewEngagementRepository()
	_ = engRepo.Create(context.Background(), &engdom.Engagement{
		ID: "e1", Name: "lab", Status: engdom.StatusActive,
		Scope: engdom.Scope{InScope: []engdom.Target{
			{Kind: engdom.TargetDomain, Value: "example.com"},
			{Kind: engdom.TargetDomain, Value: "*.example.com"},
		}},
		LiveReconEnabled: liveRecon,
	})
	guard, err := execution.NewGuard(engRepo, clock, audit)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	ev, err := evidenceuc.NewService(memory.NewEvidenceStore(), blob.NewMemory(), audit, clock, engIDs{})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	broker := logstream.NewBroker(0)
	svc, err := reconuc.NewService(guard, fakeReconRunner{out: "ignored-by-fake-parse"}, memory.NewReconRunRepository(), ev, engRepo, broker, syncDispatcher{}, clock, engIDs{}, map[string]ports.ReconTool{"subfinder": fakeReconTool{}}, time.Minute, 1<<20, false)
	if err != nil {
		t.Fatalf("recon service: %v", err)
	}
	return &Router{log: discardLog(), recon: svc, logs: broker}
}

func startReq(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e1/recon/runs", strings.NewReader(body))
	req.SetPathValue("id", "e1")
	return req
}

func TestStartReconRunHappyPath(t *testing.T) {
	rt := newReconRouter(t, true)
	rec := httptest.NewRecorder()
	rt.startReconRun(rec, startReq(`{"tool":"subfinder","target":"example.com"}`))

	// POST returns 202 + the run record (queued – async semantics).
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var run recon.Run
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if run.ID == "" {
		t.Fatal("expected a run id in the response")
	}

	// The sync dispatcher (test) ran the work inline; GET shows the final state.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/e1/recon/runs/"+run.ID.String(), nil)
	getReq.SetPathValue("id", "e1")
	getReq.SetPathValue("rid", run.ID.String())
	getRec := httptest.NewRecorder()
	rt.getReconRun(getRec, getReq)

	var got recon.Run
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.Status != recon.StatusSucceeded {
		t.Errorf("status = %s, error = %q", got.Status, got.Error)
	}
	if got.ResultCount != 1 {
		t.Errorf("ResultCount = %d, want 1 (out.attacker.test dropped)", got.ResultCount)
	}
	if got.EvidenceID == "" {
		t.Error("expected sealed evidence id on the completed run")
	}
}

func TestStartReconRunForbiddenWhenLiveReconOff(t *testing.T) {
	rt := newReconRouter(t, false)
	rec := httptest.NewRecorder()
	rt.startReconRun(rec, startReq(`{"tool":"subfinder","target":"example.com"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (live recon disabled)", rec.Code)
	}
}

func TestStartReconRunOutOfScope(t *testing.T) {
	rt := newReconRouter(t, true)
	rec := httptest.NewRecorder()
	rt.startReconRun(rec, startReq(`{"tool":"subfinder","target":"not-mine.test"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (out of scope)", rec.Code)
	}
}

func TestGetReconRunCrossEngagement404(t *testing.T) {
	rt := newReconRouter(t, true)
	// Launch under e1.
	startRec := httptest.NewRecorder()
	rt.startReconRun(startRec, startReq(`{"tool":"subfinder","target":"example.com"}`))
	var run recon.Run
	_ = json.Unmarshal(startRec.Body.Bytes(), &run)

	// Read it via a DIFFERENT engagement in the path -> 404.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/other/recon/runs/"+run.ID.String(), nil)
	req.SetPathValue("id", "other")
	req.SetPathValue("rid", run.ID.String())
	rec := httptest.NewRecorder()
	rt.getReconRun(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-engagement read should 404, got %d", rec.Code)
	}
}

func TestStreamReconLogsReplaysClosedRun(t *testing.T) {
	rt := newReconRouter(t, true)
	startRec := httptest.NewRecorder()
	rt.startReconRun(startRec, startReq(`{"tool":"subfinder","target":"example.com"}`))
	var run recon.Run
	_ = json.Unmarshal(startRec.Body.Bytes(), &run)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/e1/recon/runs/"+run.ID.String()+"/logs", nil)
	req.SetPathValue("id", "e1")
	req.SetPathValue("rid", run.ID.String())
	rec := httptest.NewRecorder()
	rt.streamReconLogs(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("content-type = %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data:") || !strings.Contains(body, "event: done") {
		t.Errorf("SSE body missing log events / done marker:\n%s", body)
	}
	if !strings.Contains(body, "in-scope") {
		t.Error("expected an in-scope result line in the replayed log")
	}
}

func TestListReconTools(t *testing.T) {
	rt := newReconRouter(t, true)
	rec := httptest.NewRecorder()
	rt.listReconTools(rec, httptest.NewRequest(http.MethodGet, "/api/v1/recon/tools", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var tools []reconuc.ToolInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &tools); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "subfinder" {
		t.Errorf("tools = %+v", tools)
	}
}
