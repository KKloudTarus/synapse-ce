package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/mcpserver"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	devidence "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	dfinding "github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	drecon "github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type findReader struct{}

func (findReader) ListByEngagement(context.Context, shared.ID) ([]dfinding.Finding, error) {
	return []dfinding.Finding{{ID: "f1", Title: "RCE", Severity: shared.SeverityHigh, Kind: dfinding.KindExploitation}}, nil
}

type evReader struct{}

func (evReader) ListByEngagement(context.Context, shared.ID) ([]devidence.Evidence, error) {
	return nil, nil
}

type noAudit struct{}

func (noAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type reconTool struct{}

func (reconTool) Name() string                         { return "subfinder" }
func (reconTool) Binary() string                       { return "subfinder" }
func (reconTool) Action() string                       { return "recon.subfinder" }
func (reconTool) CapabilitySensitive() bool            { return false }
func (reconTool) Accepts(k engagement.TargetKind) bool { return k == engagement.TargetDomain }
func (reconTool) Parse([]byte) ([]drecon.Result, error) {
	return nil, nil
}
func (reconTool) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: "subfinder", Args: []string{"-d", t.Value}}, nil
}

type investigationReader struct{ incident incident.Incident }

func (r investigationReader) Get(ctx context.Context, id shared.ID) (incident.Incident, error) {
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant != "tenant-1" {
		return incident.Incident{}, shared.ErrForbidden
	}
	if id != r.incident.ID {
		return incident.Incident{}, shared.ErrNotFound
	}
	return r.incident, nil
}

func (r investigationReader) ListByDetectionIDs(ctx context.Context, ids []shared.ID, _ int) ([]incident.Incident, error) {
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant != "tenant-1" {
		return nil, shared.ErrForbidden
	}
	for _, id := range ids {
		if id == "det-1" {
			return []incident.Incident{r.incident}, nil
		}
	}
	return nil, nil
}

type investigationDetections struct{ observed time.Time }

func (d investigationDetections) ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error) {
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant != "tenant-1" || engagementID != "eng-1" {
		return nil, shared.ErrForbidden
	}
	return []detection.Record{{
		ID: "det-1", TenantID: "tenant-1", EngagementID: "eng-1", AssetID: "asset-1",
		Detection: detection.Detection{Observed: d.observed},
	}}, nil
}

type investigationTimeline struct{ observed time.Time }

func (t investigationTimeline) Query(ctx context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant != "tenant-1" || q.AssetID != "asset-1" {
		return nil, shared.ErrForbidden
	}
	return []endpoint.TimelineEntry{{
		OccurredAt: t.observed, TenantID: "tenant-1", AssetID: "asset-1", EntityKind: endpoint.EntityProcess,
		EntityID: "process-1", Kind: endpoint.TimelineProcessExec, EventID: "event-1", Summary: "exec token=secret-value",
	}}, nil
}

type investigationProposer struct{ got judgment.Judgment }

func (p *investigationProposer) Propose(_ context.Context, proposer string, engagementID shared.ID, capability judgment.Capability, subjectKind judgment.SubjectKind, subjectID shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	j, err := judgment.New("judgment-1", engagementID, capability, subjectKind, subjectID, claim, proposer, time.Unix(2_000_000, 0).UTC())
	p.got = j
	return j, err
}

func newServer(t *testing.T) http.Handler {
	t.Helper()
	cat, err := agenttools.New(findReader{}, evReader{}, []ports.ReconTool{reconTool{}}, noAudit{}, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := mcpserver.New(cat, "tenant-1", "eng-1", "secret-token", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func newInvestigationServer(t *testing.T) (http.Handler, *investigationProposer) {
	t.Helper()
	cat, err := agenttools.New(findReader{}, evReader{}, []ports.ReconTool{reconTool{}}, noAudit{}, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(2_000_000, 0).UTC()
	inc := incident.Incident{
		ID: "incident-1", AssetID: "asset-1", Title: "Suspicious process", Severity: shared.SeverityHigh,
		State: incident.StateInvestigating, Disposition: incident.DispositionUnknown,
		DetectionIDs: []shared.ID{"det-1"}, CreatedAt: observed, UpdatedAt: observed,
	}
	if err := cat.EnableInvestigation(agenttools.InvestigationToolset{
		Incidents: investigationReader{incident: inc}, Detections: investigationDetections{observed: observed},
		Timeline: investigationTimeline{observed: observed},
	}); err != nil {
		t.Fatal(err)
	}
	proposer := &investigationProposer{}
	cat.EnableJudgments(proposer)
	srv, err := mcpserver.New(cat, "tenant-1", "eng-1", "secret-token", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), proposer
}

func rpc(t *testing.T, h http.Handler, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func TestMCPRequiresToken(t *testing.T) {
	h := newServer(t)
	code, _ := rpc(t, h, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("missing token must 401, got %d", code)
	}
	code, _ = rpc(t, h, "wrong", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong token must 401, got %d", code)
	}
}

func TestMCPInitialize(t *testing.T) {
	h := newServer(t)
	_, out := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	res, _ := out["result"].(map[string]any)
	if res == nil || res["protocolVersion"] == "" {
		t.Fatalf("initialize result wrong: %v", out)
	}
	si, _ := res["serverInfo"].(map[string]any)
	if si["name"] != "synapse-mcp" {
		t.Errorf("serverInfo.name = %v", si["name"])
	}
}

func TestMCPToolsList(t *testing.T) {
	h := newServer(t)
	_, out := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res, _ := out["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	expected := map[string]bool{
		agenttools.ToolListFindings:            true,
		agenttools.ToolGetFindingDetail:        true,
		agenttools.ToolListSASTValidation:      true,
		agenttools.ToolPlanRuntimeVerification: true,
		agenttools.ToolListEvidence:            true,
		agenttools.ToolVerifyCustody:           true,
		agenttools.ToolListReconTools:          true,
		agenttools.ToolStartRecon:              true,
		agenttools.ToolEvidenceSufficiency:     true,
	}
	actual := make(map[string]bool, len(tools))
	for _, tt := range tools {
		m := tt.(map[string]any)
		name := m["name"].(string)
		if actual[name] {
			t.Errorf("duplicate tool name: %s", name)
			continue
		}
		actual[name] = true
	}
	for name := range expected {
		if !actual[name] {
			t.Errorf("missing expected tool: %s", name)
		}
	}
	for name := range actual {
		if !expected[name] {
			t.Errorf("unexpected tool: %s", name)
		}
	}
}

func TestMCPToolsCallReadTool(t *testing.T) {
	h := newServer(t)
	_, out := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_findings","arguments":{}}}`)
	res, _ := out["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("read tool should not error: %v", res)
	}
	text := contentText(t, res)
	if !strings.Contains(text, "RCE") {
		t.Errorf("list_findings should return the finding data, got %q", text)
	}
}

func TestMCPToolsCallProposalNotExecuted(t *testing.T) {
	h := newServer(t)
	_, out := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start_recon","arguments":{"tool":"subfinder","target":"app.acme.io","rationale":"x"}}}`)
	res, _ := out["result"].(map[string]any)
	text := contentText(t, res)
	if !strings.Contains(text, "proposal_requires_human_approval") {
		t.Errorf("start_recon over MCP must return a proposal envelope (not execute), got %q", text)
	}
}

func TestMCPInvestigationIsScopedRedactedAndProposeOnly(t *testing.T) {
	h, proposer := newInvestigationServer(t)
	_, listed := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := listed["result"].(map[string]any)["tools"].([]any)
	want := map[string]bool{
		agenttools.ToolListIncidents: false, agenttools.ToolGetIncidentContext: false, agenttools.ToolProposeInvestigation: false,
	}
	for _, raw := range tools {
		name := raw.(map[string]any)["name"].(string)
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing investigation tool %s", name)
		}
	}

	_, contextOut := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_incident_context","arguments":{"incident_id":"incident-1"}}}`)
	contextText := contentText(t, contextOut["result"].(map[string]any))
	if strings.Contains(contextText, "secret-value") || !strings.Contains(contextText, "[REDACTED]") {
		t.Fatalf("MCP incident context was not redacted: %s", contextText)
	}

	_, proposed := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"propose_investigation","arguments":{"incident_id":"incident-1","tactic":"lateral_movement","confidence":82,"drivers":["network_fanout_spike"],"relevant_event_ids":["event-1"],"suggested_next_step":"retro_hunt_similar_activity"}}}`)
	proposalText := contentText(t, proposed["result"].(map[string]any))
	if !strings.Contains(proposalText, `"state":"proposed"`) || proposer.got.EvidenceScore != 0 || proposer.got.State != judgment.StateProposed {
		t.Fatalf("MCP must record only a score-0 proposed judgment: %s %+v", proposalText, proposer.got)
	}
	if proposer.got.Capability != judgment.CapInvestigation || proposer.got.SubjectID != "incident-1" {
		t.Fatalf("wrong investigation judgment: %+v", proposer.got)
	}

	_, outside := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_incident_context","arguments":{"incident_id":"incident-other"}}}`)
	if outside["result"].(map[string]any)["isError"] != true {
		t.Fatalf("cross-scope incident should fail closed: %v", outside)
	}
}

func TestMCPUnknownMethod(t *testing.T) {
	h := newServer(t)
	_, out := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","id":9,"method":"nope"}`)
	if out["error"] == nil {
		t.Fatalf("unknown method must return a JSON-RPC error, got %v", out)
	}
}

func TestMCPNotificationNoResponse(t *testing.T) {
	h := newServer(t)
	code, out := rpc(t, h, "secret-token", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if code != http.StatusAccepted || len(out) != 0 {
		t.Fatalf("a notification must get 202 with no body, got code=%d body=%v", code, out)
	}
}

func contentText(t *testing.T, res map[string]any) string {
	t.Helper()
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in result: %v", res)
	}
	return content[0].(map[string]any)["text"].(string)
}
