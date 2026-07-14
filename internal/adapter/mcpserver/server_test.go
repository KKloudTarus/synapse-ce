package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/mcpserver"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	devidence "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	dfinding "github.com/KKloudTarus/synapse-ce/internal/domain/finding"
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

func newServer(t *testing.T) http.Handler {
	t.Helper()
	cat, err := agenttools.New(findReader{}, evReader{}, []ports.ReconTool{reconTool{}}, noAudit{}, idgen.SystemClock{}, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := mcpserver.New(cat, "eng-1", "secret-token", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
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
