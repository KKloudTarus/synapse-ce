package analysis

// Live-AI demonstration for #162 (produce Kind=dast from a runtime safe-probe verification): a REAL
// 9router model proposes the SAST hypothesis (the typed CapSAST claim — CWE/location/rule), then a
// DISTINCT runtime verifier confirms it via the runtime path (VerifyRuntime, as the dastverifier does),
// and the confirmed judgment is projected into a Kind=dast finding — NOT Kind=sast. This exercises the
// full pipeline end-to-end (real analysis.Service routing + real findings.Service DAST recorder + real
// domain projection) with a real model in the proposer seat, proving the previously-inert KindDAST now
// has an end-to-end producer.
//
// Gated behind SYNAPSE_LIVE_AI=1 so the normal suite stays hermetic. Run:
//   SYNAPSE_LIVE_AI=1 SYNAPSE_LLM_BASE_URL=http://localhost:20128/v1 SYNAPSE_LLM_MODEL=cx/gpt-5.4 \
//     go test ./internal/usecase/analysis/ -run TestLiveAIRuntimeConfirmToDAST -v

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func extractJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func TestLiveAIRuntimeConfirmToDAST(t *testing.T) {
	if os.Getenv("SYNAPSE_LIVE_AI") != "1" {
		t.Skip("set SYNAPSE_LIVE_AI=1 to run the live 9router demonstration")
	}
	base := os.Getenv("SYNAPSE_LLM_BASE_URL")
	if base == "" {
		base = "http://localhost:20128/v1"
	}
	model := os.Getenv("SYNAPSE_LLM_MODEL")
	if model == "" {
		model = "cx/gpt-5.4"
	}
	llm, err := openai.New(base, os.Getenv("SYNAPSE_LLM_API_KEY"), model, 90*time.Second)
	if err != nil {
		t.Fatalf("openai client: %v", err)
	}

	// The model proposes the typed SAST hypothesis (mirrors the agent's propose_sast_validation tool).
	resp, cerr := llm.Chat(context.Background(), ports.ChatRequest{
		Model:       model,
		Temperature: 0,
		MaxTokens:   300,
		Messages: []agent.Message{
			{Role: agent.RoleSystem, Content: "You are a SAST triage assistant. Output ONLY a JSON object " +
				`{"cwe":"CWE-###","location":"path:line or pkg.Symbol","rule":"a-taint-rule-token"} for the described vulnerability. No prose.`},
			{Role: agent.RoleUser, Content: "A handler builds a SQL query by string-concatenating an unsanitized HTTP query parameter and executes it against the database in internal/app/dao.go around line 88. Classify it."},
		},
	})
	if cerr != nil {
		t.Fatalf("live chat: %v", cerr)
	}
	raw := extractJSONObject(resp.Content)
	t.Logf("model=%s raw=%s", model, resp.Content)
	if raw == "" {
		t.Fatalf("model returned no JSON: %q", resp.Content)
	}
	var out struct {
		CWE      string `json:"cwe"`
		Location string `json:"location"`
		Rule     string `json:"rule"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("parse model JSON %q: %v", raw, err)
	}
	claim := judgment.SASTClaim{CWE: strings.TrimSpace(out.CWE), Location: strings.TrimSpace(out.Location), Rule: strings.TrimSpace(out.Rule)}
	if verr := claim.Validate(); verr != nil {
		t.Fatalf("model produced an invalid SAST claim %+v: %v", claim, verr)
	}
	t.Logf("AI-proposed CapSAST claim: cwe=%s location=%s rule=%s", claim.CWE, claim.Location, claim.Rule)

	// Real analysis.Service (fake store/sealer/audit via newSvc) + a REAL findings.Service over a memory
	// repo as the DAST recorder. A SAST recorder is also wired to PROVE the runtime path does not double-emit.
	svc, _, _, _ := newSvc()
	findingRepo := memory.NewFindingRepository()
	findingsSvc := findings.NewService(findingRepo, nil, nil, &fakeAudit{}, fakeClock{}, &fakeIDs{})
	sastRec := &fakeSASTRecorder{}
	svc.SetDASTRecorder(findingsSvc)
	svc.SetSASTRecorder(sastRec)

	eng := shared.ID("eng-live")
	// Proposer and verifier MUST be distinct (a claim can never confirm itself).
	j, err := svc.Propose(context.Background(), "system:taint-scan", eng, judgment.CapSAST, judgment.SubjectDataFlow, "flow-live", claim)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	confirmed, err := svc.VerifyRuntime(context.Background(), "runtime:probe", eng, j.ID, 88,
		"proof_class=runtime_confirmed; safe canary parameter reflected in a DB error, confirming injectable sink", j.Version)
	if err != nil {
		t.Fatalf("verify runtime: %v", err)
	}
	if confirmed.State != judgment.StateConfirmed {
		t.Fatalf("runtime verdict >= bar must confirm the judgment, got %s", confirmed.State)
	}

	got, err := findingRepo.ListByEngagement(context.Background(), eng)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly one emitted finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Kind != finding.KindDAST {
		t.Fatalf("a RUNTIME confirmation must emit Kind=dast, got %s", f.Kind)
	}
	if f.Reachability != "reachable" {
		t.Errorf("a runtime probe proves reachability, want reachable, got %q", f.Reachability)
	}
	if f.CWE != claim.CWE {
		t.Errorf("the AI-proposed CWE must carry through to the DAST finding, want %q got %q", claim.CWE, f.CWE)
	}
	if len(sastRec.calls) != 0 {
		t.Errorf("the runtime path must NOT also emit a Kind=sast finding (no duplicate), got %+v", sastRec.calls)
	}
	t.Logf("PASS: real model proposed a SAST hypothesis → runtime verifier confirmed → Kind=dast finding %q (%s, reachability=%s), no duplicate SAST",
		f.Title, f.Kind, f.Reachability)
}
