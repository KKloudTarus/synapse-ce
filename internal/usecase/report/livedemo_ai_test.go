package report

// Live-AI demonstration for #160: a REAL model (9router / OpenAI-compatible) produces the risk-narrative
// drivers + priority; those closed tokens pass the domain's closed-vocabulary gate; the report SERVICE
// projects an ACCEPTED judgment to plain tokens; and the REAL HTML + PDF renderers emit them — while the
// report path stays LLM-free (the model never touches the renderer; only typed tokens cross the boundary).
//
// Gated behind SYNAPSE_LIVE_AI=1 so the normal suite stays hermetic. Run:
//   SYNAPSE_LIVE_AI=1 SYNAPSE_LLM_BASE_URL=http://localhost:20128/v1 SYNAPSE_LLM_MODEL=cx/gpt-5.4 \
//     go test ./internal/usecase/report/ -run TestLiveAIRiskNarrativeToReport -v

import (
	"context"
	"encoding/json"
	htmlpkg "html"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/llm/openai"
	inforeport "github.com/KKloudTarus/synapse-ce/internal/infrastructure/report"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// extractJSONObject pulls the first balanced {...} out of a possibly-chatty completion (9router does not
// honor response_format, so the model may wrap JSON in prose or a code fence). Mirrors the tolerant parse
// used by the fptriage/llmverifier coordinators.
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

func TestLiveAIRiskNarrativeToReport(t *testing.T) {
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

	// A concrete, high-signal finding. The model must map these facts to CLOSED driver tokens (no prose).
	const sys = `You are a security triage assistant for a pentest platform. You explain WHY a finding's risk ` +
		`priority is what it is, using only structured driver tokens — never prose. A driver token is a ` +
		`lowercase identifier, optionally with a numeric comparison, matching this grammar: ` +
		`^[a-z][a-z0-9_]*((<=|>=|==|!=|<|>)[0-9]+(\.[0-9]+)?)?$ . ` +
		`Examples: kev, reachable, internet_facing, epss>0.9, cvss>=9. ` +
		`Reply with ONLY a JSON object: {"drivers":[...tokens...],"priority":<1..5>}. No commentary.`
	const usr = `Finding: CVE-2021-44228 (Log4Shell) in org.apache.logging.log4j:log4j-core 2.14.1. ` +
		`Facts: listed in the CISA KEV catalog; EPSS = 0.97; CVSS base = 10.0 (critical); the vulnerable ` +
		`JndiLookup path is reachable from an internet-facing HTTP request handler. ` +
		`Give the driver tokens and the 1..5 priority.`

	resp, err := llm.Chat(context.Background(), ports.ChatRequest{
		Model:       model,
		Temperature: 0,
		MaxTokens:   400,
		Messages: []agent.Message{
			{Role: agent.RoleSystem, Content: sys},
			{Role: agent.RoleUser, Content: usr},
		},
	})
	if err != nil {
		t.Fatalf("live chat: %v", err)
	}
	raw := extractJSONObject(resp.Content)
	t.Logf("model=%s\nraw content: %s\nextracted JSON: %s", model, resp.Content, raw)
	if raw == "" {
		t.Fatalf("model returned no JSON object: %q", resp.Content)
	}
	var out struct {
		Drivers  []string `json:"drivers"`
		Priority int      `json:"priority"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("parse model JSON %q: %v", raw, err)
	}
	// clamp priority into the domain's 1..5 range (defensive; the domain also rejects out-of-range).
	if out.Priority < 1 {
		out.Priority = 1
	}
	if out.Priority > 5 {
		out.Priority = 5
	}

	// The closed-vocabulary gate is the anti-hallucination boundary: real model tokens must pass it, or the
	// judgment is rejected before it can ever reach a deliverable. This asserts the model stayed in-grammar.
	claim := judgment.RiskNarrativeClaim{Drivers: out.Drivers, Priority: out.Priority}
	if verr := claim.Validate(); verr != nil {
		t.Fatalf("model produced out-of-vocabulary drivers %v (priority %d): %v", out.Drivers, out.Priority, verr)
	}
	t.Logf("AI-derived, gate-valid claim: drivers=%v priority=%d", out.Drivers, out.Priority)

	// Feed an ACCEPTED judgment built from the REAL model output through the REAL report service +
	// REAL renderers. The renderer only ever sees plain tokens; no model call happens in this path.
	accepted := judgment.Judgment{
		Capability: judgment.CapRiskNarrative, State: judgment.StateConfirmed,
		SubjectKind: judgment.SubjectFinding, SubjectID: "manual:1", Claim: claim,
	}
	corr := acceptedCorrelation("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		[]string{"osv", "grype"}, []string{"owned"})

	eng := &engagement.Engagement{Name: "log4shell-live", Client: "Acme"}
	svc := NewService(
		fakeEngRepo{eng: eng},
		fakeFindingRepo{list: sampleFindings()},
		fakeRetestRepo{},
		nil,
		inforeport.NewRenderer(), // real maroto PDF renderer
		fakeInsight{ins: ports.ReportInsight{HasScan: true, ScanTarget: "/srv/app", Actionable: 1}},
		fakeClock{},
		"v-live",
	)
	htmlR := inforeport.NewHTMLRenderer() // real HTML renderer
	svc.RegisterFormat(FormatHTML, htmlR)
	svc.SetJudgments(fakeJudgments{list: []judgment.Judgment{accepted, corr}})

	// HTML: assert the AI-derived tokens land in the deliverable text.
	htmlBytes, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML})
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	html := string(htmlBytes)
	for _, d := range out.Drivers {
		// html/template auto-escapes, so a token like "epss>0.97" appears as "epss&gt;0.97".
		if !strings.Contains(html, htmlpkg.EscapeString(d)) {
			t.Errorf("rendered HTML is missing AI driver token %q", d)
		}
	}
	if !strings.Contains(html, "AI risk rationale") {
		t.Error("rendered HTML is missing the AI risk-rationale line")
	}
	if !strings.Contains(html, "Cross-check") {
		t.Error("rendered HTML is missing the cross-check line")
	}

	// PDF: prove the same insight renders to a real PDF (maroto) without error (Generate → load →
	// projectAcceptedJudgments → maroto, which draws the "AI analysis (accepted)" token block).
	pdfBytes, _, err := svc.Generate(context.Background(), "", "e1")
	if err != nil {
		t.Fatalf("render pdf: %v", err)
	}
	if len(pdfBytes) < 500 || !strings.HasPrefix(string(pdfBytes), "%PDF") {
		t.Fatalf("pdf render looks wrong: %d bytes, prefix %q", len(pdfBytes), string(pdfBytes[:min(8, len(pdfBytes))]))
	}
	t.Logf("PASS: real model → gate-valid tokens → HTML (%d bytes) + PDF (%d bytes), LLM-free render path",
		len(html), len(pdfBytes))
}
