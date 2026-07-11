package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	drecon "github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --- fakes ---

type fakeFindings struct{ items []finding.Finding }

func (f *fakeFindings) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return f.items, nil
}

type fakeEvidence struct{ items []evidence.Evidence }

func (f *fakeEvidence) ListByEngagement(context.Context, shared.ID) ([]evidence.Evidence, error) {
	return f.items, nil
}

type auditRec struct {
	Actor, Action, Target string
}

type fakeAudit struct{ recs []auditRec }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.recs = append(a.recs, auditRec{Actor: e.Actor, Action: e.Action, Target: e.Target})
	return nil
}

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type seqIDs struct{ n int }

func (g *seqIDs) NewID() shared.ID { g.n++; return shared.ID("id-" + strconv.Itoa(g.n)) }

// fakeRecon implements ports.ReconTool with configurable identity/accepts/capability so a
// test can model subfinder (passive) or naabu (capability-sensitive) without a real binary.
type fakeRecon struct {
	name, action string
	capSensitive bool
	accepts      map[engagement.TargetKind]bool
	args         []string // flags before the appended target value
}

func (f fakeRecon) Name() string                          { return f.name }
func (f fakeRecon) Binary() string                        { return f.name }
func (f fakeRecon) Action() string                        { return f.action }
func (f fakeRecon) CapabilitySensitive() bool             { return f.capSensitive }
func (f fakeRecon) Accepts(k engagement.TargetKind) bool  { return f.accepts[k] }
func (f fakeRecon) Parse([]byte) ([]drecon.Result, error) { return nil, nil }
func (f fakeRecon) BuildArgs(t engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: f.name, Args: append(append([]string{}, f.args...), t.Value)}, nil
}

func subfinder() fakeRecon {
	return fakeRecon{name: "subfinder", action: "recon.subfinder", capSensitive: false,
		accepts: map[engagement.TargetKind]bool{engagement.TargetDomain: true}, args: []string{"-silent", "-json", "-d"}}
}

func naabu() fakeRecon {
	return fakeRecon{name: "naabu", action: "recon.naabu", capSensitive: true,
		accepts: map[engagement.TargetKind]bool{engagement.TargetDomain: true, engagement.TargetIP: true}, args: []string{"-silent", "-host"}}
}

func newCatalog(t *testing.T, finds []finding.Finding, evs []evidence.Evidence, tools ...ports.ReconTool) (*Catalog, *fakeAudit) {
	t.Helper()
	audit := &fakeAudit{}
	c, err := New(&fakeFindings{finds}, &fakeEvidence{evs}, tools, audit, fakeClock{time.Unix(1_000_000, 0).UTC()}, &seqIDs{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, audit
}

func session() agent.Session {
	return agent.Session{ID: "s1", EngagementID: "eng-1", InitiatedBy: "alice"}
}

// TestToolsExposesOnlyAllowedTools is the anti-self-escalation guard: the advertised
// tool set is EXACTLY the read + propose-only allowlist, and contains NO tool that mutates
// scope, the authorization window, RoE, live-recon, credentials, or the approval mode.
func TestToolsExposesOnlyAllowedTools(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	got := map[string]bool{}
	for _, ts := range c.Tools() {
		got[ts.Name] = true
		if len(ts.Parameters) == 0 || !json.Valid(ts.Parameters) {
			t.Errorf("tool %q has invalid JSON-schema parameters", ts.Name)
		}
	}
	allowed := []string{ToolListFindings, ToolGetFindingDetail, ToolListSASTValidation, ToolPlanRuntimeVerification, ToolListEvidence, ToolVerifyCustody, ToolListReconTools, ToolStartRecon, ToolEvidenceSufficiency}
	if len(got) != len(allowed) {
		t.Fatalf("advertised %d tools, want exactly %d: %v", len(got), len(allowed), got)
	}
	for _, name := range allowed {
		if !got[name] {
			t.Errorf("missing expected tool %q", name)
		}
	}
	// Defense in depth: explicitly assert the forbidden self-escalation tools are absent.
	for _, banned := range []string{
		"set_scope", "update_scope", "add_target", "set_authorization_window", "set_window",
		"set_roe", "enable_live_recon", "disable_live_recon", "put_credential", "set_credential",
		"set_approval_mode", "approve", "run_recon", "execute", "exec_tool", "list_engagements", "get_scope",
	} {
		if got[banned] {
			t.Errorf("forbidden self-escalation tool advertised: %q", banned)
		}
	}
}

func TestNewValidates(t *testing.T) {
	audit := &fakeAudit{}
	clk := fakeClock{}
	ids := &seqIDs{}
	if _, err := New(nil, &fakeEvidence{}, nil, audit, clk, ids); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil findings must fail validation")
	}
	if _, err := New(&fakeFindings{}, &fakeEvidence{}, []ports.ReconTool{subfinder(), subfinder()}, audit, clk, ids); !errors.Is(err, shared.ErrValidation) {
		t.Error("duplicate recon tool must fail validation")
	}
}

func TestListFindingsScopedAndAudited(t *testing.T) {
	finds := []finding.Finding{
		{ID: "f1", Title: "SQLi", Severity: shared.SeverityHigh, Kind: finding.Kind("sca"), Status: finding.Status("open"), Priority: 2, KEV: true, RiskScore: 8.1},
		{ID: "f2", Title: "XSS", Severity: shared.SeverityMedium},
	}
	c, audit := newCatalog(t, finds, nil, subfinder())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolListFindings})
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal != nil {
		t.Fatal("read tool must not produce a proposal")
	}
	var out struct {
		Findings  []findingView `json:"findings"`
		Total     int           `json:"total"`
		Truncated bool          `json:"truncated"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if out.Total != 2 || len(out.Findings) != 2 || out.Findings[0].ID != "f1" || !out.Findings[0].KEV {
		t.Fatalf("unexpected findings payload: %+v", out)
	}
	if len(audit.recs) != 1 || audit.recs[0].Actor != "agent:s1" || audit.recs[0].Action != "agent.read.findings" {
		t.Fatalf("read must be audited as the agent, got %+v", audit.recs)
	}
}

func TestGetFindingDetailScopedRedactedAndAudited(t *testing.T) {
	finds := []finding.Finding{{
		ID: "f1", Title: "SQLi", Description: "AppSec validation envelope:\n- OWASP/CWE mapping: A05:2025 Injection / CWE-89\n- Source: HTTP query parameter\n- Source evidence: line 3: HTTP query parameter cue\n- Sink/control: SQL execution sink\n- Control evidence: line 1: route GET /search\n- Auth evidence: no auth middleware cue found in bounded route context\n- Exposure: public-or-unauthenticated application route\n- Dataflow evidence: context-only: source and sink are both present in bounded local context\n- Dataflow confidence: context-only\n- Validation receipt: static-code-understanding / deferred-proof-gap\n- Preconditions/proof gaps: prove attacker-controlled input reaches this code\n- Counterevidence: none observed in bounded local context\n- Callback https://user:pass@example.test/hook",
		Severity: shared.SeverityHigh, CWE: "CWE-89", Kind: finding.KindSAST, Class: finding.ClassFirstParty,
		Status: finding.StatusOpen, Priority: 2, Sources: []string{"synapse-pattern-sast"}, Confidence: "high",
		DedupKey: "sast:r:a.go:1",
	}}
	evs := []evidence.Evidence{{ID: "e1", EngagementID: "eng-1", FindingID: "f1", Kind: "sast_validation", Content: []byte("raw evidence"), CreatedBy: "system"}}
	c, audit := newCatalog(t, finds, evs, subfinder())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolGetFindingDetail,
		Arguments: json.RawMessage(`{"finding_id":"f1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal != nil {
		t.Fatal("read detail tool must not produce a proposal")
	}
	var out findingDetailView
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if out.ID != "f1" || out.CWE != "CWE-89" || !out.HasSASTEnvelope || out.EvidenceCount != 1 {
		t.Fatalf("unexpected detail payload: %+v", out)
	}
	if out.SASTValidation == nil || out.SASTValidation.Source != "HTTP query parameter" ||
		out.SASTValidation.DataflowConfidence != "context-only" ||
		out.SASTValidation.Exposure != "public-or-unauthenticated application route" ||
		out.SASTValidation.ValidationDisposition != "deferred-proof-gap" ||
		out.SASTValidation.ClosureStatus != "deferred_until_proof_gap_closed" ||
		len(out.SASTValidation.PromotionBlockers) == 0 {
		t.Fatalf("structured SAST validation envelope missing: %+v", out.SASTValidation)
	}
	if strings.Contains(out.Description, "user:pass") {
		t.Fatalf("detail description was not redacted: %q", out.Description)
	}
	if len(audit.recs) != 1 || audit.recs[0].Actor != "agent:s1" || audit.recs[0].Action != "agent.read.finding_detail" {
		t.Fatalf("detail read must be audited as the agent, got %+v", audit.recs)
	}
}

func TestListSASTValidationClosureTable(t *testing.T) {
	finds := []finding.Finding{
		{
			ID: "sast-1", Title: "SQLi", Description: "AppSec validation envelope:\n- OWASP/CWE mapping: A05:2025 Injection / CWE-89\n- Source: HTTP query parameter\n- Sink/control: SQL execution sink\n- Control evidence: line 1: route GET /search\n- Route middleware: line 1: route-level authenticated middleware cue\n- Auth evidence: line 1: route-level authenticated middleware cue\n- Exposure: authenticated application route\n- Dataflow confidence: variable-derived\n- Validation receipt: static-code-understanding / reportable-static-candidate\n- Counterevidence: none observed in bounded local context\n- Validation rubric: source=present; control=present; sink=present; dataflow=variable-derived; counterevidence=none_observed",
			Severity: shared.SeverityHigh, CWE: "CWE-89", Kind: finding.KindSAST, Status: finding.StatusOpen, Priority: 2, Confidence: "high",
		},
		{
			ID: "sast-2", Title: "Sanitized SQLi", Description: "AppSec validation envelope:\n- OWASP/CWE mapping: A05:2025 Injection / CWE-89\n- Source: HTTP query parameter\n- Sink/control: SQL execution sink\n- Dataflow confidence: sanitized\n- Validation receipt: static-code-understanding / needs-review-counterevidence\n- Counterevidence: none observed in bounded local context",
			Severity: shared.SeverityHigh, CWE: "CWE-89", Kind: finding.KindSAST, Status: finding.StatusOpen, Priority: 2, Confidence: "medium",
		},
		{
			ID: "sast-3", Title: "Reflected XSS needs verifier", Description: "AppSec validation envelope:\n- OWASP/CWE mapping: A05:2025 Injection / CWE-79\n- Source: HTTP query parameter\n- Sink/control: HTML/template rendering sink\n- Dataflow confidence: propagated\n- Validation receipt: static-code-understanding / needs-runtime-proof\n- Counterevidence: none observed in bounded local context",
			Severity: shared.SeverityHigh, CWE: "CWE-79", Kind: finding.KindSAST, Status: finding.StatusOpen, Priority: 2, Confidence: "high",
		},
		{
			ID: "sast-4", Title: "JSON-LD false positive", Description: "AppSec validation envelope:\n- OWASP/CWE mapping: A05:2025 Injection / CWE-79\n- Source: stored or rendered user content\n- Sink/control: HTML/template rendering sink\n- Dataflow confidence: context-only\n- Validation receipt: static-code-understanding / false-positive-static\n- Counterevidence: JSON-LD structured data rendered through JSON.stringify",
			Severity: shared.SeverityHigh, CWE: "CWE-79", Kind: finding.KindSAST, Status: finding.StatusOpen, Priority: 3, Confidence: "low",
		},
		{ID: "sca-1", Title: "Dependency CVE", Kind: finding.KindSCA, Severity: shared.SeverityHigh},
	}
	c, audit := newCatalog(t, finds, nil, subfinder())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolListSASTValidation})
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal != nil {
		t.Fatal("SAST validation list must be read-only")
	}
	var out struct {
		Rows      []sastValidationRow `json:"sast_validation"`
		Total     int                 `json:"total"`
		Truncated bool                `json:"truncated"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if out.Total != 4 || len(out.Rows) != 4 || out.Rows[0].FindingID != "sast-1" {
		t.Fatalf("unexpected SAST validation rows: %+v", out)
	}
	row := out.Rows[0]
	if row.ValidationDisposition != "reportable-static-candidate" || row.ClosureStatus != "static_candidate_survives_code_understanding" || row.Source != "HTTP query parameter" || row.Sink != "SQL execution sink" || row.DataflowConfidence != "variable-derived" || row.Exposure != "authenticated application route" {
		t.Fatalf("closure row lost structured validation: %+v", row)
	}
	if len(row.PromotionBlockers) != 1 || !strings.Contains(row.PromotionBlockers[0], "runtime exploitability") {
		t.Fatalf("closure row must retain runtime-proof caveat: %+v", row.PromotionBlockers)
	}
	sanitized := out.Rows[1]
	if sanitized.DataflowConfidence != "sanitized" || !strings.Contains(strings.Join(sanitized.PromotionBlockers, " "), "sanitizer/validator") {
		t.Fatalf("sanitized SAST row should explain sanitizer review blocker: %+v", sanitized)
	}
	runtimeProof := out.Rows[2]
	if runtimeProof.ValidationDisposition != "needs-runtime-proof" ||
		runtimeProof.ClosureStatus != "deferred_until_runtime_verifier_evidence" ||
		!strings.Contains(strings.Join(runtimeProof.PromotionBlockers, " "), "safe runtime verifier") {
		t.Fatalf("runtime-proof SAST row should explain verifier blocker: %+v", runtimeProof)
	}
	falsePositive := out.Rows[3]
	if falsePositive.ValidationDisposition != "false-positive-static" ||
		falsePositive.ClosureStatus != "closed_false_positive_static" ||
		!strings.Contains(strings.Join(falsePositive.PromotionBlockers, " "), "false positive") ||
		strings.Contains(strings.Join(falsePositive.PromotionBlockers, " "), "runtime exploitability") {
		t.Fatalf("false-positive SAST row should close without runtime-proof caveat: %+v", falsePositive)
	}
	if len(audit.recs) != 1 || audit.recs[0].Actor != "agent:s1" || audit.recs[0].Action != "agent.read.sast_validation" {
		t.Fatalf("SAST validation read must be audited as the agent, got %+v", audit.recs)
	}
}

func TestPlanRuntimeVerificationIsReadOnlyAndScopeGated(t *testing.T) {
	finds := []finding.Finding{
		{
			ID: "sast-ssrf", Title: "SSRF", Description: "AppSec validation envelope:\n- OWASP/CWE mapping: A01:2025 Broken Access Control / CWE-918\n- Entrypoint/control: GET /proxy\n- Source: HTTP query parameter\n- Sink/control: server-side outbound request sink\n- Dataflow confidence: propagated\n- Validation receipt: static-code-understanding / needs-runtime-proof\n- Counterevidence: none observed in bounded local context",
			Severity: shared.SeverityHigh, CWE: "CWE-918", Kind: finding.KindSAST, Status: finding.StatusOpen, Priority: 1, Confidence: "high",
		},
	}
	c, audit := newCatalog(t, finds, nil, subfinder())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolPlanRuntimeVerification,
		Arguments: json.RawMessage(`{"finding_id":"sast-ssrf"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal != nil || res.Plan != nil {
		t.Fatalf("runtime verifier planning must be read-only, got proposal=%+v plan=%+v", res.Proposal, res.Plan)
	}
	var out struct {
		Found bool                    `json:"found"`
		Plan  runtimeVerificationPlan `json:"runtime_verification_plan"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !out.Found || out.Plan.FindingID != "sast-ssrf" || out.Plan.ExecutionAllowed {
		t.Fatalf("runtime verifier plan should be found but never executable: %+v", out)
	}
	joined := strings.Join(append(out.Plan.SafeProbeStrategy, out.Plan.StopConditions...), " ")
	if !strings.Contains(joined, "operator-controlled callback/canary") ||
		!strings.Contains(joined, "do not probe cloud metadata or private networks") ||
		!strings.Contains(out.Plan.PromotionGate, "sealed as evidence") ||
		!strings.Contains(out.Plan.ArchitectureGuard, "no network request") {
		t.Fatalf("SSRF verifier plan lost safety architecture: %+v", out.Plan)
	}
	if len(audit.recs) != 1 || audit.recs[0].Actor != "agent:s1" || audit.recs[0].Action != "agent.read.runtime_verification_plan" {
		t.Fatalf("runtime verifier plan read must be audited as the agent, got %+v", audit.recs)
	}
}

func TestPlanRuntimeVerificationClosesStaticFalsePositive(t *testing.T) {
	finds := []finding.Finding{
		{
			ID: "sast-fp", Title: "JSON-LD false positive", Description: "AppSec validation envelope:\n- OWASP/CWE mapping: A05:2025 Injection / CWE-79\n- Source: stored or rendered user content\n- Sink/control: HTML/template rendering sink\n- Dataflow confidence: context-only\n- Validation receipt: static-code-understanding / false-positive-static\n- Counterevidence: JSON-LD structured data rendered through JSON.stringify",
			Severity: shared.SeverityHigh, CWE: "CWE-79", Kind: finding.KindSAST, Status: finding.StatusOpen, Priority: 3, Confidence: "low",
		},
	}
	c, _ := newCatalog(t, finds, nil, subfinder())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolPlanRuntimeVerification,
		Arguments: json.RawMessage(`{"finding_id":"sast-fp"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Found bool                    `json:"found"`
		Plan  runtimeVerificationPlan `json:"runtime_verification_plan"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if out.Plan.RiskClass != "read-only-review" ||
		!strings.Contains(strings.Join(out.Plan.SafeProbeStrategy, " "), "do not run runtime verification") ||
		out.Plan.ExecutionAllowed {
		t.Fatalf("false-positive plan should not request runtime proof: %+v", out.Plan)
	}
}

func TestListEvidenceMetadataOnly(t *testing.T) {
	e1 := evidence.Evidence{ID: "e1", EngagementID: "eng-1", Kind: "scan", Content: []byte("SECRET-CONTENT"), CreatedBy: "agent:s1", CreatedAt: time.Unix(1_000_000, 0).UTC()}.Seal()
	c, _ := newCatalog(t, nil, []evidence.Evidence{e1}, subfinder())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolListEvidence})
	if err != nil {
		t.Fatal(err)
	}
	// The raw content must never appear in what the model sees.
	if got := string(res.Data); got == "" || containsSecret(got) {
		t.Fatalf("evidence content leaked to the model: %s", got)
	}
	var out struct {
		Evidence []evidenceView `json:"evidence"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Evidence) != 1 || out.Evidence[0].Hash != e1.Hash {
		t.Fatalf("expected metadata with hash, got %+v", out.Evidence)
	}
}

func containsSecret(s string) bool {
	for i := 0; i+14 <= len(s); i++ {
		if s[i:i+14] == "SECRET-CONTENT" {
			return true
		}
	}
	return false
}

func TestVerifyCustodyOKAndTampered(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	e1 := evidence.Evidence{ID: "e1", EngagementID: "eng-1", Kind: "scan", Content: []byte("a"), CreatedBy: "x", CreatedAt: now}.Seal()
	e2 := evidence.Evidence{ID: "e2", EngagementID: "eng-1", Kind: "finding", Content: []byte("b"), PreviousHash: e1.Hash, CreatedBy: "x", CreatedAt: now}.Seal()

	// Healthy chain.
	c, _ := newCatalog(t, nil, []evidence.Evidence{e1, e2}, subfinder())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolVerifyCustody})
	if err != nil {
		t.Fatal(err)
	}
	var ok struct {
		OK    bool   `json:"ok"`
		Count int    `json:"count"`
		Head  string `json:"head_hash"`
	}
	_ = json.Unmarshal(res.Data, &ok)
	if !ok.OK || ok.Count != 2 || ok.Head != e2.Hash {
		t.Fatalf("healthy custody check wrong: %s", res.Data)
	}

	// Tampered: mutate sealed content so its hash no longer matches.
	bad := e2
	bad.Content = []byte("TAMPERED")
	c2, _ := newCatalog(t, nil, []evidence.Evidence{e1, bad}, subfinder())
	res2, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolVerifyCustody})
	if err != nil {
		t.Fatal(err)
	}
	var notok struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(res2.Data, &notok)
	if notok.OK || notok.Error == "" {
		t.Fatalf("tampered custody must report ok=false with an error: %s", res2.Data)
	}
}

func TestStartReconProposesNeverExecutes(t *testing.T) {
	c, audit := newCatalog(t, nil, nil, subfinder(), naabu())
	args, _ := json.Marshal(startReconArgs{Tool: "subfinder", Target: "app.acme.io", Rationale: "enumerate subdomains"})
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolStartRecon, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.Data != nil || res.Proposal == nil {
		t.Fatalf("execute tool must return a proposal, not data: %+v", res)
	}
	p := res.Proposal
	wantArgv := []string{"subfinder", "-silent", "-json", "-d", "app.acme.io"}
	if len(p.Argv) != len(wantArgv) {
		t.Fatalf("argv preview wrong: %v", p.Argv)
	}
	for i := range wantArgv {
		if p.Argv[i] != wantArgv[i] {
			t.Fatalf("argv[%d]=%q want %q (full %v)", i, p.Argv[i], wantArgv[i], p.Argv)
		}
	}
	if p.Action != "recon.subfinder" || p.Risk != agent.RiskActive {
		t.Errorf("action/risk wrong: %s %s", p.Action, p.Risk)
	}
	if p.SessionID != "s1" || p.EngagementID != "eng-1" {
		t.Errorf("proposal must be session-locked: sid=%s eid=%s", p.SessionID, p.EngagementID)
	}
	if p.ID == "" || p.Target.Value != "app.acme.io" || p.Rationale != "enumerate subdomains" {
		t.Errorf("proposal fields wrong: %+v", p)
	}
	// The proposal must be audited as the agent, and NOTHING beyond the proposal recorded.
	if len(audit.recs) != 1 || audit.recs[0].Action != "agent.propose" || audit.recs[0].Actor != "agent:s1" {
		t.Fatalf("proposal audit wrong: %+v", audit.recs)
	}
}

func TestStartReconCapabilitySensitiveIsIntrusive(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, naabu())
	args, _ := json.Marshal(startReconArgs{Tool: "naabu", Target: "10.0.0.5"})
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolStartRecon, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposal.Risk != agent.RiskIntrusive {
		t.Fatalf("capability-sensitive recon must be intrusive, got %s", res.Proposal.Risk)
	}
}

func TestStartReconRejectsBadInput(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	cases := []struct {
		name string
		args startReconArgs
	}{
		{"unknown tool", startReconArgs{Tool: "nuclei", Target: "app.acme.io"}},
		{"wrong kind", startReconArgs{Tool: "subfinder", Target: "10.0.0.5"}}, // subfinder accepts only domains
		{"empty target", startReconArgs{Tool: "subfinder", Target: ""}},
		{"flag injection", startReconArgs{Tool: "subfinder", Target: "-rf"}},                        // leading '-' rejected
		{"whitespace target", startReconArgs{Tool: "subfinder", Target: "a b"}},                     // whitespace rejected
		{"credential placeholder", startReconArgs{Tool: "subfinder", Target: "app{{secret:x}}.io"}}, // argv guard
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(tc.args)
			if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolStartRecon, Arguments: args}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestDispatchUnknownTool(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: "rm_rf"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown tool must be ErrValidation, got %v", err)
	}
}

type fakeScanResults struct {
	blob []byte
	err  error
}

func (f *fakeScanResults) LatestResult(context.Context, shared.ID) ([]byte, error) {
	return f.blob, f.err
}

func TestReachabilityContext(t *testing.T) {
	c, audit := newCatalog(t, nil, nil, subfinder())
	doc := &sbom.SBOM{
		Components: []sbom.Component{
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Scope: sbom.ScopeProduction, Location: "package.json"},
			{Name: "deep", Version: "1.0.0", PURL: "pkg:npm/deep@1.0.0", Scope: sbom.ScopeTest, Location: "test/package.json"},
		},
		Dependencies: []sbom.Dependency{
			{Ref: "root", DependsOn: []string{"pkg:npm/lodash@4.17.21"}},
			{Ref: "pkg:npm/lodash@4.17.21", DependsOn: []string{"pkg:npm/deep@1.0.0"}},
		},
	}
	blob, _ := json.Marshal(map[string]any{
		"sbom": doc,
		"vulnerabilities": []vulnerability.Vulnerability{
			{Component: "lodash", Version: "4.17.21", AffectedSymbols: []string{"lodash.template"}},
		},
	})
	c.EnableReachability(&fakeScanResults{blob: blob})

	get := func(args string) reachabilityView {
		t.Helper()
		res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolReachabilityContext, Arguments: json.RawMessage(args)})
		if err != nil {
			t.Fatalf("dispatch %s: %v", args, err)
		}
		var v reachabilityView
		if err := json.Unmarshal(res.Data, &v); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return v
	}

	// direct production dependency → present, direct, depth 2, tier-1, not background
	if d := get(`{"component":"lodash","version":"4.17.21"}`); !d.PresentInSBOM || !d.InDependencyGraph || !d.Direct ||
		d.Depth != 2 || d.SuggestedTier != string(judgment.Tier1) || d.Scope != sbom.ScopeProduction || d.BackgroundScope ||
		len(d.AffectedSymbols) != 1 || d.AffectedSymbols[0] != "lodash.template" {
		t.Fatalf("direct prod dep facts wrong: %+v", d)
	}
	// transitive test-only dependency → present, NOT direct, depth 3, tier-0, background scope,
	// and the manifest location is basenamed ("test/package.json" → "package.json", data-minimization)
	if tr := get(`{"component":"deep","version":"1.0.0"}`); !tr.PresentInSBOM || tr.Direct ||
		tr.Depth != 3 || tr.SuggestedTier != string(judgment.Tier0) || !tr.BackgroundScope || tr.Location != "package.json" {
		t.Fatalf("transitive test dep facts wrong: %+v", tr)
	}
	// not in the SBOM → absent (a strong not-reachable signal)
	if g := get(`{"component":"ghost"}`); g.PresentInSBOM || g.InDependencyGraph {
		t.Fatalf("absent package must report present_in_sbom=false: %+v", g)
	}
	// the read is audited as the agent
	if len(audit.recs) == 0 || audit.recs[len(audit.recs)-1].Action != "agent.read.reachability" || audit.recs[len(audit.recs)-1].Actor != "agent:s1" {
		t.Fatalf("reachability read must be audited as the agent: %+v", audit.recs)
	}
	// component is required
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolReachabilityContext, Arguments: json.RawMessage(`{}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty component: want ErrValidation, got %v", err)
	}
	// tool absent until enabled
	c2, _ := newCatalog(t, nil, nil, subfinder())
	if _, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolReachabilityContext, Arguments: json.RawMessage(`{"component":"x"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("reachability disabled: want ErrValidation, got %v", err)
	}
}

// TestReachabilityClampsHostileStrings: a hostile/oversized SBOM string (component is
// attacker-influenceable) must be bounded + basenamed before it is reflected into the LLM transcript.
func TestReachabilityClampsHostileStrings(t *testing.T) {
	long := strings.Repeat("A", 500)
	c, _ := newCatalog(t, nil, nil, subfinder())
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "x", Version: long, PURL: "pkg:npm/x@" + long, Location: "deep/dir/" + long + "/package.json"},
	}}
	blob, _ := json.Marshal(map[string]any{"sbom": doc})
	c.EnableReachability(&fakeScanResults{blob: blob})

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolReachabilityContext, Arguments: json.RawMessage(`{"component":"x"}`)})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var v reachabilityView
	if err := json.Unmarshal(res.Data, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(v.Version) > maxReachStr+4 { // clamped (+"…" is 3 bytes)
		t.Errorf("version not clamped: %d bytes", len(v.Version))
	}
	if v.Location != "package.json" { // basename strips the long hostile dir
		t.Errorf("location not basenamed/clamped: %q", v.Location)
	}
}

type fakeJudgmentProposer struct {
	got judgment.Judgment
	err error
}

func (f *fakeJudgmentProposer) Propose(_ context.Context, proposer string, eng shared.ID, capb judgment.Capability, sk judgment.SubjectKind, sid shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	if f.err != nil {
		return judgment.Judgment{}, f.err
	}
	// echo a PROPOSED judgment at score 0, mirroring analysis.Propose (which validates + seals + audits)
	f.got = judgment.Judgment{
		ID: "j-1", EngagementID: eng, Capability: capb, SubjectKind: sk, SubjectID: sid,
		State: judgment.StateProposed, EvidenceScore: 0, ProposedBy: proposer, Claim: claim,
	}
	return f.got, nil
}

func TestProposeThreat(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeThreat {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_threat has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_threat must be advertised after EnableJudgments")
	}

	// a STRIDE info-disclosure threat on a boundary-crossing data flow, exposing the pii asset
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeThreat,
		Arguments: json.RawMessage(`{"element_kind":"data_flow","element_id":"f1","category":"info_disclosure","asset":"pii"}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// recorded as PROPOSED, score 0, attributed to the AGENT, gated CapThreat about the data flow
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapThreat || fp.got.SubjectKind != judgment.SubjectDataFlow || fp.got.SubjectID != "f1" {
		t.Fatalf("subject wiring wrong: %+v", fp.got)
	}
	tc, ok := fp.got.Claim.(judgment.ThreatClaim)
	if !ok || tc.Category != judgment.InfoDisclosure || tc.Asset != "pii" {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out["evidence_score"].(float64) != 0 || out["publishable"].(bool) {
		t.Fatalf("response must be score 0 + not publishable (a human ratifies): %v", out)
	}

	// a component-targeted threat wires through SubjectComponent
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeThreat, Arguments: json.RawMessage(`{"element_kind":"component","element_id":"api","category":"spoofing"}`)}); err != nil {
		t.Fatalf("component threat: %v", err)
	}
	if fp.got.SubjectKind != judgment.SubjectComponent || fp.got.SubjectID != "api" {
		t.Fatalf("component subject wiring wrong: %+v", fp.got)
	}

	// element_id required; element_kind must be component|data_flow (tool-level guards)
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeThreat, Arguments: json.RawMessage(`{"element_kind":"data_flow","category":"spoofing"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing element_id: want ErrValidation, got %v", err)
	}
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeThreat, Arguments: json.RawMessage(`{"element_kind":"datastore","element_id":"x","category":"spoofing"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad element_kind: want ErrValidation, got %v", err)
	}

	// disabled by default (no EnableJudgments) – not advertised, dispatch refused
	c2, _ := newCatalog(t, nil, nil, subfinder())
	for _, ts := range c2.Tools() {
		if ts.Name == ToolProposeThreat {
			t.Fatal("propose_threat must NOT be advertised without EnableJudgments")
		}
	}
	if _, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeThreat, Arguments: json.RawMessage(`{"element_kind":"component","element_id":"api","category":"spoofing"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("disabled propose_threat: want ErrValidation, got %v", err)
	}
}

func TestProposeReachability(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)

	// advertised after enable, with valid JSON-schema parameters
	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeReachability {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_reachability has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_reachability must be advertised after EnableJudgments")
	}

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeReachability,
		Arguments: json.RawMessage(`{"subject_id":"f1","reachable":"not_reachable","tier":"tier-1","path":["root","lodash"],"confidence":80}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// recorded as PROPOSED, score 0, attributed to the AGENT (not a human), about the finding
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapReachability || fp.got.SubjectKind != judgment.SubjectFinding || fp.got.SubjectID != "f1" {
		t.Fatalf("subject wiring wrong: %+v", fp.got)
	}
	rc, ok := fp.got.Claim.(judgment.ReachabilityClaim)
	if !ok || rc.Reachable != judgment.NotReachable || rc.Tier != judgment.Tier1 || rc.Confidence != 80 {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
	// the response echoes score 0 + NOT publishable (a human must verify)
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out["evidence_score"].(float64) != 0 || out["publishable"].(bool) {
		t.Fatalf("response must be score 0 + not publishable: %v", out)
	}

	// subject_id required
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeReachability, Arguments: json.RawMessage(`{"reachable":"unknown","tier":"tier-0"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing subject_id: want ErrValidation, got %v", err)
	}
	// disabled by default (no EnableJudgments)
	c2, _ := newCatalog(t, nil, nil, subfinder())
	if _, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeReachability, Arguments: json.RawMessage(`{"subject_id":"f1","reachable":"unknown","tier":"tier-0"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("propose_reachability disabled: want ErrValidation, got %v", err)
	}
}

func TestProposeSASTValidation(t *testing.T) {
	finds := []finding.Finding{{
		ID: "sast-1", Title: "SQLi", Kind: finding.KindSAST, CWE: "CWE-89", Status: finding.StatusOpen,
		Description: "AppSec validation envelope:\n- Validation receipt: static-code-understanding / needs-runtime-proof",
	}}
	c, _ := newCatalog(t, finds, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeSASTValidation {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_sast_validation has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_sast_validation must be advertised after EnableJudgments")
	}

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeSASTValidation,
		Arguments: json.RawMessage(`{"finding_id":"sast-1","cwe":"CWE-89","location":"finding:sast-1","rule":"runtime-verification-needed"}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Proposal != nil || res.Plan != nil {
		t.Fatalf("SAST validation proposal must record a judgment, not execute a tool: proposal=%+v plan=%+v", res.Proposal, res.Plan)
	}
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapSAST || fp.got.SubjectKind != judgment.SubjectFinding || fp.got.SubjectID != "sast-1" {
		t.Fatalf("subject wiring wrong: %+v", fp.got)
	}
	sc, ok := fp.got.Claim.(judgment.SASTClaim)
	if !ok || sc.CWE != "CWE-89" || sc.Location != "finding:sast-1" || sc.Rule != "runtime-verification-needed" {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out["evidence_score"].(float64) != 0 || out["publishable"].(bool) {
		t.Fatalf("response must be score 0 + not publishable: %v", out)
	}

	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeSASTValidation,
		Arguments: json.RawMessage(`{"finding_id":"missing","cwe":"CWE-89","location":"finding:missing","rule":"runtime-verification-needed"}`),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing SAST finding must fail closed, got %v", err)
	}
	c2, _ := newCatalog(t, finds, nil, subfinder())
	if _, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeSASTValidation, Arguments: json.RawMessage(`{"finding_id":"sast-1","cwe":"CWE-89","location":"finding:sast-1","rule":"runtime-verification-needed"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("disabled propose_sast_validation: want ErrValidation, got %v", err)
	}
}

func TestProposeCritique(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeCritique {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_critique has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_critique must be advertised after EnableJudgments")
	}

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeCritique,
		Arguments: json.RawMessage(`{"subject_id":"f1","verdict":"refuted","driver":"not_reachable","confidence":80}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapCritique || fp.got.SubjectKind != judgment.SubjectFinding || fp.got.SubjectID != "f1" {
		t.Fatalf("subject wiring wrong: %+v", fp.got)
	}
	cc, ok := fp.got.Claim.(judgment.CritiqueClaim)
	if !ok || cc.Verdict != judgment.CritiqueRefuted || cc.Driver != "not_reachable" || cc.Confidence != 80 {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out["evidence_score"].(float64) != 0 || out["publishable"].(bool) {
		t.Fatalf("response must be score 0 + not publishable: %v", out)
	}
	// subject_id required
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeCritique, Arguments: json.RawMessage(`{"verdict":"sound","driver":"x"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing subject_id: want ErrValidation, got %v", err)
	}
	// disabled by default
	c2, _ := newCatalog(t, nil, nil, subfinder())
	if _, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeCritique, Arguments: json.RawMessage(`{"subject_id":"f1","verdict":"sound","driver":"x"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("propose_critique disabled: want ErrValidation, got %v", err)
	}
}

func TestProposeRiskNarrative(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeRiskNarrative {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_risk_narrative has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_risk_narrative must be advertised after EnableJudgments")
	}

	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeRiskNarrative,
		Arguments: json.RawMessage(`{"subject_id":"f1","drivers":["kev","cvss>=9"],"priority":1}`),
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// ungated descriptive judgment, recorded at score 0, attributed to the agent
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapRiskNarrative || fp.got.SubjectKind != judgment.SubjectFinding || fp.got.SubjectID != "f1" {
		t.Fatalf("subject wiring wrong: %+v", fp.got)
	}
	rn, ok := fp.got.Claim.(judgment.RiskNarrativeClaim)
	if !ok || len(rn.Drivers) != 2 || rn.Drivers[0] != "kev" || rn.Priority != 1 {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
	// subject_id required + disabled by default
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeRiskNarrative, Arguments: json.RawMessage(`{"drivers":["kev"],"priority":1}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing subject_id: want ErrValidation, got %v", err)
	}
	c2, _ := newCatalog(t, nil, nil, subfinder())
	if _, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeRiskNarrative, Arguments: json.RawMessage(`{"subject_id":"f1","drivers":["kev"],"priority":1}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("propose_risk_narrative disabled: want ErrValidation, got %v", err)
	}
}

func TestEvidenceSufficiency(t *testing.T) {
	finds := []finding.Finding{
		{ID: "exp1", EngagementID: "eng-1", Kind: finding.KindExploitation, EvidenceScore: 0}, // gated, below bar
		{ID: "sca1", EngagementID: "eng-1", Kind: finding.KindSCA},                            // ungated
	}
	evs := []evidence.Evidence{{FindingID: "exp1"}, {FindingID: "exp1"}}
	c, audit := newCatalog(t, finds, evs, subfinder())

	get := func(fid string) sufficiencyView {
		t.Helper()
		res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolEvidenceSufficiency, Arguments: json.RawMessage(`{"finding_id":"` + fid + `"}`)})
		if err != nil {
			t.Fatalf("dispatch %s: %v", fid, err)
		}
		var v sufficiencyView
		if err := json.Unmarshal(res.Data, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// gated exploitation @ score 0 with 2 evidence items → needs a distinct verifier verdict, gap 75
	if v := get("exp1"); !v.Found || !v.Gated || v.Publishable || v.Bar != 75 || v.Gap != 75 || v.EvidenceCount != 2 ||
		v.Advice != "needs_distinct_verifier_verdict_at_or_above_bar" {
		t.Fatalf("exp1 sufficiency wrong: %+v", v)
	}
	// ungated SCA → already publishable, no verifier verdict needed
	if v := get("sca1"); !v.Found || v.Gated || !v.Publishable || v.Advice != "ungated_already_publishable" {
		t.Fatalf("sca1 sufficiency wrong: %+v", v)
	}
	// unknown id → found=false (advisory, not an error)
	if v := get("ghost"); v.Found || v.Advice != "finding_not_found" {
		t.Fatalf("ghost should be not-found: %+v", v)
	}
	// audited as the agent
	if len(audit.recs) == 0 || audit.recs[len(audit.recs)-1].Action != "agent.read.sufficiency" || audit.recs[len(audit.recs)-1].Actor != "agent:s1" {
		t.Fatalf("sufficiency read must be audited as the agent: %+v", audit.recs)
	}
	// finding_id required
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolEvidenceSufficiency, Arguments: json.RawMessage(`{}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing finding_id: want ErrValidation, got %v", err)
	}
}

func TestListReconToolsReportsRiskAndKinds(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder(), naabu())
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolListReconTools})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Tools []reconToolView `json:"tools"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tools) != 2 || out.Tools[0].Name != "naabu" { // sorted
		t.Fatalf("expected sorted [naabu, subfinder], got %+v", out.Tools)
	}
	if out.Tools[0].Risk != string(agent.RiskIntrusive) || out.Tools[1].Risk != string(agent.RiskActive) {
		t.Errorf("risk classes wrong: %+v", out.Tools)
	}
}
