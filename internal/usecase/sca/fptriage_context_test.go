package sca

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type evidenceCapturingTriager struct {
	legacyCalls, contextCalls int
	evidence                  map[string][]ports.AITriageEvidenceToken
}

func (t *evidenceCapturingTriager) Triage(context.Context, []finding.Finding, string) []ports.AICritique {
	t.legacyCalls++
	return nil
}
func (t *evidenceCapturingTriager) TriageWithEvidence(_ context.Context, candidates []finding.Finding, _ string, evidence map[string][]ports.AITriageEvidenceToken) []ports.AICritique {
	t.contextCalls++
	t.evidence = evidence
	out := make([]ports.AICritique, 0, len(candidates))
	for _, f := range candidates {
		out = append(out, ports.AICritique{DedupKey: f.DedupKey})
	}
	return out
}

type forgedEvidenceTriager struct{}

func (forgedEvidenceTriager) Triage(context.Context, []finding.Finding, string) []ports.AICritique {
	return nil
}
func (forgedEvidenceTriager) TriageWithEvidence(_ context.Context, candidates []finding.Finding, _ string, _ map[string][]ports.AITriageEvidenceToken) []ports.AICritique {
	out := make([]ports.AICritique, 0, len(candidates))
	for _, f := range candidates {
		out = append(out, ports.AICritique{
			DedupKey: f.DedupKey, Verdict: "refuted", Driver: "input_sanitized", Confidence: 95,
			SuspectedFP: true, Verified: true, PromptVersion: "fp-triage-v3",
			ProposerModel: "model-a", ProposerProvider: "openai-compatible", ProposerModelFamily: "model-a",
			VerifierModel: "model-b", VerifierProvider: "openai-compatible", VerifierModelFamily: "model-b",
			IndependencePolicy: ports.AIIndependenceModelFamily,
			VerifierVerdict:    "refuted", VerifierDriver: "input_sanitized", VerifierConfidence: 94,
			ContextEvidence: []ports.AITriageEvidenceToken{
				{ID: "ev:finding_identity", Kind: ports.AITriageEvidenceKindFindingIdentity, Value: finding.Identity(f)},
				{ID: "ev:sanitizer", Kind: ports.AITriageEvidenceKindSanitizer, Value: "sanitized: fabricated by alternate port"},
			},
			EvidenceTokens: []string{"ev:sanitizer"}, VerifierEvidenceTokens: []string{"ev:sanitizer"},
		})
	}
	return out
}

func TestAITriageEvidenceUsesDeterministicSASTProof(t *testing.T) {
	raw := ports.SASTRawFinding{File: "app.go", Line: 12, RuleID: "weak", CWE: "CWE-327", Source: "HTTP query parameter", SourceEvidence: "line 4: query cue", Sink: "crypto sink", SinkEvidence: "line 12: crypto sink", DataFlow: "source -> sink", DataFlowEvidence: "interprocedural: q reaches wrapper; path=q<-source@4 -> wrapper@12", DataFlowConfidence: "interprocedural", Route: "GET /v1/x", EntryPoint: "GET /v1/x", RouteMiddleware: "line 2: authenticated middleware cue", AuthScope: "authenticated", CounterEvidence: "validator absent", ValidationMethod: "static-code-understanding", ValidationDisposition: "reportable-static-candidate"}
	f := finding.Finding{ID: "f1", DedupKey: sastFindingDedupKey(raw), Kind: finding.KindSAST, CWE: raw.CWE, RuleKey: raw.RuleID, Scope: sbom.ScopeProduction, SourceLocation: &finding.SourceLocation{File: raw.File, StartLine: raw.Line, EndLine: raw.Line}}
	ctx := aiTriageEvidenceForCandidates([]finding.Finding{f}, []ports.SASTRawFinding{raw})[f.DedupKey]
	have := map[string]string{}
	for _, token := range ctx {
		have[token.ID] = token.Value
	}
	for _, id := range []string{"ev:source", "ev:sink", "ev:data_flow_evidence", "ev:call_graph", "ev:taint_path", "ev:framework_route", "ev:framework_middleware", "ev:source_location"} {
		if have[id] == "" {
			t.Fatalf("missing %s in %+v", id, ctx)
		}
	}
}

func TestAITriageEvidenceSurfacesSanitizerProof(t *testing.T) {
	raw := ports.SASTRawFinding{File: "app.go", Line: 7, RuleID: "x", CWE: "CWE-327", DataFlowEvidence: "sanitized: value validated at line 5", DataFlowConfidence: "sanitized"}
	f := finding.Finding{ID: "f", DedupKey: sastFindingDedupKey(raw), Kind: finding.KindSAST, CWE: raw.CWE, RuleKey: raw.RuleID}
	tokens := aiTriageEvidenceForCandidates([]finding.Finding{f}, []ports.SASTRawFinding{raw})[f.DedupKey]
	found := false
	for _, token := range tokens {
		if token.ID == "ev:sanitizer" && token.Kind == ports.AITriageEvidenceKindSanitizer {
			found = true
		}
	}
	if !found {
		t.Fatalf("sanitizer token missing: %+v", tokens)
	}
}

func TestRunFPTriageUsesEvidenceAwareBoundary(t *testing.T) {
	triager := &evidenceCapturingTriager{}
	raw := ports.SASTRawFinding{File: "a.go", Line: 3, RuleID: "weak", CWE: "CWE-327", Source: "literal", SourceEvidence: "line-local literal"}
	f := finding.Finding{ID: "f", DedupKey: sastFindingDedupKey(raw), Kind: finding.KindSAST, CWE: raw.CWE, RuleKey: raw.RuleID, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium}
	result := &ScanResult{Findings: []finding.Finding{f}}
	svc := &Service{fpTriager: triager, fpTriageMode: aiTriageModeShadow, fpTriageMaxFindings: 10}
	svc.runFPTriage(context.Background(), result, "", nil, []ports.SASTRawFinding{raw})
	if triager.contextCalls != 1 || triager.legacyCalls != 0 || len(triager.evidence[f.DedupKey]) == 0 {
		t.Fatalf("boundary context=%d legacy=%d evidence=%v", triager.contextCalls, triager.legacyCalls, triager.evidence)
	}
}

func TestRunFPTriageRejectsSelfAttestedAlternatePortEvidence(t *testing.T) {
	raw := ports.SASTRawFinding{File: "a.go", Line: 3, RuleID: "weak", CWE: "CWE-327", Source: "HTTP input"}
	f := finding.Finding{ID: "f", DedupKey: sastFindingDedupKey(raw), Kind: finding.KindSAST, CWE: raw.CWE, RuleKey: raw.RuleID, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium}
	result := &ScanResult{Findings: []finding.Finding{f}}
	svc := &Service{fpTriager: forgedEvidenceTriager{}, fpTriageMode: aiTriageModeEnforce, fpTriageMaxFindings: 10, fpTriageIndependence: ports.AIIndependenceModelFamily}
	svc.runFPTriage(context.Background(), result, "", nil, []ports.SASTRawFinding{raw})
	if len(result.AITriage) != 1 {
		t.Fatalf("critique count=%d", len(result.AITriage))
	}
	got := result.AITriage[0]
	if got.GateExempt || !got.ReviewRequired || got.PolicyReason != aiPolicyDeterministicEvidenceRequired {
		t.Fatalf("self-attested evidence gained authority at service boundary: %+v", got)
	}
}

func TestEvidenceMetadataCannotBypassHumanReviewFloors(t *testing.T) {
	f := finding.Finding{ID: "f", DedupKey: "k", Kind: finding.KindSAST, CWE: "CWE-327", Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityHigh}
	result := &ScanResult{Findings: []finding.Finding{f}, AITriage: []ports.AICritique{{DedupKey: "k", Verdict: "refuted", Confidence: 99, SuspectedFP: true, Verified: true, VerifierVerdict: "refuted", VerifierConfidence: 99, ProposerProvider: "openai-compatible", VerifierProvider: "other", ProposerModel: "a", VerifierModel: "b", ProposerModelFamily: "a", VerifierModelFamily: "b", IndependencePolicy: ports.AIIndependenceModelFamily, ContextEvidence: []ports.AITriageEvidenceToken{{ID: "ev:cwe", Kind: ports.AITriageEvidenceKindCWE, Value: "CWE-327"}}, EvidenceTokens: []string{"ev:cwe"}}}}
	applyAIGatePolicyWithIndependence(result, true, aiTriageModeEnforce, ports.AIIndependenceModelFamily)
	if result.AITriage[0].GateExempt || !result.AITriage[0].ReviewRequired || result.AITriage[0].PolicyReason != aiPolicySeverityFloor {
		t.Fatalf("evidence metadata weakened floor: %+v", result.AITriage[0])
	}
}

func TestDeterministicAnalysisPrecedesAITriageInSourcePipeline(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "service.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runPipeline"} {
		var fn *ast.FuncDecl
		for _, decl := range file.Decls {
			if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == name {
				fn = f
				break
			}
		}
		if fn == nil {
			t.Fatalf("%s missing", name)
		}
		triagePos, taintPos, reachPos := token.NoPos, token.NoPos, token.NoPos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "runFPTriage" {
				triagePos = call.Pos()
			}
			if base, ok := sel.X.(*ast.SelectorExpr); ok {
				if ident, ok := base.X.(*ast.Ident); ok && ident.Name == "s" && base.Sel.Name == "taint" && sel.Sel.Name == "Scan" {
					taintPos = call.Pos()
				}
				if ident, ok := base.X.(*ast.Ident); ok && ident.Name == "s" && base.Sel.Name == "reachability" && sel.Sel.Name == "Record" {
					reachPos = call.Pos()
				}
			}
			return true
		})
		if triagePos == token.NoPos || taintPos == token.NoPos || reachPos == token.NoPos || !(reachPos < triagePos && taintPos < triagePos) {
			t.Fatalf("%s ordering reach=%v taint=%v triage=%v", name, reachPos, taintPos, triagePos)
		}
	}
}

func TestEvidenceValuesAreBoundedSingleLine(t *testing.T) {
	v := cleanAITriageEvidenceValue(strings.Repeat("x\n", 600))
	if strings.Contains(v, "\n") || len([]rune(v)) > ports.MaxAITriageEvidenceValueRunes {
		t.Fatalf("unsafe evidence value len=%d", len([]rune(v)))
	}
}
