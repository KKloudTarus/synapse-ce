package fptriage

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type evidenceLLM struct {
	replies  map[string]string
	requests []ports.ChatRequest
}

func (l *evidenceLLM) Chat(_ context.Context, req ports.ChatRequest) (ports.ChatResponse, error) {
	l.requests = append(l.requests, req)
	if reply, ok := l.replies[req.Model]; ok {
		return ports.ChatResponse{Content: reply, FinishReason: "stop"}, nil
	}
	return ports.ChatResponse{Content: `{"verdict":"uncertain","driver":"insufficient_context","confidence":20,"evidence_tokens":["ev:cwe"]}`, FinishReason: "stop"}, nil
}

func evidenceCandidate() finding.Finding {
	return finding.Finding{ID: "finding-1", EngagementID: "eng-1", DedupKey: "sast:rule:a.go:10", Title: "candidate", Kind: finding.KindSAST, CWE: "CWE-327", RuleKey: "rule", SourceLocation: &finding.SourceLocation{File: "a.go", StartLine: 10, EndLine: 10}}
}
func evidenceContext() map[string][]ports.AITriageEvidenceToken {
	return map[string][]ports.AITriageEvidenceToken{"sast:rule:a.go:10": {
		{ID: "ev:cwe", Kind: ports.AITriageEvidenceKindCWE, Value: "CWE-327"},
		{ID: "ev:sanitizer", Kind: ports.AITriageEvidenceKindSanitizer, Value: "sanitized: validator cue before sink"},
	}}
}

func TestAssessWithEvidenceRetainsCheckableCitationsAndBlindVerifier(t *testing.T) {
	llm := &evidenceLLM{replies: map[string]string{
		"proposer": `{"verdict":"refuted","driver":"input_sanitized","confidence":92,"evidence_tokens":["ev:sanitizer"]}`,
		"verifier": `{"verdict":"refuted","driver":"input_sanitized","confidence":88,"evidence_tokens":["ev:sanitizer"]}`,
	}}
	coord := New(llm, "proposer").WithVerifier(llm, "verifier")
	got := coord.AssessWithEvidence(context.Background(), []finding.Finding{evidenceCandidate()}, nil, evidenceContext())[0]
	if got.Err != nil || !got.VerifiedConsensus(75) {
		t.Fatalf("evidence consensus = %+v", got)
	}
	if got.PromptVersion != evidencePromptVersion || len(got.ContextEvidence) != 2 || strings.Join(got.EvidenceTokens, ",") != "ev:sanitizer" || strings.Join(got.VerifierEvidenceTokens, ",") != "ev:sanitizer" {
		t.Fatalf("evidence receipt = %+v", got)
	}
	if len(llm.requests) != 2 {
		t.Fatalf("requests=%d", len(llm.requests))
	}
	for _, req := range llm.requests {
		joined := req.Messages[len(req.Messages)-1].Content
		if !strings.Contains(joined, `"id":"ev:sanitizer"`) {
			t.Fatalf("request lacks deterministic dictionary: %s", joined)
		}
		if strings.Contains(joined, "proposer verdict") {
			t.Fatal("blind verifier prompt leaked proposer result")
		}
	}
}

func TestAssessWithEvidenceRejectsUnknownOrUnsupportedCitations(t *testing.T) {
	for name, reply := range map[string]string{
		"unknown":     `{"verdict":"sound","driver":"attacker_controlled","confidence":90,"evidence_tokens":["ev:invented"]}`,
		"unsupported": `{"verdict":"refuted","driver":"input_sanitized","confidence":90,"evidence_tokens":["ev:cwe"]}`,
		"missing":     `{"verdict":"sound","driver":"attacker_controlled","confidence":90,"evidence_tokens":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			llm := &evidenceLLM{replies: map[string]string{"proposer": reply}}
			got := New(llm, "proposer").AssessWithEvidence(context.Background(), []finding.Finding{evidenceCandidate()}, nil, evidenceContext())[0]
			if got.Err == nil {
				t.Fatalf("invalid citation became a retained claim: %+v", got)
			}
		})
	}
}

func TestAssessWithEvidenceFailsBeforeProviderWhenDictionaryMissing(t *testing.T) {
	llm := &evidenceLLM{replies: map[string]string{"proposer": `{"verdict":"sound","driver":"attacker_controlled","confidence":90,"evidence_tokens":["ev:cwe"]}`}}
	got := New(llm, "proposer").AssessWithEvidence(context.Background(), []finding.Finding{evidenceCandidate()}, nil, nil)[0]
	if got.Err == nil || len(llm.requests) != 0 {
		t.Fatalf("missing evidence should fail before provider: got=%+v calls=%d", got, len(llm.requests))
	}
}

func TestNormalizeEvidenceRejectsDuplicateAndOversizeTokens(t *testing.T) {
	dup := []ports.AITriageEvidenceToken{{ID: "ev:cwe", Kind: ports.AITriageEvidenceKindCWE, Value: "a"}, {ID: "ev:cwe", Kind: ports.AITriageEvidenceKindCWE, Value: "b"}}
	if _, err := normalizeEvidence(dup, true); err == nil {
		t.Fatal("duplicate evidence id accepted")
	}
	if _, err := normalizeEvidence([]ports.AITriageEvidenceToken{{ID: "ev:cwe", Kind: ports.AITriageEvidenceKindCWE, Value: strings.Repeat("x", ports.MaxAITriageEvidenceValueRunes+1)}}, true); err == nil {
		t.Fatal("oversized evidence accepted")
	}
}

func TestEvidenceAwareTriagerMapsReceipt(t *testing.T) {
	llm := &evidenceLLM{replies: map[string]string{"proposer": `{"verdict":"sound","driver":"attacker_controlled","confidence":82,"evidence_tokens":["ev:cwe"]}`}}
	triager := NewTriager(New(llm, "proposer"), nil)
	got := triager.TriageWithEvidence(context.Background(), []finding.Finding{evidenceCandidate()}, "", evidenceContext())
	if len(got) != 1 || got[0].PromptVersion != evidencePromptVersion || len(got[0].ContextEvidence) != 2 || len(got[0].EvidenceTokens) != 1 {
		t.Fatalf("mapped critique=%+v", got)
	}
}

func TestRefutedDriversRequireRelevantDeterministicEvidence(t *testing.T) {
	base := []ports.AITriageEvidenceToken{{ID: "ev:cwe", Kind: ports.AITriageEvidenceKindCWE, Value: "CWE-327"}}
	bad := []struct {
		name     string
		driver   string
		evidence []ports.AITriageEvidenceToken
		cite     string
	}{
		{name: "semantic sound driver", driver: "attacker_controlled", evidence: base, cite: "ev:cwe"},
		{name: "semantic uncertainty driver", driver: "insufficient_context", evidence: base, cite: "ev:cwe"},
		{name: "intended without proof", driver: "intended_behavior", evidence: base, cite: "ev:cwe"},
		{name: "attacker source cannot prove non attacker control", driver: "not_attacker_controlled", evidence: []ports.AITriageEvidenceToken{{ID: "ev:source", Kind: ports.AITriageEvidenceKindSource, Value: "HTTP query parameter"}}, cite: "ev:source"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			reply := fmt.Sprintf(`{"verdict":"refuted","driver":%q,"confidence":95,"evidence_tokens":[%q]}`, tc.driver, tc.cite)
			if _, _, err := parseCritiqueWithEvidence(reply, tc.evidence); err == nil {
				t.Fatalf("unsupported refutation driver %q was accepted", tc.driver)
			}
		})
	}

	good := []struct {
		driver   string
		evidence []ports.AITriageEvidenceToken
		cite     string
	}{
		{driver: "input_sanitized", evidence: []ports.AITriageEvidenceToken{{ID: "ev:sanitizer", Kind: ports.AITriageEvidenceKindSanitizer, Value: "sanitized before sink"}}, cite: "ev:sanitizer"},
		{driver: "not_attacker_controlled", evidence: []ports.AITriageEvidenceToken{{ID: "ev:source", Kind: ports.AITriageEvidenceKindSource, Value: "server-side constant literal"}}, cite: "ev:source"},
		{driver: "intended_behavior", evidence: []ports.AITriageEvidenceToken{{ID: "ev:counter_evidence", Kind: ports.AITriageEvidenceKindCounterEvidence, Value: "configured intended behavior"}}, cite: "ev:counter_evidence"},
	}
	for _, tc := range good {
		reply := fmt.Sprintf(`{"verdict":"refuted","driver":%q,"confidence":95,"evidence_tokens":[%q]}`, tc.driver, tc.cite)
		if _, _, err := parseCritiqueWithEvidence(reply, tc.evidence); err != nil {
			t.Fatalf("supported refutation %q rejected: %v", tc.driver, err)
		}
	}
}

func TestValidateEvidenceReceiptBindsContextToServerAndFinding(t *testing.T) {
	item := evidenceCandidate()
	server := []ports.AITriageEvidenceToken{
		{ID: "ev:finding_identity", Kind: ports.AITriageEvidenceKindFindingIdentity, Value: finding.Identity(item)},
		{ID: "ev:sanitizer", Kind: ports.AITriageEvidenceKindSanitizer, Value: "sanitized before sink"},
	}
	valid := ports.AICritique{
		DedupKey: item.DedupKey, Verdict: "refuted", Driver: "input_sanitized", Confidence: 92,
		VerifierModel: "verifier", VerifierVerdict: "refuted", VerifierDriver: "input_sanitized", VerifierConfidence: 90,
		PromptVersion:   evidencePromptVersion,
		ContextEvidence: append([]ports.AITriageEvidenceToken(nil), server...),
		EvidenceTokens:  []string{"ev:sanitizer"}, VerifierEvidenceTokens: []string{"ev:sanitizer"},
	}
	if err := ValidateEvidenceReceiptAgainst(valid, item, server); err != nil {
		t.Fatalf("valid evidence receipt rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ports.AICritique){
		"prompt":                  func(c *ports.AICritique) { c.PromptVersion = promptVersion },
		"identity missing":        func(c *ports.AICritique) { c.ContextEvidence = c.ContextEvidence[1:] },
		"identity mismatch":       func(c *ports.AICritique) { c.ContextEvidence[0].Value = "other" },
		"self-attested sanitizer": func(c *ports.AICritique) { c.ContextEvidence[1].Value = "sanitized: fabricated by port" },
		"proposer citation":       func(c *ports.AICritique) { c.EvidenceTokens = []string{"ev:finding_identity"} },
		"verifier citation":       func(c *ports.AICritique) { c.VerifierEvidenceTokens = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.ContextEvidence = append([]ports.AITriageEvidenceToken(nil), valid.ContextEvidence...)
			candidate.EvidenceTokens = append([]string(nil), valid.EvidenceTokens...)
			candidate.VerifierEvidenceTokens = append([]string(nil), valid.VerifierEvidenceTokens...)
			mutate(&candidate)
			if err := ValidateEvidenceReceiptAgainst(candidate, item, server); err == nil {
				t.Fatalf("invalid receipt %s accepted: %+v", name, candidate)
			}
		})
	}
}

func TestEvaluationPromptVersionUsesEvidenceContract(t *testing.T) {
	if EvaluationPromptVersion() != evidencePromptVersion || EvaluationPromptVersion() != "fp-triage-v3" {
		t.Fatalf("evaluation must execute the evidence-rich prompt contract, got %q", EvaluationPromptVersion())
	}
}
