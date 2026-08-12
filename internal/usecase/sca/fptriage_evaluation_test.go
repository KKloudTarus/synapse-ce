package sca

import (
	"context"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixtureEvaluationTriager struct{}

func (fixtureEvaluationTriager) Triage(_ context.Context, candidates []finding.Finding, _ string) []ports.AICritique {
	out := make([]ports.AICritique, 0, len(candidates))
	for _, candidate := range candidates {
		c := ports.AICritique{
			DedupKey: candidate.DedupKey, ProposerModel: "fixture-proposer", ProposerProvider: "fixture-provider",
			ProposerModelFamily: "fixture-proposer", VerifierModel: "fixture-verifier", VerifierProvider: "fixture-provider",
			VerifierModelFamily: "fixture-verifier", IndependencePolicy: ports.AIIndependenceModelFamily, PromptVersion: "fixture-prompt-v1",
		}
		switch candidate.DedupKey {
		case "ai-eval:fp-go-constant-input", "ai-eval:fp-js-static-regexp", "ai-eval:tp-java-predictable-session":
			c.Verdict, c.Driver, c.Confidence, c.SuspectedFP = "refuted", "constant_or_literal", 95, true
			c.Verified, c.VerifierVerdict, c.VerifierDriver, c.VerifierConfidence = true, "refuted", "constant_or_literal", 92
		case "ai-eval:tp-python-path-traversal":
			c.Verdict, c.Driver, c.Confidence = "refuted", "constant_or_literal", 94
			c.VerifierVerdict, c.VerifierDriver, c.VerifierConfidence = "sound", "attacker_controlled", 91
		case "ai-eval:uncertain-k8s-network-policy":
			c.Verdict, c.Driver, c.Confidence = "refuted", "constant_or_literal", 90
			c.VerifierVerdict, c.VerifierDriver, c.VerifierConfidence = "uncertain", "insufficient_context", 82
		case "ai-eval:uncertain-ruby-dispatch":
			c.Verdict, c.Driver, c.Confidence = "uncertain", "insufficient_context", 70
		default:
			c.Verdict, c.Driver, c.Confidence = "sound", "attacker_controlled", 96
		}
		// A buggy injected triager may forge this field; shadow policy must clear it.
		c.GateExempt = true
		out = append(out, c)
	}
	return out
}

func (fixtureEvaluationTriager) TriageWithEvidence(_ context.Context, candidates []finding.Finding, _ string, evidence map[string][]ports.AITriageEvidenceToken) []ports.AICritique {
	out := fixtureEvaluationTriager{}.Triage(context.Background(), candidates, "")
	for i := range out {
		c := &out[i]
		c.PromptVersion = "fp-triage-v3"
		c.ContextEvidence = append([]ports.AITriageEvidenceToken(nil), evidence[c.DedupKey]...)
		proposerCitation := "ev:finding_identity"
		verifierCitation := "ev:finding_identity"
		if c.Verdict == "refuted" {
			c.ContextEvidence = append(c.ContextEvidence, ports.AITriageEvidenceToken{ID: "ev:source", Kind: "source", Value: "synthetic evaluator deterministic cue: server-side constant literal"})
			proposerCitation = "ev:source"
		}
		if c.VerifierVerdict == "refuted" {
			if proposerCitation != "ev:source" {
				c.ContextEvidence = append(c.ContextEvidence, ports.AITriageEvidenceToken{ID: "ev:source", Kind: "source", Value: "synthetic evaluator deterministic cue: server-side constant literal"})
			}
			verifierCitation = "ev:source"
		}
		c.EvidenceTokens = []string{proposerCitation}
		c.VerifierEvidenceTokens = []string{verifierCitation}
	}
	return out
}

func loadGoldenEvaluationDataset(t *testing.T) AIEvaluationDataset {
	t.Helper()
	b, err := os.ReadFile("testdata/fptriage-golden-v1.json")
	if err != nil {
		t.Fatalf("read golden dataset: %v", err)
	}
	dataset, err := LoadAIEvaluationDataset(b)
	if err != nil {
		t.Fatalf("load golden dataset: %v", err)
	}
	return dataset
}

func TestEvaluateFPTriageGoldenDataset(t *testing.T) {
	dataset := loadGoldenEvaluationDataset(t)
	run := AIEvaluationRun{
		ProposerProvider: "fixture-provider", ProposerModel: "fixture-proposer",
		VerifierProvider: "fixture-provider", VerifierModel: "fixture-verifier",
		IndependencePolicy: ports.AIIndependenceModelFamily,
		PromptVersion:      "fp-triage-v3", PolicyVersion: aiTriagePolicyVersion,
	}
	report, err := EvaluateFPTriage(context.Background(), dataset, run, fixtureEvaluationTriager{})
	if err != nil {
		t.Fatalf("EvaluateFPTriage: %v", err)
	}
	if report.RunID == "" || report.DatasetSHA256 == "" || report.DatasetVersion != dataset.Version || report.Run != run {
		t.Fatalf("versioned run metadata missing: %+v", report)
	}
	m := report.Metrics
	if m.Total != 8 || m.Covered != 8 || m.HumanFalsePositives != 2 || m.HumanTruePositives != 4 ||
		m.ConsensusFalsePositives != 3 || m.CorrectFalsePositives != 2 || m.TruePositiveEscapes != 1 ||
		m.VerifierComparisons != 5 || m.VerifierDisagreements != 2 {
		t.Fatalf("unexpected aggregate counters: %+v", m)
	}
	if m.Precision != 2.0/3.0 || m.Recall != 1 || m.FalseNegativeEscapeRate != 0.25 ||
		m.DisagreementRate != 0.4 || m.Coverage != 1 {
		t.Fatalf("unexpected aggregate rates: %+v", m)
	}
	for _, dimension := range []string{"language", "kind", "cwe", "severity", "framework"} {
		if len(report.Breakdowns[dimension]) == 0 {
			t.Errorf("missing %s breakdown", dimension)
		}
	}
	for _, result := range report.Results {
		if result.GateExempt || result.Critique.GateExempt || !result.Critique.Shadow {
			t.Fatalf("shadow evaluation leaked gate authority: %+v", result)
		}
	}

	again, err := EvaluateFPTriage(context.Background(), dataset, run, fixtureEvaluationTriager{})
	if err != nil {
		t.Fatalf("repeat EvaluateFPTriage: %v", err)
	}
	if again.RunID != report.RunID {
		t.Fatalf("same dataset and replies produced run IDs %q and %q", report.RunID, again.RunID)
	}
}

func TestAIEvaluationDatasetRequiresReviewMetadata(t *testing.T) {
	dataset := loadGoldenEvaluationDataset(t)
	dataset.Reviewer = ""
	if err := dataset.Validate(); err == nil {
		t.Fatal("dataset without a reviewer must be rejected")
	}
}

func TestAIEvaluationSourceReaderUsesOnlyDatasetSource(t *testing.T) {
	dataset := loadGoldenEvaluationDataset(t)
	reader := NewAIEvaluationSourceReader(dataset)
	got, err := reader.Snippet(context.Background(), dataset.Cases[0].File, dataset.Cases[0].Line, 8)
	if err != nil || got != dataset.Cases[0].Source {
		t.Fatalf("dataset source = %q, %v", got, err)
	}
	if _, err := reader.Snippet(context.Background(), "production/secret.go", 1, 8); err == nil {
		t.Fatal("reader must not fall through to production filesystem data")
	}
}
