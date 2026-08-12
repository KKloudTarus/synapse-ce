package fptriage

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func evidenceForObservedTest(findingID string) []ports.AITriageEvidenceToken {
	return []ports.AITriageEvidenceToken{
		{ID: "ev:finding_identity", Kind: ports.AITriageEvidenceKindFindingIdentity, Value: findingID},
		{ID: "ev:source", Kind: ports.AITriageEvidenceKindSource, Value: "literal constant"},
	}
}

func TestEvidenceObservedTriageUsesV3MetricsAndCitations(t *testing.T) {
	llm := &observedLLM{content: `{"verdict":"refuted","driver":"constant_or_literal","confidence":90,"evidence_tokens":["ev:source"]}`, usage: agent.Usage{PromptTokens: 20, CompletionTokens: 10, TotalTokens: 30}}
	f := mkFinding("a", "finding")
	evidence := evidenceForObservedTest(f.DedupKey)
	coord := New(llm, "model").WithOperationalPolicy(ports.FPTriageOperationalPolicy{MaxTokens: 100000})
	p := coord.prepareWithEvidence(context.Background(), f, nil, evidence, true)
	critiques, telemetry := coord.assessPreparedObserved(context.Background(), []preparedFinding{p})
	if len(critiques) != 1 || critiques[0].Err != nil || len(critiques[0].EvidenceTokens) != 1 || critiques[0].EvidenceTokens[0] != "ev:source" {
		t.Fatalf("evidence critique = %+v", critiques)
	}
	if len(telemetry.Calls) != 1 || telemetry.Calls[0].PromptVersion != evidencePromptVersion || telemetry.ParseFailureCount != 0 {
		t.Fatalf("telemetry = %+v", telemetry)
	}
}

func TestEvidenceObservedTriageCountsMissingCitationAsParseFailure(t *testing.T) {
	llm := &observedLLM{content: `{"verdict":"refuted","driver":"constant_or_literal","confidence":90,"evidence_tokens":[]}`}
	f := mkFinding("a", "finding")
	coord := New(llm, "model").WithOperationalPolicy(ports.FPTriageOperationalPolicy{MaxTokens: 100000})
	p := coord.prepareWithEvidence(context.Background(), f, nil, evidenceForObservedTest(f.DedupKey), true)
	critiques, telemetry := coord.assessPreparedObserved(context.Background(), []preparedFinding{p})
	if llm.count() != 1 || len(critiques) != 1 || critiques[0].Err == nil || telemetry.ParseFailureCount != 1 || telemetry.SuccessCount != 0 {
		t.Fatalf("calls=%d critiques=%+v telemetry=%+v", llm.count(), critiques, telemetry)
	}
}

func TestEvidenceObservedTriageEnforcesTokenBudgetBeforeProviderCall(t *testing.T) {
	llm := &observedLLM{content: `{"verdict":"sound","driver":"attacker_controlled","confidence":90,"evidence_tokens":["ev:source"]}`}
	f := mkFinding("a", "finding")
	coord := New(llm, "model").WithOperationalPolicy(ports.FPTriageOperationalPolicy{MaxTokens: 1})
	p := coord.prepareWithEvidence(context.Background(), f, nil, evidenceForObservedTest(f.DedupKey), true)
	critiques, telemetry := coord.assessPreparedObserved(context.Background(), []preparedFinding{p})
	if llm.count() != 0 || telemetry.BudgetSkippedFindings != 1 || len(critiques) != 1 || critiques[0].Err == nil {
		t.Fatalf("calls=%d critiques=%+v telemetry=%+v", llm.count(), critiques, telemetry)
	}
}
