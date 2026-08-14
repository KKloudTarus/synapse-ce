package sca

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAIEvaluationReleasePromotionAndRollbackAreVersionedAndChained(t *testing.T) {
	evidence := releaseTestEvidence(t)
	comparison := evidence.Comparison
	manifest := releaseTestManifest("release-2026-08-canary", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	manifest.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &evidence, manifest)

	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Decisions) != 1 || ledger.Decisions[0].Status != "approved" ||
		ledger.Decisions[0].ActiveRun.PromptVersion != "prompt-v2" || ledger.HeadDecisionID == "" {
		t.Fatalf("promotion ledger = %+v", ledger)
	}

	rollback := releaseTestManifest("release-2026-08-rollback", AIEvaluationReleaseRollback, "", "initial")
	rollback.Approvals = releaseTestApprovals(t, ledger, nil, rollback)
	ledger, err = ApplyAIEvaluationRelease(ledger, nil, rollback)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Decisions) != 2 || ledger.Decisions[1].PreviousDecisionID != ledger.Decisions[0].DecisionID ||
		ledger.Decisions[1].ActiveRun.PromptVersion != "prompt-v1" {
		t.Fatalf("rollback ledger = %+v", ledger)
	}
	b, _ := json.Marshal(ledger)
	loaded, err := LoadAIEvaluationReleaseLedger(b)
	if err != nil || loaded.HeadDecisionID != ledger.HeadDecisionID {
		t.Fatalf("load ledger = %+v err=%v", loaded, err)
	}
}

func TestAIEvaluationReleaseRejectsMachineDuplicateAndReplayedApprovals(t *testing.T) {
	evidence := releaseTestEvidence(t)
	comparison := evidence.Comparison
	manifest := releaseTestManifest("release-canary", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	manifest.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &evidence, manifest)

	tests := map[string]func(*AIEvaluationReleaseManifest){
		"same human":      func(m *AIEvaluationReleaseManifest) { m.Approvals[1].Reviewer = m.Approvals[0].Reviewer },
		"model actor":     func(m *AIEvaluationReleaseManifest) { m.Approvals[0].Reviewer = comparison.CandidateRun.ProposerModel },
		"machine actor":   func(m *AIEvaluationReleaseManifest) { m.Approvals[0].Reviewer = "bot:release" },
		"replayed digest": func(m *AIEvaluationReleaseManifest) { m.Provenance = "security/change-43" },
		"role order":      func(m *AIEvaluationReleaseManifest) { m.Approvals[0], m.Approvals[1] = m.Approvals[1], m.Approvals[0] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			changed.Approvals = append([]AIEvaluationReleaseApproval(nil), manifest.Approvals...)
			mutate(&changed)
			if _, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, changed); err == nil {
				t.Fatal("unsafe release approval was accepted")
			}
		})
	}
}

func TestAIEvaluationReleaseRejectsBlockedComparisonAndTamperedLedger(t *testing.T) {
	evidence := releaseTestEvidence(t)
	comparison := evidence.Comparison
	blocked := comparison
	blocked.Status = "blocked"
	blocked.ApprovalRequired = false
	blocked.ComparisonID = evaluationComparisonID(blocked)
	manifest := releaseTestManifest("release-canary", AIEvaluationReleasePromote, blocked.ComparisonID, "")
	blockedEvidence := evidence
	blockedEvidence.Comparison = blocked
	if _, err := AIEvaluationReleaseReviewDigest(AIEvaluationReleaseLedger{}, &blockedEvidence, manifest); err == nil {
		t.Fatal("blocked comparison reached approval")
	}

	manifest = releaseTestManifest("release-canary", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	manifest.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &evidence, manifest)
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Decisions[0].ActiveRun.PromptVersion = "tampered"
	if err := ledger.Validate(); err == nil {
		t.Fatal("tampered ledger passed validation")
	}
}

func TestAIEvaluationReleaseRejectsUnknownAndCurrentRollbackTargets(t *testing.T) {
	evidence := releaseTestEvidence(t)
	comparison := evidence.Comparison
	manifest := releaseTestManifest("release-canary", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	manifest.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &evidence, manifest)
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{strings.Repeat("a", 64), ledger.HeadDecisionID} {
		rollback := releaseTestManifest("rollback-"+target[:4], AIEvaluationReleaseRollback, "", target)
		if _, err := AIEvaluationReleaseReviewDigest(ledger, nil, rollback); err == nil {
			t.Fatalf("rollback target %q was accepted", target)
		}
	}
}

func TestAIEvaluationReleaseApprovalCannotReplayAfterLedgerHeadChanges(t *testing.T) {
	firstEvidence := releaseTestEvidenceFor(t, "prompt-v1", "prompt-v2")
	first := releaseTestManifest("release-one", AIEvaluationReleasePromote, firstEvidence.Comparison.ComparisonID, "")
	first.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &firstEvidence, first)
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &firstEvidence, first)
	if err != nil {
		t.Fatal(err)
	}

	rollback := releaseTestManifest("rollback-one", AIEvaluationReleaseRollback, "", "initial")
	rollback.Approvals = releaseTestApprovals(t, ledger, nil, rollback)

	secondEvidence := releaseTestEvidenceFor(t, "prompt-v2", "prompt-v3")
	second := releaseTestManifest("release-two", AIEvaluationReleasePromote, secondEvidence.Comparison.ComparisonID, "")
	second.Approvals = releaseTestApprovals(t, ledger, &secondEvidence, second)
	ledger, err = ApplyAIEvaluationRelease(ledger, &secondEvidence, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyAIEvaluationRelease(ledger, nil, rollback); err == nil {
		t.Fatal("approval from an older ledger head was replayed")
	}
}

func TestAIEvaluationReleaseRecomputesComparisonFromReports(t *testing.T) {
	evidence := releaseTestEvidence(t)
	evidence.BaselineReport.Run.PromptVersion = "tampered"
	manifest := releaseTestManifest("release-canary", AIEvaluationReleasePromote, evidence.Comparison.ComparisonID, "")
	if _, err := AIEvaluationReleaseReviewDigest(AIEvaluationReleaseLedger{}, &evidence, manifest); err == nil {
		t.Fatal("comparison was trusted after its baseline report changed")
	}
}

func releaseTestEvidence(t *testing.T) AIEvaluationPromotionEvidence {
	return releaseTestEvidenceFor(t, "prompt-v1", "prompt-v2")
}

func releaseTestEvidenceFor(t *testing.T, baselinePrompt, candidatePrompt string) AIEvaluationPromotionEvidence {
	t.Helper()
	baseline, candidate := promotionTestReport(baselinePrompt, nil), promotionTestReport(candidatePrompt, nil)
	comparison, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return AIEvaluationPromotionEvidence{BaselineReport: baseline, CandidateReport: candidate, Comparison: comparison}
}

func releaseTestManifest(version, action, comparisonID, rollbackTo string) AIEvaluationReleaseManifest {
	return AIEvaluationReleaseManifest{SchemaVersion: AIEvaluationReleaseManifestSchema, Version: version,
		Action: action, Provenance: "security/change-42", ComparisonID: comparisonID, RollbackTo: rollbackTo}
}

func releaseTestApprovals(t *testing.T, ledger AIEvaluationReleaseLedger, evidence *AIEvaluationPromotionEvidence, manifest AIEvaluationReleaseManifest) []AIEvaluationReleaseApproval {
	t.Helper()
	digest, err := AIEvaluationReleaseReviewDigest(ledger, evidence, manifest)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	return []AIEvaluationReleaseApproval{
		{Role: "pm", Reviewer: "pm@example.com", Approved: true, Rationale: "Product rollout approved", ReviewedAt: now, ReviewedSHA256: digest},
		{Role: "security", Reviewer: "security@example.com", Approved: true, Rationale: "Security evidence approved", ReviewedAt: now.Add(time.Minute), ReviewedSHA256: digest},
	}
}
