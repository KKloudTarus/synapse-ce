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

	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest, releaseTestApprovers())
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Decisions) != 1 || ledger.Decisions[0].Status != "approved" ||
		ledger.Decisions[0].ActiveRun.PromptVersion != "prompt-v2" || ledger.HeadDecisionID == "" {
		t.Fatalf("promotion ledger = %+v", ledger)
	}

	rollback := releaseTestManifest("release-2026-08-rollback", AIEvaluationReleaseRollback, "", "initial")
	rollback.Approvals = releaseTestApprovals(t, ledger, nil, rollback)
	ledger, err = ApplyAIEvaluationRelease(ledger, nil, rollback, releaseTestApprovers())
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
			if _, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, changed, releaseTestApprovers()); err == nil {
				t.Fatal("unsafe release approval was accepted")
			}
		})
	}
}

func TestAIEvaluationReleaseRequiresAllowlistedHumanApprovers(t *testing.T) {
	evidence := releaseTestEvidence(t)
	comparison := evidence.Comparison
	manifest := releaseTestManifest("release-canary", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	manifest.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &evidence, manifest)

	rejected := map[string][]string{
		"no allowlist":            nil,
		"empty allowlist":         {},
		"security absent":         {"pm@example.com"},
		"case differs":            {"PM@example.com", "security@example.com"},
		"entry is not trimmed":    {" pm@example.com", "security@example.com"},
		"machine principal entry": {"system:release", "security@example.com"},
	}
	for name, approvers := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest, approvers); err == nil {
				t.Fatal("release recorded an approver the operator never admitted")
			}
		})
	}

	// The denylist keeps its say: an allowlist entry cannot launder a model identity into an approval.
	launder := manifest
	launder.Approvals = append([]AIEvaluationReleaseApproval(nil), manifest.Approvals...)
	launder.Approvals[0].Reviewer = comparison.CandidateRun.ProposerModel
	if _, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, launder,
		[]string{comparison.CandidateRun.ProposerModel, "security@example.com"}); err == nil {
		t.Fatal("allowlisting a model identity admitted it as a human approver")
	}

	if _, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest, releaseTestApprovers()); err != nil {
		t.Fatalf("allowlisted approvers were rejected: %v", err)
	}
}

// A decision keeps the approvers it was admitted with. An approver who later leaves the allowlist -- or
// a ledger read somewhere the allowlist is not available at all -- must not invalidate signed history,
// otherwise the append-only evidence chain would stop loading on a staffing change.
func TestAIEvaluationReleaseLedgerValidatesWithoutTheApproverAllowlist(t *testing.T) {
	evidence := releaseTestEvidence(t)
	manifest := releaseTestManifest("release-canary", AIEvaluationReleasePromote, evidence.Comparison.ComparisonID, "")
	manifest.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &evidence, manifest)
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest, releaseTestApprovers())
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Validate(); err != nil {
		t.Fatalf("signed history failed to validate without an allowlist: %v", err)
	}
	b, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAIEvaluationReleaseLedger(b)
	if err != nil || loaded.HeadDecisionID != ledger.HeadDecisionID {
		t.Fatalf("stored ledger no longer loads: %+v err=%v", loaded, err)
	}

	// The next decision still has to clear the allowlist in force now.
	rollback := releaseTestManifest("release-rollback", AIEvaluationReleaseRollback, "", "initial")
	rollback.Approvals = releaseTestApprovals(t, ledger, nil, rollback)
	if _, err := ApplyAIEvaluationRelease(ledger, nil, rollback, []string{"pm@example.com"}); err == nil {
		t.Fatal("a later decision skipped the current allowlist")
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
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest, releaseTestApprovers())
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
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &evidence, manifest, releaseTestApprovers())
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
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &firstEvidence, first, releaseTestApprovers())
	if err != nil {
		t.Fatal(err)
	}

	rollback := releaseTestManifest("rollback-one", AIEvaluationReleaseRollback, "", "initial")
	rollback.Approvals = releaseTestApprovals(t, ledger, nil, rollback)

	secondEvidence := releaseTestEvidenceFor(t, "prompt-v2", "prompt-v3")
	second := releaseTestManifest("release-two", AIEvaluationReleasePromote, secondEvidence.Comparison.ComparisonID, "")
	second.Approvals = releaseTestApprovals(t, ledger, &secondEvidence, second)
	ledger, err = ApplyAIEvaluationRelease(ledger, &secondEvidence, second, releaseTestApprovers())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyAIEvaluationRelease(ledger, nil, rollback, releaseTestApprovers()); err == nil {
		t.Fatal("approval from an older ledger head was replayed")
	}
}

func TestAIEvaluationReleaseRejectsFreshBaselineForSameActiveConfiguration(t *testing.T) {
	firstEvidence := releaseTestEvidenceFor(t, "prompt-v1", "prompt-v2")
	first := releaseTestManifest("release-one", AIEvaluationReleasePromote, firstEvidence.Comparison.ComparisonID, "")
	first.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &firstEvidence, first)
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &firstEvidence, first, releaseTestApprovers())
	if err != nil {
		t.Fatal(err)
	}

	// This is the same prompt/model configuration as the active run, but it is a freshly
	// evaluated artifact with different canonical evidence. It must not replace the exact
	// active run as the next promotion's baseline.
	freshBaseline := promotionTestReport("prompt-v2", func(results []AIEvaluationResult) {
		results[0].Critique.Confidence--
	})
	if freshBaseline.RunID == currentReleaseRunID(ledger) {
		t.Fatal("test setup did not create a distinct baseline run")
	}
	candidate := promotionTestReport("prompt-v3", nil)
	comparison, err := CompareAIEvaluationReports(freshBaseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	evidence := AIEvaluationPromotionEvidence{BaselineReport: freshBaseline, CandidateReport: candidate, Comparison: comparison}
	manifest := releaseTestManifest("release-two", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	if _, err := AIEvaluationReleaseReviewDigest(ledger, &evidence, manifest); err == nil {
		t.Fatal("fresh same-configuration baseline replaced the exact active approved run")
	}

	validEvidence := releaseTestEvidenceFor(t, "prompt-v2", "prompt-v3")
	validManifest := releaseTestManifest("release-two-valid", AIEvaluationReleasePromote, validEvidence.Comparison.ComparisonID, "")
	validManifest.Approvals = releaseTestApprovals(t, ledger, &validEvidence, validManifest)
	validLedger, err := ApplyAIEvaluationRelease(ledger, &validEvidence, validManifest, releaseTestApprovers())
	if err != nil {
		t.Fatal(err)
	}
	validLedger.Decisions[1].BaselineEvaluationID = freshBaseline.RunID
	validLedger.Decisions[1].DecisionID, err = releaseDecisionID(validLedger.Decisions[1])
	if err != nil {
		t.Fatal(err)
	}
	validLedger.HeadDecisionID = validLedger.Decisions[1].DecisionID
	if err := validLedger.Validate(); err == nil {
		t.Fatal("ledger validation accepted a rehashed promotion with a substituted baseline run id")
	}
}

func TestAIEvaluationReleaseEnforcesPromotionPolicyFloor(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	candidate := promotionTestReport("prompt-v2", nil)
	weak := DefaultAIEvaluationPromotionPolicy()
	weak.MinimumPrecisionBasisPoints = 0
	comparison, err := CompareAIEvaluationReports(baseline, candidate, weak)
	if err != nil {
		t.Fatal(err)
	}
	evidence := AIEvaluationPromotionEvidence{BaselineReport: baseline, CandidateReport: candidate, Comparison: comparison}
	manifest := releaseTestManifest("release-weak", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	if _, err := AIEvaluationReleaseReviewDigest(AIEvaluationReleaseLedger{}, &evidence, manifest); err == nil {
		t.Fatal("self-declared policy below the release safety floor was accepted")
	}

	weakRobustness := DefaultAIEvaluationPromotionPolicy()
	weakRobustness.MinimumCounterfactualCoverageBasisPoints = 0
	comparison, err = CompareAIEvaluationReports(baseline, candidate, weakRobustness)
	if err != nil {
		t.Fatal(err)
	}
	evidence = AIEvaluationPromotionEvidence{BaselineReport: baseline, CandidateReport: candidate, Comparison: comparison}
	manifest = releaseTestManifest("release-weak-robustness", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	if _, err := AIEvaluationReleaseReviewDigest(AIEvaluationReleaseLedger{}, &evidence, manifest); err == nil {
		t.Fatal("release accepted a policy without complete counterfactual coverage")
	}

	validEvidence := releaseTestEvidence(t)
	validManifest := releaseTestManifest("release-valid", AIEvaluationReleasePromote, validEvidence.Comparison.ComparisonID, "")
	validManifest.Approvals = releaseTestApprovals(t, AIEvaluationReleaseLedger{}, &validEvidence, validManifest)
	ledger, err := ApplyAIEvaluationRelease(AIEvaluationReleaseLedger{}, &validEvidence, validManifest, releaseTestApprovers())
	if err != nil {
		t.Fatal(err)
	}
	ledger.Decisions[0].PromotionPolicy.MinimumPrecisionBasisPoints = 0
	ledger.Decisions[0].DecisionID, err = releaseDecisionID(ledger.Decisions[0])
	if err != nil {
		t.Fatal(err)
	}
	ledger.HeadDecisionID = ledger.Decisions[0].DecisionID
	if err := ledger.Validate(); err == nil {
		t.Fatal("ledger validation accepted a rehashed policy below the release safety floor")
	}

	strict := DefaultAIEvaluationPromotionPolicy()
	strict.MinimumPrecisionBasisPoints = 9600
	comparison, err = CompareAIEvaluationReports(baseline, candidate, strict)
	if err != nil {
		t.Fatal(err)
	}
	evidence = AIEvaluationPromotionEvidence{BaselineReport: baseline, CandidateReport: candidate, Comparison: comparison}
	manifest = releaseTestManifest("release-strict", AIEvaluationReleasePromote, comparison.ComparisonID, "")
	if _, err := AIEvaluationReleaseReviewDigest(AIEvaluationReleaseLedger{}, &evidence, manifest); err != nil {
		t.Fatalf("stricter release policy was rejected: %v", err)
	}
}

func TestAIEvaluationRollbackSeparationOfDutiesIncludesTargetModels(t *testing.T) {
	target := candidateRun("prompt-v1")
	target.ProposerModel = "rollback-target-model"
	current := candidateRun("prompt-v2")
	ledger := AIEvaluationReleaseLedger{
		SchemaVersion: aiEvaluationReleaseLedgerSchema,
		InitialRun:    target,
		InitialRunID:  strings.Repeat("a", 64),
		Decisions: []AIEvaluationReleaseDecision{{
			ActiveRun: current, ActiveRunID: strings.Repeat("b", 64),
		}},
	}
	manifest := releaseTestManifest("rollback-target", AIEvaluationReleaseRollback, "", "initial")
	digest := strings.Repeat("c", 64)
	now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	approvals := []AIEvaluationReleaseApproval{
		{Role: "pm", Reviewer: target.ProposerModel, Approved: true, Rationale: "Product approval", ReviewedAt: now, ReviewedSHA256: digest},
		{Role: "security", Reviewer: "security@example.com", Approved: true, Rationale: "Security approval", ReviewedAt: now.Add(time.Minute), ReviewedSHA256: digest},
	}
	if err := validateReleaseApprovals(approvals, digest, releaseModelIdentities(ledger, nil, manifest)); err == nil {
		t.Fatal("rollback target model was accepted as a human approver")
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

func releaseTestApprovers() []string {
	return []string{"pm@example.com", "security@example.com"}
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
