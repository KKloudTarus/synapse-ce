package sca

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func feedbackReview(state aitriagereview.State) aitriagereview.Review {
	decidedAt := time.Unix(200, 0).UTC()
	return aitriagereview.Review{
		ID: "review-prod-1", TenantID: "tenant-secret", EngagementID: "eng-secret", FindingID: "finding-prod-1",
		DedupKey: "sast:private", Title: "production SQL injection", Severity: shared.SeverityMedium, CWE: "CWE-89",
		Owner: "original-reviewer", State: state, Verdict: "refuted", Driver: "sanitizer", Confidence: 92, SuspectedFP: true,
		ProposerModel: "model-a", ProposerProvider: "openai", ProposerModelFamily: "model-a",
		VerifierModel: "model-b", VerifierProvider: "anthropic", VerifierModelFamily: "model-b", IndependencePolicy: "provider",
		PromptVersion: "fp-triage-v3", Verified: true, VerifierVerdict: "refuted", VerifierDriver: "sanitizer", VerifierConfidence: 91,
		PolicyVersion: "fp-gate-v5", PolicyReason: "verified_consensus", ReviewRequired: true,
		EvidenceRef: "evidence-prod-1", DecidedBy: "original-reviewer", DecisionRationale: "contains production-only reasoning",
		CreatedAt: time.Unix(100, 0).UTC(), UpdatedAt: decidedAt, DecidedAt: &decidedAt, Version: 3,
	}
}

func feedbackCase(review aitriagereview.Review, label AIEvaluationLabel) AIEvaluationFeedbackCase {
	return AIEvaluationFeedbackCase{
		ReviewID: review.ID, Label: label, Language: "go", Framework: "net/http", Kind: finding.KindSAST,
		Title: "Curated SQL injection example", Description: "Approved minimal reproduction",
		File: "curated/sql_injection.go", Line: 7, Source: "package curated\nfunc handler() {}\n",
	}
}

func approveFeedbackCase(t *testing.T, review aitriagereview.Review, manifest *AIEvaluationFeedbackManifest, caseIndex int) {
	t.Helper()
	c := &manifest.Cases[caseIndex]
	digest, err := AIEvaluationFeedbackReviewDigest(review, *manifest, *c)
	if err != nil {
		t.Fatal(err)
	}
	at := review.DecidedAt.Add(time.Minute)
	c.PrivacyReview = AIEvaluationFeedbackApproval{
		Reviewer: "privacy-reviewer", Approved: true, Rationale: "approved redacted context", ReviewedAt: at, ReviewedSHA256: digest,
	}
	c.LabelQualityReview = AIEvaluationFeedbackApproval{
		Reviewer: "label-auditor", Approved: true, Rationale: "label matches reviewed outcome", ReviewedAt: at, ReviewedSHA256: digest,
	}
}

func feedbackManifest(cases ...AIEvaluationFeedbackCase) AIEvaluationFeedbackManifest {
	return AIEvaluationFeedbackManifest{
		SchemaVersion:  AIEvaluationFeedbackManifestSchema,
		DatasetVersion: "feedback-2026-08-12",
		Provenance:     "privacy-approved reviewer feedback batch",
		Curator:        "dataset-curator",
		Cases:          cases,
	}
}

func TestCurateAIEvaluationFeedbackProducesApprovedDatasetWithOpaqueProvenance(t *testing.T) {
	review := feedbackReview(aitriagereview.StateAccepted)
	manifest := feedbackManifest(feedbackCase(review, AIEvaluationFalsePositive))
	approveFeedbackCase(t, review, &manifest, 0)

	dataset, err := CurateAIEvaluationFeedback([]aitriagereview.Review{review}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if dataset.SchemaVersion != "synapse-ai-triage-dataset-v2" || dataset.Version != "feedback-2026-08-12" || dataset.Reviewer != "dataset-curator" {
		t.Fatalf("unexpected dataset metadata: %+v", dataset)
	}
	if !strings.HasPrefix(dataset.Provenance, "reviewer-feedback-curation; curated_feedback_sha256=") {
		t.Fatalf("dataset provenance is not bound to curation manifest: %q", dataset.Provenance)
	}
	if len(dataset.Cases) != 1 {
		t.Fatalf("want one curated case, got %d", len(dataset.Cases))
	}
	got := dataset.Cases[0]
	if !strings.HasPrefix(got.ID, "review-feedback-") || got.Label != AIEvaluationFalsePositive || got.Severity != shared.SeverityMedium || got.CWE != "CWE-89" {
		t.Fatalf("unexpected curated case: %+v", got)
	}

	encoded, err := json.Marshal(dataset)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{review.ID.String(), review.EvidenceRef.String(), review.TenantID.String(), review.DecisionRationale, manifest.Provenance} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("curated dataset leaked production/local curation provenance %q: %s", secret, encoded)
		}
	}
}

func TestCurateAIEvaluationFeedbackFailsClosedOnApprovalOrContentChanges(t *testing.T) {
	review := feedbackReview(aitriagereview.StateAccepted)
	base := feedbackManifest(feedbackCase(review, AIEvaluationFalsePositive))
	approveFeedbackCase(t, review, &base, 0)

	severityChanged := review
	severityChanged.Severity = shared.SeverityLow
	if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{severityChanged}, base); err == nil {
		t.Fatal("review severity changed after approval without invalidating digest")
	}

	caseMutations := map[string]func(*AIEvaluationFeedbackCase){
		"privacy not approved":        func(c *AIEvaluationFeedbackCase) { c.PrivacyReview.Approved = false },
		"source changed after review": func(c *AIEvaluationFeedbackCase) { c.Source += "// changed\n" },
		"label changed after review":  func(c *AIEvaluationFeedbackCase) { c.Label = AIEvaluationUncertain },
		"label auditor is original reviewer": func(c *AIEvaluationFeedbackCase) {
			c.LabelQualityReview.Reviewer = review.DecidedBy
		},
		"privacy and label auditor are same reviewer": func(c *AIEvaluationFeedbackCase) {
			c.LabelQualityReview.Reviewer = c.PrivacyReview.Reviewer
		},
	}
	for name, mutate := range caseMutations {
		t.Run(name, func(t *testing.T) {
			manifest := base
			manifest.Cases = append([]AIEvaluationFeedbackCase(nil), base.Cases...)
			mutate(&manifest.Cases[0])
			if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{review}, manifest); err == nil {
				t.Fatal("expected curation to fail closed")
			}
		})
	}
}

func TestAIEvaluationFeedbackApprovalBindsManifestHeader(t *testing.T) {
	review := feedbackReview(aitriagereview.StateAccepted)
	base := feedbackManifest(feedbackCase(review, AIEvaluationFalsePositive))
	approveFeedbackCase(t, review, &base, 0)

	mutations := map[string]func(*AIEvaluationFeedbackManifest){
		"dataset version": func(m *AIEvaluationFeedbackManifest) { m.DatasetVersion = "forged-version" },
		"provenance":      func(m *AIEvaluationFeedbackManifest) { m.Provenance = "forged provenance after approval" },
		"curator":         func(m *AIEvaluationFeedbackManifest) { m.Curator = "forged-curator" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			manifest := base
			mutate(&manifest)
			if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{review}, manifest); err == nil {
				t.Fatal("manifest header changed after approval without invalidating digest")
			}
		})
	}
}

func TestAIEvaluationFeedbackApprovalBindsCompleteReviewSnapshot(t *testing.T) {
	review := feedbackReview(aitriagereview.StateAccepted)
	base := feedbackManifest(feedbackCase(review, AIEvaluationFalsePositive))
	approveFeedbackCase(t, review, &base, 0)

	mutations := map[string]func(*aitriagereview.Review){
		"tenant":         func(r *aitriagereview.Review) { r.TenantID = "different-tenant" },
		"engagement":     func(r *aitriagereview.Review) { r.EngagementID = "different-engagement" },
		"dedup key":      func(r *aitriagereview.Review) { r.DedupKey = "sast:forged" },
		"policy version": func(r *aitriagereview.Review) { r.PolicyVersion = "fp-gate-forged" },
		"proposer model": func(r *aitriagereview.Review) { r.ProposerModel = "forged-model" },
		"verifier model": func(r *aitriagereview.Review) { r.VerifierModel = "forged-verifier" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := review
			mutate(&tampered)
			if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{tampered}, base); err == nil {
				t.Fatal("review snapshot changed after approval without invalidating digest")
			}
		})
	}
}

func TestAIEvaluationFeedbackLabelMustFollowHumanOutcome(t *testing.T) {
	accepted := feedbackReview(aitriagereview.StateAccepted)
	acceptedCase := feedbackCase(accepted, AIEvaluationTruePositive)
	if _, err := AIEvaluationFeedbackReviewDigest(accepted, feedbackManifest(acceptedCase), acceptedCase); err == nil {
		t.Fatal("accepted false-positive recommendation must not become a true-positive label")
	}
	rejected := feedbackReview(aitriagereview.StateRejected)
	rejectedCase := feedbackCase(rejected, AIEvaluationFalsePositive)
	if _, err := AIEvaluationFeedbackReviewDigest(rejected, feedbackManifest(rejectedCase), rejectedCase); err == nil {
		t.Fatal("rejected false-positive recommendation must not become a false-positive label")
	}
	uncertainCase := feedbackCase(rejected, AIEvaluationUncertain)
	if _, err := AIEvaluationFeedbackReviewDigest(rejected, feedbackManifest(uncertainCase), uncertainCase); err != nil {
		t.Fatalf("label audit must be able to conservatively downgrade to uncertain: %v", err)
	}
}

func TestAIEvaluationFeedbackRejectsPendingUnsealedOrImpossibleReviews(t *testing.T) {
	tests := map[string]aitriagereview.Review{}
	pending := feedbackReview(aitriagereview.StatePending)
	tests["pending"] = pending
	unsealed := feedbackReview(aitriagereview.StateAccepted)
	unsealed.EvidenceRef = ""
	tests["unsealed"] = unsealed
	ownerless := feedbackReview(aitriagereview.StateAccepted)
	ownerless.Owner = ""
	tests["ownerless"] = ownerless
	wrongOwner := feedbackReview(aitriagereview.StateAccepted)
	wrongOwner.Owner = "somebody-else"
	tests["owner mismatch"] = wrongOwner
	badVersion := feedbackReview(aitriagereview.StateAccepted)
	badVersion.Version = 2
	tests["pre-decision version"] = badVersion
	badTimestamp := feedbackReview(aitriagereview.StateAccepted)
	badTimestamp.UpdatedAt = badTimestamp.UpdatedAt.Add(time.Second)
	tests["decision timestamp mismatch"] = badTimestamp
	missingTenant := feedbackReview(aitriagereview.StateAccepted)
	missingTenant.TenantID = ""
	tests["missing tenant"] = missingTenant

	for name, review := range tests {
		t.Run(name, func(t *testing.T) {
			c := feedbackCase(review, AIEvaluationUncertain)
			if _, err := AIEvaluationFeedbackReviewDigest(review, feedbackManifest(c), c); err == nil {
				t.Fatal("invalid review entered feedback curation")
			}
		})
	}
}

func TestAIEvaluationFeedbackRejectsMachineApproversAndDecisionActors(t *testing.T) {
	review := feedbackReview(aitriagereview.StateAccepted)
	base := feedbackManifest(feedbackCase(review, AIEvaluationFalsePositive))
	approveFeedbackCase(t, review, &base, 0)

	machineActors := []string{
		"agent:runner", "llm:model-a", "mcp:bot", "system:curator",
		"machine:worker", "bot:triage", "service:reviewer", "  SYSTEM:CURATOR  ",
	}
	for _, actor := range machineActors {
		t.Run("privacy_"+strings.TrimSpace(actor), func(t *testing.T) {
			manifest := base
			manifest.Cases = append([]AIEvaluationFeedbackCase(nil), base.Cases...)
			manifest.Cases[0].PrivacyReview.Reviewer = actor
			if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{review}, manifest); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("machine privacy reviewer %q must fail validation, got %v", actor, err)
			}
		})
		t.Run("label_"+strings.TrimSpace(actor), func(t *testing.T) {
			manifest := base
			manifest.Cases = append([]AIEvaluationFeedbackCase(nil), base.Cases...)
			manifest.Cases[0].LabelQualityReview.Reviewer = actor
			if _, err := CurateAIEvaluationFeedback([]aitriagereview.Review{review}, manifest); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("machine label-quality reviewer %q must fail validation, got %v", actor, err)
			}
		})
	}

	for _, actor := range append(machineActors, "model-a", "MODEL-B") {
		t.Run("decider_"+strings.TrimSpace(actor), func(t *testing.T) {
			forged := review
			forged.DecidedBy = actor
			forged.Owner = actor
			c := feedbackCase(forged, AIEvaluationFalsePositive)
			if _, err := AIEvaluationFeedbackReviewDigest(forged, feedbackManifest(c), c); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("machine/model decision actor %q must fail validation, got %v", actor, err)
			}
		})
	}
}

func TestAIEvaluationFeedbackErrorsUseDomainTaxonomyWithoutLeakingReviewIDs(t *testing.T) {
	review := feedbackReview(aitriagereview.StateAccepted)
	missing := feedbackCase(review, AIEvaluationFalsePositive)
	missing.ReviewID = "review-super-secret-missing"
	_, err := AIEvaluationFeedbackReviewDigests([]aitriagereview.Review{review}, feedbackManifest(missing))
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown review must be classified not-found, got %v", err)
	}
	if strings.Contains(err.Error(), missing.ReviewID.String()) || strings.Contains(err.Error(), review.ID.String()) {
		t.Fatalf("lookup error leaked raw review id: %v", err)
	}

	_, err = AIEvaluationFeedbackReviewDigests([]aitriagereview.Review{review, review}, feedbackManifest(feedbackCase(review, AIEvaluationFalsePositive)))
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("duplicate review export must be classified validation, got %v", err)
	}
	if strings.Contains(err.Error(), review.ID.String()) {
		t.Fatalf("duplicate-id validation error leaked raw review id: %v", err)
	}
}
