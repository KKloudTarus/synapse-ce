package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func curateReview() aitriagereview.Review {
	decidedAt := time.Unix(200, 0).UTC()
	return aitriagereview.Review{
		ID: "r1", TenantID: "tenant-a", EngagementID: "e1", FindingID: "f1", EvidenceRef: "ev1",
		DedupKey: "sast:key", Title: "SQL injection", Severity: shared.SeverityMedium, CWE: "CWE-89", Owner: "reviewer-a",
		State: aitriagereview.StateAccepted, Verdict: "refuted", Driver: "sanitizer", Confidence: 91, SuspectedFP: true,
		ProposerModel: "model-a", ProposerProvider: "openai", ProposerModelFamily: "model-a",
		VerifierModel: "model-b", VerifierProvider: "anthropic", VerifierModelFamily: "model-b", IndependencePolicy: "provider",
		PromptVersion: "fp-triage-v3", PolicyVersion: "fp-gate-v5", PolicyReason: "verified_consensus", Verified: true,
		VerifierVerdict: "refuted", VerifierDriver: "sanitizer", VerifierConfidence: 90, ReviewRequired: true,
		DecidedBy: "reviewer-a", DecisionRationale: "reviewed evidence", DecidedAt: &decidedAt,
		CreatedAt: time.Unix(100, 0).UTC(), UpdatedAt: decidedAt, Version: 3,
	}
}

func curateManifest(review aitriagereview.Review) sca.AIEvaluationFeedbackManifest {
	return sca.AIEvaluationFeedbackManifest{
		SchemaVersion:  sca.AIEvaluationFeedbackManifestSchema,
		DatasetVersion: "feedback-v1", Provenance: "approved internal feedback", Curator: "curator-a",
		Cases: []sca.AIEvaluationFeedbackCase{{
			ReviewID: review.ID, Label: sca.AIEvaluationFalsePositive, Language: "go", Framework: "net/http", Kind: finding.KindSAST,
			Title: "Curated SQL injection", File: "curated/example.go", Line: 4, Source: "package curated\n",
		}},
	}
}

func writeFixture(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func approveCurateManifest(t *testing.T, review aitriagereview.Review, manifest *sca.AIEvaluationFeedbackManifest) {
	t.Helper()
	digest, err := sca.AIEvaluationFeedbackReviewDigest(review, *manifest, manifest.Cases[0])
	if err != nil {
		t.Fatal(err)
	}
	at := review.DecidedAt.Add(time.Minute)
	manifest.Cases[0].PrivacyReview = sca.AIEvaluationFeedbackApproval{
		Reviewer: "privacy-a", Approved: true, Rationale: "approved context", ReviewedAt: at, ReviewedSHA256: digest,
	}
	manifest.Cases[0].LabelQualityReview = sca.AIEvaluationFeedbackApproval{
		Reviewer: "label-a", Approved: true, Rationale: "label verified", ReviewedAt: at, ReviewedSHA256: digest,
	}
}

func approvedCurateInputs(t *testing.T, dir string) (aitriagereview.Review, string, string) {
	t.Helper()
	review := curateReview()
	manifest := curateManifest(review)
	approveCurateManifest(t, review, &manifest)
	reviewsPath := filepath.Join(dir, "reviews.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	writeFixture(t, reviewsPath, reviewExport{Reviews: []aitriagereview.Review{review}})
	writeFixture(t, manifestPath, manifest)
	return review, reviewsPath, manifestPath
}

func TestRunPrintsDigestsThenProducesCuratedDataset(t *testing.T) {
	dir := t.TempDir()
	review := curateReview()
	manifest := curateManifest(review)
	reviewsPath := filepath.Join(dir, "reviews.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	outputPath := filepath.Join(dir, "dataset.json")
	writeFixture(t, reviewsPath, reviewExport{Reviews: []aitriagereview.Review{review}})
	writeFixture(t, manifestPath, manifest)

	var digestOut bytes.Buffer
	if err := run(reviewsPath, manifestPath, "", true, &digestOut); err != nil {
		t.Fatal(err)
	}
	var printed struct {
		ReviewDigests []sca.AIEvaluationFeedbackDigest `json:"review_digests"`
	}
	if err := json.Unmarshal(digestOut.Bytes(), &printed); err != nil {
		t.Fatal(err)
	}
	if len(printed.ReviewDigests) != 1 || printed.ReviewDigests[0].Case != 1 || printed.ReviewDigests[0].SHA256 == "" {
		t.Fatalf("unexpected digest output: %s", digestOut.String())
	}
	if strings.Contains(digestOut.String(), review.ID.String()) || strings.Contains(digestOut.String(), review.TenantID.String()) || strings.Contains(digestOut.String(), "review_id") {
		t.Fatalf("digest stdout leaked production review identity: %s", digestOut.String())
	}

	digest := printed.ReviewDigests[0].SHA256
	at := review.DecidedAt.Add(time.Minute)
	manifest.Cases[0].PrivacyReview = sca.AIEvaluationFeedbackApproval{
		Reviewer: "privacy-a", Approved: true, Rationale: "approved context", ReviewedAt: at, ReviewedSHA256: digest,
	}
	manifest.Cases[0].LabelQualityReview = sca.AIEvaluationFeedbackApproval{
		Reviewer: "label-a", Approved: true, Rationale: "label verified", ReviewedAt: at, ReviewedSHA256: digest,
	}
	writeFixture(t, manifestPath, manifest)

	if err := run(reviewsPath, manifestPath, outputPath, false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("curated dataset mode = %o, want 600", got)
		}
	}
	b, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	dataset, err := sca.LoadAIEvaluationDataset(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Cases) != 1 || dataset.Cases[0].Label != sca.AIEvaluationFalsePositive {
		t.Fatalf("unexpected dataset: %+v", dataset)
	}
	if strings.Contains(string(b), review.ID.String()) || strings.Contains(string(b), review.EvidenceRef.String()) {
		t.Fatalf("curated output leaked raw review linkage: %s", b)
	}
}

func TestRunRefusesCuratedDatasetOnStdout(t *testing.T) {
	dir := t.TempDir()
	_, reviewsPath, manifestPath := approvedCurateInputs(t, dir)
	var stdout bytes.Buffer
	if err := run(reviewsPath, manifestPath, "-", false, &stdout); err == nil {
		t.Fatal("curated production-derived source was allowed on stdout")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout received curated dataset bytes: %q", stdout.String())
	}
}

func TestRunCuratedOutputIsCreateOnlyAndDoesNotFollowSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires elevated Windows privileges")
	}
	dir := t.TempDir()
	_, reviewsPath, manifestPath := approvedCurateInputs(t, dir)
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("DO NOT TOUCH"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "dataset.json")
	if err := os.Symlink(victim, outputPath); err != nil {
		t.Fatal(err)
	}
	if err := run(reviewsPath, manifestPath, outputPath, false, &bytes.Buffer{}); err == nil {
		t.Fatal("curated output replaced or followed an existing symlink")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "DO NOT TOUCH" {
		t.Fatalf("output symlink overwrote victim: %q", got)
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("failed publication unexpectedly replaced the output symlink")
	}
}

func TestRunCuratedOutputDoesNotOverwriteExistingFileOrInputs(t *testing.T) {
	dir := t.TempDir()
	_, reviewsPath, manifestPath := approvedCurateInputs(t, dir)
	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("DO NOT REPLACE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(reviewsPath, manifestPath, existing, false, &bytes.Buffer{}); err == nil {
		t.Fatal("curated output replaced an existing file")
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "DO NOT REPLACE" {
		t.Fatalf("existing output was modified: %q", got)
	}

	for _, input := range []string{reviewsPath, manifestPath} {
		before, err := os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		if err := run(reviewsPath, manifestPath, input, false, &bytes.Buffer{}); err == nil {
			t.Fatalf("curated output was allowed to target input %q", input)
		}
		after, err := os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("input %q was modified", input)
		}
	}
}

func TestRunRejectsUnknownManifestFields(t *testing.T) {
	dir := t.TempDir()
	review := curateReview()
	reviewsPath := filepath.Join(dir, "reviews.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	writeFixture(t, reviewsPath, reviewExport{Reviews: []aitriagereview.Review{review}})
	if err := os.WriteFile(manifestPath, []byte(`{"schema_version":"synapse-ai-triage-feedback-curation-v1","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(reviewsPath, manifestPath, "", true, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown curation field was accepted")
	}
}
