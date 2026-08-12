package sca

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aitriagereview"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	AIEvaluationFeedbackManifestSchema = "synapse-ai-triage-feedback-curation-v1"
	feedbackApprovalDigestSchema       = "synapse-ai-triage-feedback-approval-v1"
	maxFeedbackSourceBytes             = 128 << 10
	maxFeedbackReviewTextRunes         = 2000
)

// AIEvaluationFeedbackApproval is one human approval over the exact review outcome
// and curated evaluation context. ReviewedSHA256 is produced by
// AIEvaluationFeedbackReviewDigest and prevents approval reuse after edits.
type AIEvaluationFeedbackApproval struct {
	Reviewer       string    `json:"reviewer"`
	Approved       bool      `json:"approved"`
	Rationale      string    `json:"rationale"`
	ReviewedAt     time.Time `json:"reviewed_at"`
	ReviewedSHA256 string    `json:"reviewed_sha256"`
}

// AIEvaluationFeedbackCase selects one durable human review outcome and supplies
// only the context explicitly approved for evaluation use. ReviewID never enters
// the resulting dataset; the output case ID is an opaque digest-derived token.
type AIEvaluationFeedbackCase struct {
	ReviewID           shared.ID                    `json:"review_id"`
	Label              AIEvaluationLabel            `json:"label"`
	Language           string                       `json:"language"`
	Framework          string                       `json:"framework"`
	Kind               finding.Kind                 `json:"kind"`
	Title              string                       `json:"title"`
	Description        string                       `json:"description,omitempty"`
	File               string                       `json:"file"`
	Line               int                          `json:"line"`
	Source             string                       `json:"source"`
	Adversarial        bool                         `json:"adversarial,omitempty"`
	PrivacyReview      AIEvaluationFeedbackApproval `json:"privacy_review"`
	LabelQualityReview AIEvaluationFeedbackApproval `json:"label_quality_review"`
}

// AIEvaluationFeedbackManifest is an offline, operator-owned curation manifest.
// It is deliberately separate from runtime triage policy and never changes model,
// prompt, threshold, or gate settings.
type AIEvaluationFeedbackManifest struct {
	SchemaVersion  string                     `json:"schema_version"`
	DatasetVersion string                     `json:"dataset_version"`
	Provenance     string                     `json:"provenance"`
	Curator        string                     `json:"curator"`
	Cases          []AIEvaluationFeedbackCase `json:"cases"`
}

// AIEvaluationFeedbackDigest is safe to print for reviewers: Case maps the digest
// to manifest order while ReviewID is retained only in-process and never serialized.
type AIEvaluationFeedbackDigest struct {
	Case     int       `json:"case"`
	ReviewID shared.ID `json:"-"`
	SHA256   string    `json:"sha256"`
}

// AIEvaluationFeedbackReviewDigests computes the exact digests that privacy and
// label-quality reviewers must approve. It does not require approvals to exist yet.
func AIEvaluationFeedbackReviewDigests(reviews []aitriagereview.Review, manifest AIEvaluationFeedbackManifest) ([]AIEvaluationFeedbackDigest, error) {
	if err := validateFeedbackManifestHeader(manifest); err != nil {
		return nil, err
	}
	byID, err := feedbackReviewIndex(reviews)
	if err != nil {
		return nil, err
	}
	if len(manifest.Cases) == 0 {
		return nil, feedbackValidationf("AI feedback curation manifest has no cases")
	}

	seen := make(map[string]struct{}, len(manifest.Cases))
	out := make([]AIEvaluationFeedbackDigest, 0, len(manifest.Cases))
	for i, c := range manifest.Cases {
		id := strings.TrimSpace(c.ReviewID.String())
		if id == "" {
			return nil, feedbackValidationf("AI feedback curation case %d has no review id", i+1)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, feedbackValidationf("AI feedback curation contains a duplicate review id")
		}
		seen[id] = struct{}{}
		review, ok := byID[id]
		if !ok {
			return nil, feedbackNotFoundf("AI feedback curation references an unknown review")
		}
		digest, err := AIEvaluationFeedbackReviewDigest(review, manifest, c)
		if err != nil {
			return nil, fmt.Errorf("AI feedback curation case %d: %w", i+1, err)
		}
		out = append(out, AIEvaluationFeedbackDigest{Case: i + 1, ReviewID: c.ReviewID, SHA256: digest})
	}
	return out, nil
}

// AIEvaluationFeedbackReviewDigest binds a human review decision to both the exact
// review snapshot and the manifest header under which the curated context will be
// used. Both approval steps must cite this digest.
func AIEvaluationFeedbackReviewDigest(review aitriagereview.Review, manifest AIEvaluationFeedbackManifest, c AIEvaluationFeedbackCase) (string, error) {
	caseDigest, err := feedbackReviewCaseDigest(review, c)
	if err != nil {
		return "", err
	}
	headerDigest, err := feedbackManifestHeaderDigest(manifest)
	if err != nil {
		return "", err
	}
	payload := struct {
		Schema               string `json:"schema"`
		ReviewCaseSHA256     string `json:"review_case_sha256"`
		ManifestHeaderSHA256 string `json:"manifest_header_sha256"`
	}{
		Schema:               feedbackApprovalDigestSchema,
		ReviewCaseSHA256:     caseDigest,
		ManifestHeaderSHA256: headerDigest,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode AI feedback approval digest: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// feedbackReviewCaseDigest is a stable opaque identity for one exact decided review
// plus its curated non-approval fields. The complete JSON review snapshot is hashed
// so future or currently-unused review metadata cannot be silently rebound after an
// approval. Approval objects are intentionally excluded to avoid a circular digest.
func feedbackReviewCaseDigest(review aitriagereview.Review, c AIEvaluationFeedbackCase) (string, error) {
	if err := validateFeedbackReview(review); err != nil {
		return "", err
	}
	if c.ReviewID != review.ID {
		return "", feedbackValidationf("curation review id does not match review snapshot")
	}
	if !feedbackLabelMatchesDecision(review.State, c.Label) {
		return "", feedbackValidationf("curated feedback label contradicts the human review outcome")
	}
	if c.Kind != finding.KindSAST && c.Kind != finding.KindMisconfig {
		return "", feedbackValidationf("curated feedback kind %q is not AI-triage evaluable", c.Kind)
	}
	if strings.TrimSpace(c.Language) == "" || strings.TrimSpace(c.Framework) == "" ||
		strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.File) == "" || c.Line < 1 || strings.TrimSpace(c.Source) == "" {
		return "", feedbackValidationf("curated feedback requires language, framework, title, file, line, and source")
	}
	if len([]byte(c.Source)) > maxFeedbackSourceBytes {
		return "", feedbackValidationf("curated feedback source exceeds %d bytes", maxFeedbackSourceBytes)
	}

	reviewBytes, err := json.Marshal(review)
	if err != nil {
		return "", fmt.Errorf("encode AI feedback review snapshot: %w", err)
	}
	reviewHash := sha256.Sum256(reviewBytes)
	sourceHash := sha256.Sum256([]byte(c.Source))
	payload := struct {
		ReviewSnapshotHash string            `json:"review_snapshot_sha256"`
		Label              AIEvaluationLabel `json:"label"`
		Language           string            `json:"language"`
		Framework          string            `json:"framework"`
		Kind               finding.Kind      `json:"kind"`
		Title              string            `json:"title"`
		Description        string            `json:"description"`
		File               string            `json:"file"`
		Line               int               `json:"line"`
		SourceHash         string            `json:"source_sha256"`
		Adversarial        bool              `json:"adversarial"`
	}{
		ReviewSnapshotHash: hex.EncodeToString(reviewHash[:]),
		Label:              c.Label,
		Language:           strings.TrimSpace(c.Language),
		Framework:          strings.TrimSpace(c.Framework),
		Kind:               c.Kind,
		Title:              strings.TrimSpace(c.Title),
		Description:        strings.TrimSpace(c.Description),
		File:               strings.TrimSpace(c.File),
		Line:               c.Line,
		SourceHash:         hex.EncodeToString(sourceHash[:]),
		Adversarial:        c.Adversarial,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode AI feedback review case digest: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func feedbackManifestHeaderDigest(manifest AIEvaluationFeedbackManifest) (string, error) {
	if err := validateFeedbackManifestHeader(manifest); err != nil {
		return "", err
	}
	header := struct {
		SchemaVersion  string `json:"schema_version"`
		DatasetVersion string `json:"dataset_version"`
		Provenance     string `json:"provenance"`
		Curator        string `json:"curator"`
	}{
		SchemaVersion:  manifest.SchemaVersion,
		DatasetVersion: manifest.DatasetVersion,
		Provenance:     manifest.Provenance,
		Curator:        manifest.Curator,
	}
	b, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encode AI feedback manifest header: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// CurateAIEvaluationFeedback converts only doubly-approved review outcomes into a
// normal evaluation dataset. It has no runtime-policy side effects: callers receive
// data and must explicitly pass that dataset to the existing evaluation command.
func CurateAIEvaluationFeedback(reviews []aitriagereview.Review, manifest AIEvaluationFeedbackManifest) (AIEvaluationDataset, error) {
	digests, err := AIEvaluationFeedbackReviewDigests(reviews, manifest)
	if err != nil {
		return AIEvaluationDataset{}, err
	}
	byID, err := feedbackReviewIndex(reviews)
	if err != nil {
		return AIEvaluationDataset{}, err
	}

	digestByID := make(map[string]string, len(digests))
	for _, d := range digests {
		digestByID[d.ReviewID.String()] = d.SHA256
	}

	cases := make([]AIEvaluationCase, 0, len(manifest.Cases))
	for _, c := range manifest.Cases {
		review := byID[c.ReviewID.String()]
		digest := digestByID[c.ReviewID.String()]
		if err := validateFeedbackApproval("privacy", c.PrivacyReview, digest, review, false); err != nil {
			return AIEvaluationDataset{}, err
		}
		if err := validateFeedbackApproval("label-quality", c.LabelQualityReview, digest, review, true); err != nil {
			return AIEvaluationDataset{}, err
		}
		if strings.EqualFold(strings.TrimSpace(c.PrivacyReview.Reviewer), strings.TrimSpace(c.LabelQualityReview.Reviewer)) {
			return AIEvaluationDataset{}, feedbackValidationf("AI feedback privacy and label-quality reviewers must be distinct")
		}
		caseDigest, err := feedbackReviewCaseDigest(review, c)
		if err != nil {
			return AIEvaluationDataset{}, err
		}
		cases = append(cases, AIEvaluationCase{
			ID: "review-feedback-" + caseDigest[:24], Label: c.Label,
			Language: strings.TrimSpace(c.Language), Framework: strings.TrimSpace(c.Framework),
			Adversarial: c.Adversarial, Kind: c.Kind, Severity: review.Severity, CWE: strings.TrimSpace(review.CWE),
			Title: strings.TrimSpace(c.Title), Description: strings.TrimSpace(c.Description),
			File: strings.TrimSpace(c.File), Line: c.Line, Source: c.Source,
		})
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return AIEvaluationDataset{}, fmt.Errorf("encode AI feedback curation manifest: %w", err)
	}
	manifestHash := sha256.Sum256(manifestBytes)
	dataset := AIEvaluationDataset{
		SchemaVersion: "synapse-ai-triage-dataset-v1",
		Version:       strings.TrimSpace(manifest.DatasetVersion),
		Provenance:    "reviewer-feedback-curation; curated_feedback_sha256=" + hex.EncodeToString(manifestHash[:]),
		Reviewer:      strings.TrimSpace(manifest.Curator),
		Cases:         cases,
	}
	if err := dataset.Validate(); err != nil {
		return AIEvaluationDataset{}, fmt.Errorf("curated AI feedback dataset: %w", err)
	}
	return dataset, nil
}

func validateFeedbackManifestHeader(manifest AIEvaluationFeedbackManifest) error {
	if manifest.SchemaVersion != AIEvaluationFeedbackManifestSchema {
		return feedbackValidationf("AI feedback curation manifest requires schema %q", AIEvaluationFeedbackManifestSchema)
	}
	if strings.TrimSpace(manifest.DatasetVersion) == "" || strings.TrimSpace(manifest.Provenance) == "" || strings.TrimSpace(manifest.Curator) == "" {
		return feedbackValidationf("AI feedback curation manifest requires dataset version, provenance, and curator")
	}
	if len([]rune(strings.TrimSpace(manifest.Provenance))) > maxFeedbackReviewTextRunes {
		return feedbackValidationf("AI feedback provenance exceeds %d characters", maxFeedbackReviewTextRunes)
	}
	return nil
}

func feedbackReviewIndex(reviews []aitriagereview.Review) (map[string]aitriagereview.Review, error) {
	byID := make(map[string]aitriagereview.Review, len(reviews))
	for i, review := range reviews {
		id := strings.TrimSpace(review.ID.String())
		if id == "" {
			return nil, feedbackValidationf("AI feedback review export item %d has no id", i+1)
		}
		if _, duplicate := byID[id]; duplicate {
			return nil, feedbackValidationf("AI feedback review export contains a duplicate review id")
		}
		byID[id] = review
	}
	return byID, nil
}

func validateFeedbackReview(review aitriagereview.Review) error {
	if review.State != aitriagereview.StateAccepted && review.State != aitriagereview.StateRejected {
		return feedbackValidationf("AI feedback review is not a decided accept/reject outcome")
	}
	if review.ID.IsZero() || review.TenantID.IsZero() || review.EngagementID.IsZero() || review.FindingID.IsZero() || review.EvidenceRef.IsZero() || review.DecidedAt == nil ||
		strings.TrimSpace(review.DecidedBy) == "" || strings.TrimSpace(review.DecisionRationale) == "" {
		return feedbackValidationf("AI feedback review lacks decision provenance or sealed evidence reference")
	}
	if aitriagereview.IsMachineOrModelActor(review.DecidedBy, review.ProposerModel, review.VerifierModel) {
		return feedbackValidationf("AI feedback review decision must be attributed to a human reviewer")
	}
	if strings.TrimSpace(review.DedupKey) == "" || strings.TrimSpace(review.Title) == "" || !review.Severity.Valid() {
		return feedbackValidationf("AI feedback review lacks a valid finding snapshot")
	}
	if review.CreatedAt.IsZero() || review.UpdatedAt.IsZero() || review.DecidedAt.IsZero() ||
		review.DecidedAt.Before(review.CreatedAt) || !review.UpdatedAt.Equal(*review.DecidedAt) || review.Version < 3 {
		return feedbackValidationf("AI feedback review has an impossible decision lifecycle")
	}
	if strings.TrimSpace(review.Owner) == "" || !strings.EqualFold(strings.TrimSpace(review.Owner), strings.TrimSpace(review.DecidedBy)) {
		return feedbackValidationf("AI feedback review decision owner does not match deciding reviewer")
	}
	if review.GateExempt || !review.ReviewRequired {
		return feedbackValidationf("AI feedback review is not a policy-held human-review outcome")
	}
	return nil
}

func feedbackLabelMatchesDecision(state aitriagereview.State, label AIEvaluationLabel) bool {
	if label == AIEvaluationUncertain {
		return true
	}
	switch state {
	case aitriagereview.StateAccepted:
		return label == AIEvaluationFalsePositive
	case aitriagereview.StateRejected:
		return label == AIEvaluationTruePositive
	default:
		return false
	}
}

func validateFeedbackApproval(kind string, approval AIEvaluationFeedbackApproval, digest string, review aitriagereview.Review, requireIndependentReviewer bool) error {
	if !approval.Approved {
		return feedbackValidationf("AI feedback %s review is not approved", kind)
	}
	reviewer := strings.TrimSpace(approval.Reviewer)
	rationale := strings.TrimSpace(approval.Rationale)
	if reviewer == "" || approval.ReviewedAt.IsZero() || len([]rune(rationale)) < 3 || len([]rune(rationale)) > maxFeedbackReviewTextRunes {
		return feedbackValidationf("AI feedback %s review requires reviewer, timestamp, and 3..%d character rationale", kind, maxFeedbackReviewTextRunes)
	}
	if aitriagereview.IsMachineOrModelActor(reviewer, review.ProposerModel, review.VerifierModel) {
		return feedbackValidationf("AI feedback %s review must be performed by a human reviewer", kind)
	}
	if review.DecidedAt != nil && approval.ReviewedAt.Before(*review.DecidedAt) {
		return feedbackValidationf("AI feedback %s review predates the human triage decision", kind)
	}
	if requireIndependentReviewer && strings.EqualFold(reviewer, strings.TrimSpace(review.DecidedBy)) {
		return feedbackValidationf("AI feedback label-quality reviewer must differ from the original decision reviewer")
	}
	if approval.ReviewedSHA256 != digest {
		return feedbackValidationf("AI feedback %s approval does not match current review/content digest", kind)
	}
	return nil
}

func feedbackValidationf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", shared.ErrValidation, fmt.Sprintf(format, args...))
}

func feedbackNotFoundf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", shared.ErrNotFound, fmt.Sprintf(format, args...))
}
