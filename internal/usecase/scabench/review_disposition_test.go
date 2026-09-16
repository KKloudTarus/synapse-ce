package scabench

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCommentedGitHubReviewBindsDistinctMaintainerDisposition(t *testing.T) {
	reviewCapture := GitHubReviewCapture{
		SchemaVersion: GitHubReviewCaptureSchemaVersion,
		ID:            "5216540287",
		URL:           "https://github.com/example/repository/pull/1242#pullrequestreview-5216540287",
		Login:         "independent-reviewer",
		State:         "COMMENTED",
		SubmittedAt:   "2026-09-15T22:45:33Z",
		CommitID:      strings.Repeat("a", 40),
		Body:          "Independent review found no blockers and recorded remediation recommendations.",
	}
	dispositionCapture := GitHubReviewDispositionCapture{
		SchemaVersion:        GitHubReviewDispositionCaptureSchemaVersion,
		ID:                   "5689000000",
		URL:                  "https://github.com/example/repository/pull/1242#issuecomment-5689000000",
		Login:                "maintainer",
		CreatedAt:            "2026-09-16T01:00:00Z",
		UpdatedAt:            "2026-09-16T01:00:00Z",
		ReviewID:             reviewCapture.ID,
		ReviewedCommit:       reviewCapture.CommitID,
		ImplementationCommit: strings.Repeat("b", 40),
		Decision:             "approved",
	}
	dispositionCapture.Body = CanonicalReviewDispositionBody(dispositionCapture.Decision, dispositionCapture.ReviewID, dispositionCapture.ReviewedCommit, dispositionCapture.ImplementationCommit)
	reviewBytes, err := json.Marshal(reviewCapture)
	if err != nil {
		t.Fatal(err)
	}
	dispositionBytes, err := json.Marshal(dispositionCapture)
	if err != nil {
		t.Fatal(err)
	}
	review := AccountableReview{
		SchemaVersion:             AccountableReviewSchemaVersion,
		CycleID:                   "review-cycle",
		AdjudicationDigest:        cycleTestDigest('a'),
		FinalOracleDigest:         cycleTestDigest('b'),
		ReviewerIdentity:          "github:" + reviewCapture.Login,
		SubmittedAt:               reviewCapture.SubmittedAt,
		ReviewedCommit:            reviewCapture.CommitID,
		GitHubReviewID:            reviewCapture.ID,
		GitHubReviewURL:           reviewCapture.URL,
		ReviewCapture:             ContentReference{Locator: "reviews/github/review.json", Digest: SHA256Digest(reviewBytes), Size: int64(len(reviewBytes))},
		DecisionAuthorityIdentity: "github:" + dispositionCapture.Login,
		DecisionSubmittedAt:       dispositionCapture.CreatedAt,
		ImplementationCommit:      dispositionCapture.ImplementationCommit,
		GitHubDispositionID:       dispositionCapture.ID,
		GitHubDispositionURL:      dispositionCapture.URL,
		DecisionCapture:           ContentReference{Locator: "reviews/dispositions/github/decision.json", Digest: SHA256Digest(dispositionBytes), Size: int64(len(dispositionBytes))},
		Decision:                  dispositionCapture.Decision,
		DecisionDigest:            SHA256Digest(dispositionBytes),
	}
	if err := review.Validate(); err != nil {
		t.Fatalf("validate accountable review: %v", err)
	}
	if err := reviewCapture.ValidateAgainstAccountableReview(review); err != nil {
		t.Fatalf("bind commented review: %v", err)
	}
	if err := dispositionCapture.ValidateAgainstAccountableReview(review); err != nil {
		t.Fatalf("bind maintainer disposition: %v", err)
	}
}

func TestGitHubReviewDispositionCaptureStrictlySanitizesAndBindsProvenance(t *testing.T) {
	review := testAccountableReview("review-cycle", cycleTestDigest('a'), cycleTestDigest('b'))
	capture := GitHubReviewDispositionCapture{
		SchemaVersion:        GitHubReviewDispositionCaptureSchemaVersion,
		ID:                   review.GitHubDispositionID,
		URL:                  review.GitHubDispositionURL,
		Login:                "maintainer",
		CreatedAt:            review.DecisionSubmittedAt,
		UpdatedAt:            review.DecisionSubmittedAt,
		ReviewID:             review.GitHubReviewID,
		ReviewedCommit:       review.ReviewedCommit,
		ImplementationCommit: review.ImplementationCommit,
		Decision:             review.Decision,
	}
	capture.Body = CanonicalReviewDispositionBody(capture.Decision, capture.ReviewID, capture.ReviewedCommit, capture.ImplementationCommit)
	body, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGitHubReviewDispositionCapture(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("decode sanitized github review disposition: %v", err)
	}
	if err := decoded.ValidateAgainstAccountableReview(review); err != nil {
		t.Fatalf("bind sanitized github review disposition: %v", err)
	}

	edited := capture
	edited.UpdatedAt = "2026-09-15T13:01:00Z"
	mismatchedCommit := capture
	mismatchedCommit.ImplementationCommit = strings.Repeat("c", 40)
	mismatchedCommit.Body = CanonicalReviewDispositionBody(mismatchedCommit.Decision, mismatchedCommit.ReviewID, mismatchedCommit.ReviewedCommit, mismatchedCommit.ImplementationCommit)
	nonCanonical := capture
	nonCanonical.Body += "\n"
	tests := []struct {
		name string
		body []byte
	}{
		{name: "forbidden user field", body: append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"user":"forbidden"}`)...)},
		{name: "edited comment", body: mustJSON(t, edited)},
		{name: "mismatched implementation commit", body: mustJSON(t, mismatchedCommit)},
		{name: "noncanonical body", body: mustJSON(t, nonCanonical)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := DecodeGitHubReviewDispositionCapture(bytes.NewReader(test.body))
			if err == nil {
				err = candidate.ValidateAgainstAccountableReview(review)
			}
			if err == nil {
				t.Fatal("GitHub review disposition accepted sensitive, mutable, or mismatched provenance")
			}
		})
	}
}

func TestApprovedDispositionCannotHideChangesRequestedReview(t *testing.T) {
	review := testAccountableReview("review-cycle", cycleTestDigest('a'), cycleTestDigest('b'))
	capture := GitHubReviewCapture{
		SchemaVersion: GitHubReviewCaptureSchemaVersion,
		ID:            review.GitHubReviewID,
		URL:           review.GitHubReviewURL,
		Login:         "reviewer",
		State:         "CHANGES_REQUESTED",
		SubmittedAt:   review.SubmittedAt,
		CommitID:      review.ReviewedCommit,
		Body:          "Changes are required.",
	}
	if err := capture.ValidateAgainstAccountableReview(review); err == nil {
		t.Fatal("approved disposition accepted a changes-requested review")
	}
}
