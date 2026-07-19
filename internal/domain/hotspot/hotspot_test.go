package hotspot_test

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProject(t *testing.T) {
	tenantID := shared.ID("t1")
	projectID := shared.ID("p1")
	analysisID := "a1"
	createdAt := time.Now()
	candidate := hotspot.Candidate{
		Key:             "k1",
		FindingIdentity: "f1",
		RuleKey:         "r1",
		Title:           "t1",
		Description:     "d1",
		Severity:        shared.SeverityHigh,
		Kind:            finding.KindSAST,
		CWE:             "cwe-1",
		Location:        "loc-1",
	}

	t.Run("valid", func(t *testing.T) {
		h, err := hotspot.Project(tenantID, projectID, analysisID, createdAt, candidate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedID := hotspot.DeterministicID(tenantID, projectID, candidate.Key)
		if h.ID != expectedID {
			t.Fatalf("expected ID %s, got %s", expectedID, h.ID)
		}
		if h.Status != hotspot.StatusToReview {
			t.Fatalf("expected status to_review, got %s", h.Status)
		}
		if h.Version != 1 {
			t.Fatalf("expected version 1, got %d", h.Version)
		}
		if h.FirstSeenAnalysisID != analysisID || h.LastSeenAnalysisID != analysisID {
			t.Fatalf("expected seen analysis id %s", analysisID)
		}
	})

	t.Run("empty project id", func(t *testing.T) {
		_, err := hotspot.Project(tenantID, "", analysisID, createdAt, candidate)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("empty analysis id", func(t *testing.T) {
		_, err := hotspot.Project(tenantID, projectID, "", createdAt, candidate)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("zero timestamp", func(t *testing.T) {
		_, err := hotspot.Project(tenantID, projectID, analysisID, time.Time{}, candidate)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid candidate", func(t *testing.T) {
		invalid := candidate
		invalid.Key = ""
		_, err := hotspot.Project(tenantID, projectID, analysisID, createdAt, invalid)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
