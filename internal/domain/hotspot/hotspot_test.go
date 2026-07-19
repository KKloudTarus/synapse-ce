package hotspot

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestHotspotValidateAndDeterministicID(t *testing.T) {
	now := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	h := Hotspot{
		ID: "id", TenantID: "tenant", ProjectID: "project", Key: "sast:rule:file:1", FindingIdentity: "sast:rule:file:1",
		RuleKey: "rule", Title: "Title", Description: "Description", Severity: shared.SeverityHigh,
		Kind: finding.KindSAST, Status: StatusToReview, Version: 1, FirstSeenAnalysisID: "a1", LastSeenAnalysisID: "a1",
		FirstSeenAt: now, LastSeenAt: now,
	}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, want := DeterministicID("tenant", "project", h.Key), DeterministicID("tenant", "project", h.Key); got != want || got.IsZero() {
		t.Fatalf("deterministic id=%q want=%q", got, want)
	}
	if DeterministicID("other", "project", h.Key) == DeterministicID("tenant", "project", h.Key) {
		t.Fatal("tenant must be part of deterministic identity")
	}
}

func TestHotspotValidateAllowsDefaultTenant(t *testing.T) {
	now := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	h := Hotspot{
		ID: "id", ProjectID: "project", Key: "sast:rule:file:1", FindingIdentity: "sast:rule:file:1",
		RuleKey: "rule", Severity: shared.SeverityUnknown,
		Status: StatusToReview, Version: 1, FirstSeenAnalysisID: "a1", LastSeenAnalysisID: "a1",
		FirstSeenAt: now, LastSeenAt: now,
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("default tenant should be valid: %v", err)
	}
}

func TestStatusValid(t *testing.T) {
	for _, status := range []Status{StatusToReview, StatusAcknowledged, StatusFixed, StatusSafe} {
		if !status.Valid() {
			t.Errorf("%q should be valid", status)
		}
	}
	if Status("unknown").Valid() {
		t.Fatal("unknown status should be invalid")
	}
}

func TestProject(t *testing.T) {
	tenantID := shared.ID("t1")
	projectID := shared.ID("p1")
	analysisID := "a1"
	createdAt := time.Now()
	candidate := Candidate{
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
		h, err := Project(tenantID, projectID, analysisID, createdAt, candidate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedID := DeterministicID(tenantID, projectID, candidate.Key)
		if h.ID != expectedID {
			t.Fatalf("expected ID %s, got %s", expectedID, h.ID)
		}
		if h.Status != StatusToReview {
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
		_, err := Project(tenantID, "", analysisID, createdAt, candidate)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("empty analysis id", func(t *testing.T) {
		_, err := Project(tenantID, projectID, "", createdAt, candidate)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("zero timestamp", func(t *testing.T) {
		_, err := Project(tenantID, projectID, analysisID, time.Time{}, candidate)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid candidate", func(t *testing.T) {
		invalid := candidate
		invalid.Key = ""
		_, err := Project(tenantID, projectID, analysisID, createdAt, invalid)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
