package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func projectionCandidate(key string, title string) hotspot.Candidate {
	return hotspot.Candidate{
		Key: key, FindingIdentity: key, RuleKey: "rule-" + key, Title: title, Description: "description",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST,
	}
}

func projectionAnalysis(id string, at time.Time) projectanalysis.Analysis {
	return projectanalysis.Analysis{ID: id, TenantID: "tenant-a", ProjectID: "project-a", CreatedAt: at}
}

func TestProjectHotspotProjectionRescanPreservesReviewStateAndFirstSeen(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	firstAt := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	secondAt := firstAt.Add(time.Hour)
	first := projectionCandidate("sast:rule-a:main.go:1", "first")
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a1", firstAt), nil, []hotspot.Candidate{first}); err != nil {
		t.Fatal(err)
	}
	id := hotspot.DeterministicID("tenant-a", "project-a", first.Key)
	item, err := store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	item.Status, item.Version = hotspot.StatusSafe, 7
	store.hotspots[0] = item
	second := projectionCandidate(first.Key, "updated")
	second.Description = "updated description"
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a2", secondAt), nil, []hotspot.Candidate{second}); err != nil {
		t.Fatal(err)
	}
	older := projectionCandidate(first.Key, "older")
	olderAt := firstAt.Add(-time.Hour)
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a0", olderAt), nil, []hotspot.Candidate{older}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != hotspot.StatusSafe || got.Version != 7 {
		t.Fatalf("review state reset: %+v", got)
	}
	if got.FirstSeenAnalysisID != "a0" || !got.FirstSeenAt.Equal(olderAt) || got.LastSeenAnalysisID != "a2" || !got.LastSeenAt.Equal(secondAt) || got.Title != "updated" {
		t.Fatalf("seen metadata/descriptive update: %+v", got)
	}
}

func TestProjectHotspotProjectionIsTenantAndProjectScoped(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	analysis := projectionAnalysis("a1", time.Unix(1, 0))
	if err := store.SaveWithResultAndHotspots(ctx, analysis, nil, []hotspot.Candidate{projectionCandidate("a", "title")}); err != nil {
		t.Fatal(err)
	}
	id := hotspot.DeterministicID("tenant-a", "project-a", "a")
	if _, err := store.GetHotspot(ctx, "tenant-b", "project-a", id); err != shared.ErrNotFound {
		t.Fatalf("cross-tenant get=%v, want not found", err)
	}
	if _, err := store.GetHotspot(ctx, "tenant-a", "project-b", id); err != shared.ErrNotFound {
		t.Fatalf("wrong-project get=%v, want not found", err)
	}
	page, err := store.ListHotspots(ctx, "tenant-b", "project-a", hotspot.ListFilter{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("cross-tenant list=%+v err=%v", page, err)
	}
}

func TestProjectHotspotProjectionPaginationAndFacets(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	base := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	for i, key := range []string{"a", "b", "c"} {
		if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a"+key, base.Add(time.Duration(i)*time.Hour)), nil, []hotspot.Candidate{projectionCandidate(key, key)}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListHotspots(ctx, "tenant-a", "project-a", hotspot.ListFilter{Limit: 2})
	if err != nil || len(page.Items) != 2 || page.Next == nil || page.Facets.RuleKeys["rule-a"] != 1 {
		t.Fatalf("first page=%+v err=%v", page, err)
	}
	next, err := store.ListHotspots(ctx, "tenant-a", "project-a", hotspot.ListFilter{Limit: 2, BeforeLastSeenAt: page.Next.BeforeLastSeenAt, BeforeID: page.Next.BeforeID})
	if err != nil || len(next.Items) != 1 || next.Items[0].Key != "a" {
		t.Fatalf("next page=%+v err=%v", next, err)
	}
}

func TestProjectHotspotProjectionRejectsCandidateAtomically(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	valid := projectionCandidate("valid", "valid")
	invalid := valid
	invalid.Key = ""
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a1", time.Unix(1, 0)), nil, []hotspot.Candidate{valid, invalid}); err == nil {
		t.Fatal("invalid candidate should fail")
	}
	if _, _, err := store.List(ctx, "tenant-a", "project-a", 10, time.Time{}, ""); err != nil {
		t.Fatal(err)
	} else {
		analyses, _, _ := store.List(ctx, "tenant-a", "project-a", 10, time.Time{}, "")
		if len(analyses) != 0 {
			t.Fatalf("analysis committed despite projection validation: %+v", analyses)
		}
	}
	if page, err := store.ListHotspots(ctx, "tenant-a", "project-a", hotspot.ListFilter{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("hotspot committed despite projection validation: %+v err=%v", page, err)
	}
}

func TestProjectHotspot_ReopenAsNewCode(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	
	t1 := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	
	// 1. Analysis 1 detects hotspot
	c := projectionCandidate("sast:rule-a:main.go:1", "reopen-test")
	analysis1 := projectionAnalysis("a1", t1)
	if err := store.SaveWithResultAndHotspots(ctx, analysis1, nil, []hotspot.Candidate{c}); err != nil {
		t.Fatal(err)
	}
	
	// 2. Human marks it Fixed
	id := hotspot.DeterministicID("tenant-a", "project-a", c.Key)
	item, err := store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	item.Status, item.Version = hotspot.StatusFixed, 2
	store.hotspots[0] = item
	
	// 3. Later analysis detects it again
	analysis2 := projectionAnalysis("a2", t2)
	if err := store.SaveWithResultAndHotspots(ctx, analysis2, nil, []hotspot.Candidate{c}); err != nil {
		t.Fatal(err)
	}
	
	// Assertions
	reopened, err := store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != hotspot.StatusToReview {
		t.Fatalf("expected to_review, got %s", reopened.Status)
	}
	
	history, err := store.HotspotHistory(ctx, "tenant-a", "project-a", id)
	if err != nil || len(history) != 1 {
		t.Fatalf("expected 1 system event, got %d", len(history))
	}
	
	summary, err := store.CurrentAnalysisHotspotSummary(ctx, "tenant-a", "project-a", shared.ID(analysis2.ID), hotspot.LensNewCode)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 {
		t.Fatalf("expected 1 new code hotspot, got %d", summary.Total)
	}
}

func TestProjectHotspotProjectionUpdatesFindingIdentityFromLaterAnalysis(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()

	t0 := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	// a1: key stable, finding_identity = old
	c1 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "old", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe-1", Location: "loc",
	}
	a1 := projectionAnalysis("a1", t1)
	if err := store.SaveWithResultAndHotspots(ctx, a1, nil, []hotspot.Candidate{c1}); err != nil {
		t.Fatal(err)
	}

	// a2: newer analysis: same key, finding_identity = new
	c2 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "new", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe-1", Location: "loc",
	}
	a2 := projectionAnalysis("a2", t2)
	if err := store.SaveWithResultAndHotspots(ctx, a2, nil, []hotspot.Candidate{c2}); err != nil {
		t.Fatal(err)
	}

	id := hotspot.DeterministicID("tenant-a", "project-a", "k1")
	h, err := store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	if h.FindingIdentity != "new" {
		t.Fatalf("expected finding identity 'new', got '%s'", h.FindingIdentity)
	}

	// a0: older analysis arrives late: identity = stale
	c0 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "stale", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe-1", Location: "loc",
	}
	a0 := projectionAnalysis("a0", t0)
	if err := store.SaveWithResultAndHotspots(ctx, a0, nil, []hotspot.Candidate{c0}); err != nil {
		t.Fatal(err)
	}

	// identity must remain 'new'
	h, err = store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	if h.FindingIdentity != "new" {
		t.Fatalf("expected finding identity 'new', got '%s'", h.FindingIdentity)
	}
}
