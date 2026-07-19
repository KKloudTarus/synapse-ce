package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func issueCand(key string, t rule.Type, lang string) issue.Candidate {
	return issue.Candidate{
		Key: key, FindingIdentity: key, RuleKey: "r-" + key, Type: t,
		Title: key, Severity: shared.SeverityMedium, Language: lang, File: key + ".go", Location: key + ".go:1",
	}
}

func saveIssues(t *testing.T, s *ProjectAnalysisStore, id string, at time.Time, cands ...issue.Candidate) {
	t.Helper()
	a := projectanalysis.Analysis{ID: id, TenantID: "t1", ProjectID: "p1", CreatedAt: at}
	if err := s.SaveWithResultAndProjections(context.Background(), a, nil, nil, cands); err != nil {
		t.Fatalf("SaveWithResultAndProjections: %v", err)
	}
}

func TestProjectIssueStoreProjectListFacets(t *testing.T) {
	s := NewProjectAnalysisStore()
	now := time.Now()
	saveIssues(t, s, "a1", now, issueCand("bug1", rule.TypeBug, "Go"), issueCand("smell1", rule.TypeCodeSmell, "Go"))

	page, err := s.ListIssues(context.Background(), "t1", "p1", issue.ListFilter{})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("want 2 issues, got %d", len(page.Items))
	}
	if page.Summary.Total != 2 || page.Summary.Open != 2 || page.Summary.Resolved != 0 {
		t.Fatalf("unexpected summary: %+v", page.Summary)
	}
	if page.Facets.Types[string(rule.TypeBug)] != 1 || page.Facets.Types[string(rule.TypeCodeSmell)] != 1 {
		t.Fatalf("unexpected type facets: %+v", page.Facets.Types)
	}
	// Every projection from the first analysis is New Code.
	for _, it := range page.Items {
		if !it.IsNew {
			t.Fatalf("first-analysis issue should be new code: %s", it.Key)
		}
	}
}

func TestProjectIssueStoreTypeAndNewCodeFilters(t *testing.T) {
	s := NewProjectAnalysisStore()
	now := time.Now()
	saveIssues(t, s, "a1", now, issueCand("bug1", rule.TypeBug, "Go"), issueCand("smell1", rule.TypeCodeSmell, "Java"))
	// A later analysis re-observes bug1 only -> bug1 is no longer new; smell1 stays.
	saveIssues(t, s, "a2", now.Add(time.Hour), issueCand("bug1", rule.TypeBug, "Go"))

	bug := rule.TypeBug
	page, _ := s.ListIssues(context.Background(), "t1", "p1", issue.ListFilter{Type: &bug})
	if len(page.Items) != 1 || page.Items[0].Key != "bug1" {
		t.Fatalf("type filter should return only bug1, got %+v", page.Items)
	}
	if page.Items[0].IsNew {
		t.Fatal("bug1 seen in two analyses should not be new code")
	}
	newPage, _ := s.ListIssues(context.Background(), "t1", "p1", issue.ListFilter{NewCodeOnly: true})
	if len(newPage.Items) != 1 || newPage.Items[0].Key != "smell1" {
		t.Fatalf("new-code filter should return only smell1, got %+v", newPage.Items)
	}
}

func TestProjectIssueStoreTransitionAndResolvedKeys(t *testing.T) {
	s := NewProjectAnalysisStore()
	now := time.Now()
	saveIssues(t, s, "a1", now, issueCand("bug1", rule.TypeBug, "Go"))
	got, _ := s.ListIssues(context.Background(), "t1", "p1", issue.ListFilter{})
	id := got.Items[0].ID

	updated, event, err := s.TransitionIssue(context.Background(), issue.TransitionCommand{
		TenantID: "t1", ProjectID: "p1", IssueID: id, EventID: "ev1",
		To: issue.StatusFalsePositive, Actor: "alice", Rationale: "not exploitable in this context", ExpectedVersion: 1,
	})
	if err != nil {
		t.Fatalf("TransitionIssue: %v", err)
	}
	if updated.Status != issue.StatusFalsePositive || event.Version != 2 {
		t.Fatalf("unexpected transition result: %+v / %+v", updated, event)
	}
	resolved, _ := s.ResolvedIssueKeys(context.Background(), "t1", "p1")
	if !resolved["bug1"] {
		t.Fatalf("resolved issue key should be gate-exempt, got %+v", resolved)
	}
	hist, _ := s.IssueHistory(context.Background(), "t1", "p1", id)
	if len(hist) != 1 || hist[0].To != issue.StatusFalsePositive {
		t.Fatalf("unexpected history: %+v", hist)
	}
}

func TestProjectIssueStoreTenantIsolation(t *testing.T) {
	s := NewProjectAnalysisStore()
	saveIssues(t, s, "a1", time.Now(), issueCand("bug1", rule.TypeBug, "Go"))
	page, err := s.ListIssues(context.Background(), "other-tenant", "p1", issue.ListFilter{})
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("cross-tenant list must be empty, got %d", len(page.Items))
	}
	if _, err := s.GetIssue(context.Background(), "other-tenant", "p1", issue.DeterministicID("t1", "p1", "bug1")); err != shared.ErrNotFound {
		t.Fatalf("cross-tenant get must be not-found, got %v", err)
	}
}
