package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectIssueStoreIntegration(t *testing.T) {
	ctx := context.Background()
	store := setupProjectHotspotStore(t) // shared setup: migrates + connects, or skips without DSN.
	pool := store.pool

	tenant := shared.ID("issue-test-tenant")
	projectID := shared.ID("issue-test-project")
	seedHotspotProject(t, store, tenant, projectID, "issue-test")

	t1 := time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)

	smell := issue.Candidate{
		Key: "sast:rule-smell:app.go:5", FindingIdentity: "sast:rule-smell:app.go:5", RuleKey: "rule-smell",
		Type: rule.TypeCodeSmell, Title: "smell", Description: "smelly", Severity: shared.SeverityLow, Kind: finding.KindSAST,
		Language: "go", File: "app.go", Location: "app.go:5",
	}
	vuln := issue.Candidate{
		Key: "sca:CVE-1:lib@1.0:", FindingIdentity: "sca:CVE-1:lib@1.0:", RuleKey: "rule-vuln",
		Type: rule.TypeVulnerability, Title: "vuln", Description: "vulnerable", Severity: shared.SeverityHigh, Kind: finding.KindSCA,
		Language: "go", File: "go.mod", Location: "go.mod",
	}

	a1 := projectanalysis.Analysis{ID: "issue-a1", TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: t1}
	if err := store.SaveWithResultAndProjections(ctx, a1, []byte(`{"r":1}`), nil, []issue.Candidate{smell, vuln}); err != nil {
		t.Fatal(err)
	}

	smellID := issue.DeterministicID(tenant, projectID, smell.Key)
	got, err := store.GetIssue(ctx, tenant, projectID, smellID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != issue.StatusOpen || got.Version != 1 || !got.IsNew || got.Type != rule.TypeCodeSmell || got.Language != "go" {
		t.Fatalf("initial projection=%+v", got)
	}

	// Triage the smell to accepted (gate-exempt, sticky across rescans).
	updated, _, err := store.TransitionIssue(ctx, issue.TransitionCommand{
		TenantID: tenant, ProjectID: projectID, IssueID: smellID, EventID: "issue-ev-1",
		To: issue.StatusAccepted, Actor: "reviewer1", Rationale: "Accepted risk for this release.", ExpectedVersion: 1,
	})
	if err != nil || updated.Status != issue.StatusAccepted || updated.Version != 2 {
		t.Fatalf("transition=%+v err=%v", updated, err)
	}

	resolved, err := store.ResolvedIssueKeys(ctx, tenant, projectID)
	if err != nil || !resolved[smell.Key] || resolved[vuln.Key] {
		t.Fatalf("resolved keys=%v err=%v", resolved, err)
	}

	// Rescan (later): triage is sticky, both issues are no longer New Code.
	if err := store.SaveWithResultAndProjections(ctx, projectanalysis.Analysis{ID: "issue-a2", TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: t2}, []byte(`{"r":2}`), nil, []issue.Candidate{smell, vuln}); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetIssue(ctx, tenant, projectID, smellID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != issue.StatusAccepted || got.Version != 2 || got.IsNew {
		t.Fatalf("post-rescan projection=%+v (triage must survive, IsNew must clear)", got)
	}

	// List: facets + summary computed over the whole filtered set.
	page, err := store.ListIssues(ctx, tenant, projectID, issue.ListFilter{Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Summary.Total != 2 || page.Summary.Open != 1 || page.Summary.Resolved != 1 {
		t.Fatalf("list page=%+v summary=%+v", page.Items, page.Summary)
	}
	if page.Facets.Types["code_smell"] != 1 || page.Facets.Types["vulnerability"] != 1 ||
		page.Facets.Statuses["accepted"] != 1 || page.Facets.Statuses["open"] != 1 ||
		page.Facets.Languages["go"] != 2 {
		t.Fatalf("facets=%+v", page.Facets)
	}

	// Type facet filter narrows to one issue.
	vt := rule.TypeVulnerability
	filtered, err := store.ListIssues(ctx, tenant, projectID, issue.ListFilter{Limit: 25, Type: &vt})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].Type != rule.TypeVulnerability {
		t.Fatalf("type-filtered=%+v err=%v", filtered.Items, err)
	}

	// New-code lens hides both (neither is new after the rescan).
	newOnly, err := store.ListIssues(ctx, tenant, projectID, issue.ListFilter{Limit: 25, NewCodeOnly: true})
	if err != nil || len(newOnly.Items) != 0 {
		t.Fatalf("new-code lens=%+v err=%v", newOnly.Items, err)
	}

	history, err := store.IssueHistory(ctx, tenant, projectID, smellID)
	if err != nil || len(history) != 1 || history[0].To != issue.StatusAccepted {
		t.Fatalf("history=%+v err=%v", history, err)
	}

	if _, err := store.GetIssue(ctx, "other-tenant", projectID, smellID); err != shared.ErrNotFound {
		t.Fatalf("cross-tenant get=%v, want not found", err)
	}

	// A projection insert failure rolls the whole analysis back.
	if _, err := pool.Exec(ctx, `ALTER TABLE project_issues ADD CONSTRAINT project_issues_test_rollback CHECK (tenant_id <> 'issue-rollback-tenant')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `ALTER TABLE project_issues DROP CONSTRAINT IF EXISTS project_issues_test_rollback`)
	})
	rbTenant := shared.ID("issue-rollback-tenant")
	rbProject := shared.ID("issue-rollback-project")
	seedHotspotProject(t, store, rbTenant, rbProject, "issue-rollback")
	err = store.SaveWithResultAndProjections(ctx, projectanalysis.Analysis{ID: "issue-rollback-a", TenantID: rbTenant.String(), ProjectID: rbProject.String(), CreatedAt: t1}, nil, nil, []issue.Candidate{smell})
	if err == nil {
		t.Fatal("forced issue insert failure should fail the analysis transaction")
	}
	var analyses int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM project_analyses WHERE id='issue-rollback-a'`).Scan(&analyses); err != nil {
		t.Fatal(err)
	}
	if analyses != 0 {
		t.Fatalf("analysis committed despite issue failure: count=%d", analyses)
	}
}
