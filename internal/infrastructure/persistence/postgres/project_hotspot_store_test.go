package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectHotspotStoreIntegration(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Make reruns safe when a previous process was interrupted before t.Cleanup ran.
	if _, err := pool.Exec(ctx, `ALTER TABLE project_hotspots DROP CONSTRAINT IF EXISTS project_hotspots_test_rollback`); err != nil {
		t.Fatal(err)
	}
	tenantID := shared.ID("hotspot-test-tenant")
	projectID := shared.ID("hotspot-test-project")
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id IN ($1, $2)`, tenantID, "hotspot-rollback-tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id IN ($1, $2)`, tenantID, "hotspot-rollback-tenant"); err != nil {
		t.Fatal(err)
	}
	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenantID)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID) })
	p, err := project.New(projectID, tenantID, "Hotspot Test", "hotspot-test", project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/repo.git"}, nil, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewProjectRepository(pool).Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	store := NewProjectAnalysisStore(pool)
	firstAt := time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC)
	candidate := hotspot.Candidate{Key: "sast:hotspot-rule:main.go:7", FindingIdentity: "sast:hotspot-rule:main.go:7", RuleKey: "hotspot-rule", Title: "first", Description: "description", Severity: shared.SeverityHigh, Kind: finding.KindSAST, Location: "main.go:7"}
	if err := store.SaveWithResultAndHotspots(ctx, projectanalysis.Analysis{ID: "hotspot-analysis-1", TenantID: tenantID.String(), ProjectID: projectID.String(), CreatedAt: firstAt}, []byte(`{"result":1}`), []hotspot.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	id := hotspot.DeterministicID(tenantID, projectID, candidate.Key)
	if _, err := pool.Exec(ctx, `UPDATE project_hotspots SET status='safe', version=7 WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	candidate.Title = "updated"
	secondAt := firstAt.Add(time.Hour)
	if err := store.SaveWithResultAndHotspots(ctx, projectanalysis.Analysis{ID: "hotspot-analysis-2", TenantID: tenantID.String(), ProjectID: projectID.String(), CreatedAt: secondAt}, []byte(`{"result":2}`), []hotspot.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	olderAt := firstAt.Add(-time.Hour)
	if err := store.SaveWithResultAndHotspots(ctx, projectanalysis.Analysis{ID: "hotspot-analysis-0", TenantID: tenantID.String(), ProjectID: projectID.String(), CreatedAt: olderAt}, nil, []hotspot.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetHotspot(ctx, tenantID, projectID, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != hotspot.StatusSafe || got.Version != 7 || got.FirstSeenAnalysisID != "hotspot-analysis-0" || !got.FirstSeenAt.Equal(olderAt) || got.LastSeenAnalysisID != "hotspot-analysis-2" || got.Title != "updated" {
		t.Fatalf("rescan projection=%+v", got)
	}
	page, err := store.ListHotspots(ctx, tenantID, projectID, hotspot.ListFilter{Limit: 1, Search: "updated"})
	if err != nil || len(page.Items) != 1 || page.Facets.Statuses["safe"] != 1 || page.Facets.RuleKeys["hotspot-rule"] != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if _, err := store.GetHotspot(ctx, "other-tenant", projectID, id); err != shared.ErrNotFound {
		t.Fatalf("cross-tenant get=%v, want not found", err)
	}

	rollbackTenant := shared.ID("hotspot-rollback-tenant")
	rollbackProject := shared.ID("hotspot-rollback-project")
	_, _ = pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, rollbackTenant)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, rollbackTenant) })
	rollbackP, err := project.New(rollbackProject, rollbackTenant, "Rollback", "hotspot-rollback", project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/repo.git"}, nil, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewProjectRepository(pool).Create(ctx, rollbackP); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE project_hotspots ADD CONSTRAINT project_hotspots_test_rollback CHECK (tenant_id <> 'hotspot-rollback-tenant')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `ALTER TABLE project_hotspots DROP CONSTRAINT IF EXISTS project_hotspots_test_rollback`)
	})
	err = store.SaveWithResultAndHotspots(ctx, projectanalysis.Analysis{ID: "rollback-analysis", TenantID: rollbackTenant.String(), ProjectID: rollbackProject.String(), CreatedAt: firstAt}, nil, []hotspot.Candidate{candidate})
	if err == nil {
		t.Fatal("forced hotspot insert failure should fail the analysis transaction")
	}
	var analyses int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM project_analyses WHERE id='rollback-analysis'`).Scan(&analyses); err != nil {
		t.Fatal(err)
	}
	if analyses != 0 {
		t.Fatalf("analysis committed despite hotspot failure: count=%d", analyses)
	}
}

func TestProjectHotspot_ReopenAsNewCode(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupProjectHotspotStore(t)
	defer cleanup()
	
	t1 := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	
	// 1. Analysis 1 detects hotspot
	c := hotspot.Candidate{
		Key: "sast:rule-a:main.go:1", FindingIdentity: "reopen-test", RuleKey: "rule-a", Title: "test", Description: "desc",
		Severity: shared.SeverityHigh, Kind: "sast",
	}
	a1 := projectanalysis.Analysis{ID: "a1", TenantID: "t1", ProjectID: "p1", CreatedAt: t1}
	if err := store.SaveWithResultAndHotspots(ctx, a1, nil, []hotspot.Candidate{c}); err != nil {
		t.Fatal(err)
	}
	
	// 2. Human marks it Fixed
	id := hotspot.DeterministicID("t1", "p1", c.Key)
	item, err := store.GetHotspot(ctx, "t1", "p1", id)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.TransitionHotspot(ctx, hotspot.TransitionCommand{
		TenantID:        "t1",
		ProjectID:       "p1",
		HotspotID:       id,
		EventID:         "review-event-fixed",
		To:              hotspot.StatusFixed,
		Actor:           "user1",
		Rationale:       "Marked fixed before reappearance test.",
		ExpectedVersion: item.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	
	// 3. Later analysis detects it again
	a2 := projectanalysis.Analysis{ID: "a2", TenantID: "t1", ProjectID: "p1", CreatedAt: t2}
	if err := store.SaveWithResultAndHotspots(ctx, a2, nil, []hotspot.Candidate{c}); err != nil {
		t.Fatal(err)
	}
	
	// Assertions
	reopened, err := store.GetHotspot(ctx, "t1", "p1", id)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != hotspot.StatusToReview {
		t.Fatalf("expected to_review, got %s", reopened.Status)
	}
	
	history, err := store.HotspotHistory(ctx, "t1", "p1", id)
	if err != nil || len(history) != 2 {
		t.Fatalf("expected 2 history events (1 manual + 1 system), got %d", len(history))
	}
	
	summary, err := store.CurrentAnalysisHotspotSummary(ctx, "t1", "p1", shared.ID(a2.ID), hotspot.LensNewCode)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 {
		t.Fatalf("expected 1 new code hotspot, got %d", summary.Total)
	}
}

func TestProjectHotspotProjectionUpdatesFindingIdentityFromLaterAnalysis(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupProjectHotspotStore(t)
	defer cleanup()

	t0 := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	tenant := shared.ID("t1")
	project := shared.ID("p1")

	// a1
	c1 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "old", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe", Location: "loc",
	}
	a1 := projectanalysis.Analysis{ID: "a1", TenantID: tenant.String(), ProjectID: project.String(), CreatedAt: t1}
	if err := store.SaveWithResultAndHotspots(ctx, a1, nil, []hotspot.Candidate{c1}); err != nil {
		t.Fatal(err)
	}

	// a2 (newer)
	c2 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "new", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe", Location: "loc",
	}
	a2 := projectanalysis.Analysis{ID: "a2", TenantID: tenant.String(), ProjectID: project.String(), CreatedAt: t2}
	if err := store.SaveWithResultAndHotspots(ctx, a2, nil, []hotspot.Candidate{c2}); err != nil {
		t.Fatal(err)
	}

	id := hotspot.DeterministicID(tenant, project, "k1")
	h, err := store.GetHotspot(ctx, tenant, project, id)
	if err != nil {
		t.Fatal(err)
	}
	if h.FindingIdentity != "new" {
		t.Fatalf("expected 'new', got '%s'", h.FindingIdentity)
	}

	// a0 (arrives late, older)
	c0 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "stale", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe", Location: "loc",
	}
	a0 := projectanalysis.Analysis{ID: "a0", TenantID: tenant.String(), ProjectID: project.String(), CreatedAt: t0}
	if err := store.SaveWithResultAndHotspots(ctx, a0, nil, []hotspot.Candidate{c0}); err != nil {
		t.Fatal(err)
	}

	// Still 'new'
	h, err = store.GetHotspot(ctx, tenant, project, id)
	if err != nil {
		t.Fatal(err)
	}
	if h.FindingIdentity != "new" {
		t.Fatalf("expected 'new' after old arrival, got '%s'", h.FindingIdentity)
	}
}
