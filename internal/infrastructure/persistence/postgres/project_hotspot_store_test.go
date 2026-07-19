package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func setupProjectHotspotStore(t *testing.T) *ProjectAnalysisStore {
	t.Helper()

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

	t.Cleanup(pool.Close)
	return NewProjectAnalysisStore(pool)
}

func seedHotspotProject(
	t *testing.T,
	store *ProjectAnalysisStore,
	tenantID shared.ID,
	projectID shared.ID,
	key string,
) {
	t.Helper()

	ctx := context.Background()
	pool := store.pool

	t.Cleanup(func() {
		if _, err := pool.Exec(
			ctx,
			`DELETE FROM projects WHERE id=$1 AND tenant_id=$2`,
			projectID,
			tenantID,
		); err != nil {
			t.Errorf("cleanup hotspot project: %v", err)
		}

		if _, err := pool.Exec(
			ctx,
			`DELETE FROM tenants WHERE id=$1`,
			tenantID,
		); err != nil {
			t.Errorf("cleanup hotspot tenant: %v", err)
		}
	})

	_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE id=$1 AND tenant_id=$2`, projectID, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)

	if _, err := pool.Exec(
		ctx,
		`INSERT INTO tenants (id, name)
		 VALUES ($1, $1)
		 ON CONFLICT DO NOTHING`,
		tenantID,
	); err != nil {
		t.Fatal(err)
	}

	p, err := project.New(
		projectID,
		tenantID,
		"Hotspot Test",
		key,
		project.SourceBinding{
			Kind:  project.SourceGit,
			Value: "https://example.com/repo.git",
		},
		nil,
		"",
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewProjectRepository(pool).Create(ctx, p); err != nil {
		t.Fatal(err)
	}
}

func TestProjectHotspotStoreIntegration(t *testing.T) {
	store := setupProjectHotspotStore(t)
	ctx := context.Background()
	pool := store.pool
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
	store := setupProjectHotspotStore(t)

	tenant := shared.ID("hotspot-reopen-tenant")
	projectID := shared.ID("hotspot-reopen-project")
	seedHotspotProject(t, store, tenant, projectID, "hotspot-reopen")

	t1 := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)

	// 1. Analysis 1 detects hotspot
	c := hotspot.Candidate{
		Key: "sast:rule-a:main.go:1", FindingIdentity: "reopen-test", RuleKey: "rule-a", Title: "test", Description: "desc",
		Severity: shared.SeverityHigh, Kind: "sast",
	}
	a1 := projectanalysis.Analysis{ID: "hotspot-reopen-a1", TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: t1}
	if err := store.SaveWithResultAndHotspots(ctx, a1, nil, []hotspot.Candidate{c}); err != nil {
		t.Fatal(err)
	}

	// 2. Human marks it Fixed
	id := hotspot.DeterministicID(tenant, projectID, c.Key)
	item, err := store.GetHotspot(ctx, tenant, projectID, id)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.TransitionHotspot(ctx, hotspot.TransitionCommand{
		TenantID:        tenant,
		ProjectID:       projectID,
		HotspotID:       id,
		EventID:         "hotspot-reopen-review-fixed",
		To:              hotspot.StatusFixed,
		Actor:           "user1",
		Rationale:       "Marked fixed before reappearance test.",
		ExpectedVersion: item.Version,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Later analysis detects it again
	a2 := projectanalysis.Analysis{ID: "hotspot-reopen-a2", TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: t2}
	if err := store.SaveWithResultAndHotspots(ctx, a2, nil, []hotspot.Candidate{c}); err != nil {
		t.Fatal(err)
	}

	// Assertions
	reopened, err := store.GetHotspot(ctx, tenant, projectID, id)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != hotspot.StatusToReview {
		t.Fatalf("expected to_review, got %s", reopened.Status)
	}

	history, err := store.HotspotHistory(ctx, tenant, projectID, id)
	if err != nil || len(history) != 2 {
		t.Fatalf("expected 2 history events (1 manual + 1 system), got %d", len(history))
	}

	summary, err := store.CurrentAnalysisHotspotSummary(ctx, tenant, projectID, shared.ID(a2.ID), hotspot.LensNewCode)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 {
		t.Fatalf("expected 1 new code hotspot, got %d", summary.Total)
	}
}

func TestProjectHotspotProjectionUpdatesFindingIdentityFromLaterAnalysis(t *testing.T) {
	ctx := context.Background()
	store := setupProjectHotspotStore(t)

	t0 := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	tenant := shared.ID("hotspot-identity-tenant")
	project := shared.ID("hotspot-identity-project")
	seedHotspotProject(t, store, tenant, project, "hotspot-identity")

	// a1
	c1 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "old", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe", Location: "loc",
	}
	a1 := projectanalysis.Analysis{ID: "hotspot-identity-a1", TenantID: tenant.String(), ProjectID: project.String(), CreatedAt: t1}
	if err := store.SaveWithResultAndHotspots(ctx, a1, nil, []hotspot.Candidate{c1}); err != nil {
		t.Fatal(err)
	}

	// a2 (newer)
	c2 := hotspot.Candidate{
		Key: "k1", FindingIdentity: "new", RuleKey: "r1", Title: "t1", Description: "d1",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST, CWE: "cwe", Location: "loc",
	}
	a2 := projectanalysis.Analysis{ID: "hotspot-identity-a2", TenantID: tenant.String(), ProjectID: project.String(), CreatedAt: t2}
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
	a0 := projectanalysis.Analysis{ID: "hotspot-identity-a0", TenantID: tenant.String(), ProjectID: project.String(), CreatedAt: t0}
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

func TestProjectHotspotPagination(t *testing.T) {
	ctx := context.Background()
	store := setupProjectHotspotStore(t)

	tenant := shared.ID("hotspot-pagination-tenant")
	projectID := shared.ID("hotspot-pagination-project")
	seedHotspotProject(t, store, tenant, projectID, "hotspot-pagination")

	now := time.Now().UTC()
	var candidates []hotspot.Candidate
	for i := 0; i < 3; i++ {
		candidates = append(candidates, hotspot.Candidate{
			Key:             fmt.Sprintf("k%d", i),
			FindingIdentity: fmt.Sprintf("id%d", i),
			RuleKey:         "r1",
			Title:           "title",
			Description:     "desc",
			Severity:        shared.SeverityHigh,
			Kind:            finding.KindSAST,
			Location:        "loc",
		})
	}

	analysis := projectanalysis.Analysis{
		ID:        "hotspot-pagination-a1",
		TenantID:  tenant.String(),
		ProjectID: projectID.String(),
		CreatedAt: now,
	}

	if err := store.SaveWithResultAndHotspots(ctx, analysis, nil, candidates); err != nil {
		t.Fatal(err)
	}

	// Fetch page 1
	page1, summary1, err := store.ListAnalysisHotspots(ctx, tenant, projectID, shared.ID(analysis.ID), hotspot.LensOverall, hotspot.ListFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1.Items) != 2 {
		t.Fatalf("expected 2 items on page 1, got %d", len(page1.Items))
	}
	if summary1.Total != 3 {
		t.Fatalf("expected summary total 3, got %d", summary1.Total)
	}
	if page1.Facets.Statuses["to_review"] != 3 {
		t.Fatalf("expected 3 'to_review' in facets on page 1, got %d", page1.Facets.Statuses["to_review"])
	}
	if page1.Next == nil {
		t.Fatal("expected page 1 to have next cursor")
	}

	// Fetch page 2
	page2, summary2, err := store.ListAnalysisHotspots(ctx, tenant, projectID, shared.ID(analysis.ID), hotspot.LensOverall, hotspot.ListFilter{
		Limit:            2,
		BeforeLastSeenAt: page1.Next.BeforeLastSeenAt,
		BeforeID:         page1.Next.BeforeID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.Items) != 1 {
		t.Fatalf("expected 1 item on page 2, got %d", len(page2.Items))
	}
	if summary2.Total != 3 {
		t.Fatalf("expected summary total 3 on page 2, got %d", summary2.Total)
	}
	if page2.Facets.Statuses["to_review"] != 3 {
		t.Fatalf("expected 3 'to_review' in facets on page 2, got %d", page2.Facets.Statuses["to_review"])
	}
	if page2.Next != nil {
		t.Fatal("expected page 2 to have nil next cursor")
	}

	// Ensure no items from page 1 repeat on page 2
	for _, item1 := range page1.Items {
		for _, item2 := range page2.Items {
			if item1.ID == item2.ID {
				t.Fatalf("item %s repeated on page 2", item1.ID)
			}
		}
	}
}
