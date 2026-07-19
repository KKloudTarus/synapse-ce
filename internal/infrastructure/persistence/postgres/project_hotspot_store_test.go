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
	tenantID := shared.ID("hotspot-test-tenant")
	projectID := shared.ID("hotspot-test-project")
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
	got, err := store.GetHotspot(ctx, tenantID, projectID, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != hotspot.StatusSafe || got.Version != 7 || got.FirstSeenAnalysisID != "hotspot-analysis-1" || got.LastSeenAnalysisID != "hotspot-analysis-2" || got.Title != "updated" {
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
