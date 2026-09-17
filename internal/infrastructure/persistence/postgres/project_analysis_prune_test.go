package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestProjectAnalysisStorePruneBranchAnalyses(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	tenantID := shared.ID("tenant-prune-" + uuid.NewString())
	projectID := shared.ID("project-prune-" + uuid.NewString())
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'prune-test')`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding) VALUES ($1,$2,'prune-test',$3,'{}'::jsonb)`, projectID.String(), tenantID.String(), "prune-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM project_analyses WHERE project_id=$1`, projectID.String())
		_, _ = pool.Exec(bg, `DELETE FROM projects WHERE id=$1`, projectID.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
	})

	store := NewProjectAnalysisStore(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	save := func(id, branch string, at time.Time) {
		a := projectanalysis.Analysis{ID: id, TenantID: tenantID.String(), ProjectID: projectID.String(), ProjectKey: "prune-test", CreatedAt: at, SourceRef: branch}
		if err := store.Save(ctx, a); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	featIDs := []string{"pf1-" + uuid.NewString(), "pf2-" + uuid.NewString(), "pf3-" + uuid.NewString(), "pf4-" + uuid.NewString()}
	for i, id := range featIDs {
		save(id, "feature/x", now.Add(time.Duration(i)*time.Minute))
	}
	mainIDs := []string{"pm1-" + uuid.NewString(), "pm2-" + uuid.NewString()}
	for i, id := range mainIDs {
		save(id, "main", now.Add(time.Duration(i)*time.Minute))
	}

	deleted, err := store.PruneBranchAnalyses(ctx, tenantID, projectID, "feature/x", 2)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2 (kept the newest 2 of 4)", deleted)
	}
	feat, _, err := store.List(ctx, tenantID, projectID, "feature/x", 10, time.Time{}, "")
	if err != nil || len(feat) != 2 || feat[0].ID != featIDs[3] || feat[1].ID != featIDs[2] {
		t.Fatalf("kept feature analyses = %+v err=%v, want the newest two", feat, err)
	}
	main, _, err := store.List(ctx, tenantID, projectID, "main", 10, time.Time{}, "")
	if err != nil || len(main) != 2 {
		t.Fatalf("main analyses = %d, prune must not touch another branch", len(main))
	}
	// keep < 1 is a no-op.
	if n, err := store.PruneBranchAnalyses(ctx, tenantID, projectID, "feature/x", 0); err != nil || n != 0 {
		t.Fatalf("keep=0 deleted=%d err=%v, want 0", n, err)
	}
}

func TestProjectAnalysisStorePruneTieBreakAndCrossTenant(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	tenantA := shared.ID("tenant-a-" + uuid.NewString())
	tenantB := shared.ID("tenant-b-" + uuid.NewString())
	projectA := shared.ID("project-a-" + uuid.NewString())
	projectB := shared.ID("project-b-" + uuid.NewString())
	for _, seed := range []struct {
		tenant, project shared.ID
	}{{tenantA, projectA}, {tenantB, projectB}} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,'prune-tie')`, seed.tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding) VALUES ($1,$2,'prune-tie',$3,'{}'::jsonb)`, seed.project.String(), seed.tenant.String(), "tie-"+uuid.NewString()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, id := range []shared.ID{projectA, projectB} {
			_, _ = pool.Exec(bg, `DELETE FROM project_analyses WHERE project_id=$1`, id.String())
			_, _ = pool.Exec(bg, `DELETE FROM projects WHERE id=$1`, id.String())
		}
		for _, id := range []shared.ID{tenantA, tenantB} {
			_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, id.String())
		}
	})

	store := NewProjectAnalysisStore(pool)
	at := time.Now().UTC().Truncate(time.Microsecond)
	// Three tenant-A feature analyses sharing one created_at: the id COLLATE "C" order decides.
	aIDs := []string{"aaa-tie", "bbb-tie", "ccc-tie"}
	for _, id := range aIDs {
		if err := store.Save(ctx, projectanalysis.Analysis{ID: id, TenantID: tenantA.String(), ProjectID: projectA.String(), ProjectKey: "a", CreatedAt: at, SourceRef: "feature/x"}); err != nil {
			t.Fatal(err)
		}
	}
	// Tenant-B has its own feature/x analyses that must be untouched by a tenant-A prune.
	for _, id := range []string{"b1-" + uuid.NewString(), "b2-" + uuid.NewString()} {
		if err := store.Save(ctx, projectanalysis.Analysis{ID: id, TenantID: tenantB.String(), ProjectID: projectB.String(), ProjectKey: "b", CreatedAt: at, SourceRef: "feature/x"}); err != nil {
			t.Fatal(err)
		}
	}

	deleted, err := store.PruneBranchAnalyses(ctx, tenantA, projectA, "feature/x", 1)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	// On an equal created_at, id COLLATE "C" DESC keeps the lexically greatest id ("ccc-tie").
	kept, _, err := store.List(ctx, tenantA, projectA, "feature/x", 10, time.Time{}, "")
	if err != nil || len(kept) != 1 || kept[0].ID != "ccc-tie" {
		t.Fatalf("kept = %+v, want only ccc-tie (matching List's tie-break)", kept)
	}
	// Tenant B untouched.
	bList, _, err := store.List(ctx, tenantB, projectB, "feature/x", 10, time.Time{}, "")
	if err != nil || len(bList) != 2 {
		t.Fatalf("tenant B analyses = %d, want 2 (a prune must not cross tenants)", len(bList))
	}
}
