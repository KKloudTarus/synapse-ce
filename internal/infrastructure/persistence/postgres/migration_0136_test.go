package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestMigration0136ProjectAnalysesBranch asserts the branch column is populated from each analysis's
// branch on write and that branch-scoped reads (List filter, Branches) key on it.
func TestMigration0136ProjectAnalysesBranch(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	suffix := randHex(t)
	tenant := shared.ID("t-0136-" + suffix)
	projectID := shared.ID("p-0136-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM project_analyses WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	repo := NewProjectRepository(pool)
	p, err := project.New(projectID, tenant, "Multi Branch", "mb-0136-"+suffix, project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/repo.git"}, nil, "", now)
	if err != nil {
		t.Fatalf("build project: %v", err)
	}
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("create project: %v", err)
	}

	store := NewProjectAnalysisStore(pool)
	mainAnalysis := projectanalysis.Analysis{ID: "a-main-" + suffix, TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: now, SourceRef: "main"}
	featAnalysis := projectanalysis.Analysis{ID: "a-feat-" + suffix, TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: now.Add(time.Second), SourceRef: "feature/x"}
	if err := store.SaveWithResult(ctx, mainAnalysis, []byte(`{"r":"main"}`)); err != nil {
		t.Fatalf("save main analysis: %v", err)
	}
	if err := store.SaveWithResult(ctx, featAnalysis, []byte(`{"r":"feat"}`)); err != nil {
		t.Fatalf("save feature analysis: %v", err)
	}

	// The new branch column is populated from analysis.Branch() at write time.
	branches := map[string]string{}
	rows, err := pool.Query(ctx, `SELECT id, branch FROM project_analyses WHERE tenant_id=$1 AND project_id=$2`, tenant.String(), projectID.String())
	if err != nil {
		t.Fatalf("read branch column: %v", err)
	}
	for rows.Next() {
		var id, branch string
		if err := rows.Scan(&id, &branch); err != nil {
			rows.Close()
			t.Fatalf("scan branch: %v", err)
		}
		branches[id] = branch
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate branches: %v", err)
	}
	if branches[mainAnalysis.ID] != "main" || branches[featAnalysis.ID] != "feature/x" {
		t.Fatalf("branch column not populated: %+v", branches)
	}

	// A branch-filtered List returns only the matching branch.
	listed, _, err := store.List(ctx, tenant, projectID, "feature/x", 10, time.Time{}, "")
	if err != nil {
		t.Fatalf("list feature branch: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != featAnalysis.ID {
		t.Fatalf("branch-filtered list = %+v, want only %s", listed, featAnalysis.ID)
	}

	// LatestWithResult honors the branch filter.
	latest, result, err := store.LatestWithResult(ctx, tenant, projectID, "main")
	if err != nil || latest.ID != mainAnalysis.ID || string(result) != `{"r":"main"}` {
		t.Fatalf("latest for main = %+v result=%q err=%v", latest, result, err)
	}

	// Branches returns the distinct set, sorted.
	got, err := store.Branches(ctx, tenant, projectID)
	if err != nil {
		t.Fatalf("branches: %v", err)
	}
	if len(got) != 2 || got[0] != "feature/x" || got[1] != "main" {
		t.Fatalf("branches = %v, want [feature/x main]", got)
	}
}
