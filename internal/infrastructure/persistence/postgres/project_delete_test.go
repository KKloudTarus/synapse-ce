package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Twelve foreign keys reference projects. Eight cascade, and the four that do not decide whether a
// delete succeeds. Linking a project to a business asset is an ordinary console action, and its
// ON DELETE RESTRICT made DELETE /api/v1/projects/{key} answer 500 with "internal error": the
// SQLSTATE 23503 reached the handler as an unclassified error. These tests pin both halves of the
// rule: the link is the project's own side of a relationship and goes with it, while a record that
// merely references the project refuses the delete and says why.
func TestProjectDeleteWithDependents(t *testing.T) {
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
	defer pool.Close()

	tenant := shared.ID("project-delete-tenant")
	// Ordered by dependency so a run that ends mid-way leaves nothing for the next one: an engagement
	// keeps ownership rows alive, and those keep the engagement alive.
	reset := func() {
		for _, stmt := range []string{
			`DELETE FROM business_asset_projects WHERE tenant_id=$1`,
			`DELETE FROM ownership_dirty_scopes WHERE tenant_id=$1`,
			`DELETE FROM engagements WHERE tenant_id=$1`,
			`DELETE FROM projects WHERE tenant_id=$1`,
			`DELETE FROM fleet_business_services WHERE tenant_id=$1`,
			`DELETE FROM tenants WHERE id=$1`,
		} {
			_, _ = pool.Exec(context.Background(), stmt, tenant.String())
		}
	}
	reset()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reset)
	tenantCtx := shared.WithTenant(ctx, tenant)
	repo := NewProjectRepository(pool)
	now := time.Now().UTC()

	newProject := func(t *testing.T, id, key string) *project.Project {
		t.Helper()
		p, err := project.New(shared.ID(id), tenant, key, key,
			project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/repo.git", Ref: "main"},
			map[string]string{}, "gate", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(tenantCtx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("a business asset link goes with the project and the asset survives", func(t *testing.T) {
		p := newProject(t, "project-delete-linked", "project-delete-linked")
		const assetID = "project-delete-asset"
		if _, err := pool.Exec(ctx, `INSERT INTO fleet_business_services
			(id, tenant_id, name, owner, created_at, updated_at, key, description, asset_type, criticality, lifecycle, metadata, version, created_by, updated_by)
			VALUES ($1,$2,'Payments','team-pay',now(),now(),'payments','','application','high','active','{}'::jsonb,1,'operator','operator')`,
			assetID, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO business_asset_projects (tenant_id, business_asset_id, project_id, role, provenance, created_at)
			VALUES ($1,$2,$3,'primary','manual',now())`, tenant.String(), assetID, p.ID.String()); err != nil {
			t.Fatal(err)
		}

		if err := repo.DeleteByKey(tenantCtx, tenant, p.Key); err != nil {
			t.Fatalf("delete a project linked to a business asset: %v", err)
		}

		var links int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM business_asset_projects WHERE tenant_id=$1 AND project_id=$2`,
			tenant.String(), p.ID.String()).Scan(&links); err != nil {
			t.Fatal(err)
		}
		if links != 0 {
			t.Errorf("asset links after delete = %d, want 0", links)
		}
		var assets int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM fleet_business_services WHERE tenant_id=$1 AND id=$2`,
			tenant.String(), assetID).Scan(&assets); err != nil {
			t.Fatal(err)
		}
		if assets != 1 {
			t.Errorf("the business asset itself was removed by a project delete: count=%d, want 1", assets)
		}
	})

	t.Run("an assessment engagement refuses the delete and says why", func(t *testing.T) {
		p := newProject(t, "project-delete-assessed", "project-delete-assessed")
		eng, err := engagement.New("project-delete-engagement", tenant, "eng", "client", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := NewEngagementRepository(pool).Create(tenantCtx, eng); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE engagements SET assessment_project_id=$1 WHERE id=$2`, p.ID.String(), eng.ID.String()); err != nil {
			t.Fatal(err)
		}

		err = repo.DeleteByKey(tenantCtx, tenant, p.Key)
		if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("delete=%v, want a conflict the handler can report as 409", err)
		}
		if !strings.Contains(err.Error(), "assessment engagement") {
			t.Errorf("the refusal does not name what blocks it: %v", err)
		}
		if strings.Contains(err.Error(), "SQLSTATE") {
			t.Errorf("the refusal leaks the driver error to the operator: %v", err)
		}
		// The remedy the message names: re-scope the engagement, then the delete goes through.
		if _, err := pool.Exec(ctx, `UPDATE engagements SET assessment_project_id=NULL WHERE id=$1`, eng.ID.String()); err != nil {
			t.Fatal(err)
		}
		if err := repo.DeleteByKey(tenantCtx, tenant, p.Key); err != nil {
			t.Fatalf("delete after the engagement stops naming the project: %v", err)
		}
	})
}
