package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestTenantRLSIsolation exercises actual PostgreSQL policies. It is opt-in so
// ordinary unit tests do not need a database. Supply a non-superuser runtime
// DSN and a separate migration/admin DSN.
func TestTenantRLSIsolation(t *testing.T) {
	runtimeDSN := os.Getenv("SYNAPSE_TEST_POSTGRES_DSN")
	adminDSN := os.Getenv("SYNAPSE_TEST_POSTGRES_MIGRATE_DSN")
	if runtimeDSN == "" || adminDSN == "" {
		t.Skip("set SYNAPSE_TEST_POSTGRES_DSN and SYNAPSE_TEST_POSTGRES_MIGRATE_DSN to run PostgreSQL RLS integration")
	}
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin, err := Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close()
	runtime, err := Connect(ctx, runtimeDSN)
	if err != nil {
		t.Fatalf("connect runtime: %v", err)
	}
	defer runtime.Close()
	if err := RequireNonSuperuser(ctx, runtime); err != nil {
		t.Fatalf("runtime role: %v", err)
	}

	suffix := fmt.Sprintf("rls-%d", time.Now().UnixNano())
	tenantA, tenantB, projectID := suffix+"-a", suffix+"-b", suffix+"-project"
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, tenant, tenant); err != nil {
			t.Fatalf("insert tenant %q: %v", tenant, err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, `DELETE FROM projects WHERE id=$1`, projectID)
		_, _ = admin.Exec(ctx, `DELETE FROM tenants WHERE id = ANY($1)`, []string{tenantA, tenantB})
	})

	if err := WithTenantTx(ctx, runtime, shared.ID(tenantA), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding, default_profile_by_lang, gate_id, created_at, updated_at, created_by, updated_by) VALUES ($1,$2,'RLS test',$3,'{}','{}','',now(),now(),'test','test')`, projectID, tenantA, suffix)
		return err
	}); err != nil {
		t.Fatalf("insert tenant A project: %v", err)
	}

	var count int
	if err := runtime.QueryRow(ctx, `SELECT count(*) FROM projects WHERE id=$1`, projectID).Scan(&count); err != nil {
		t.Fatalf("query without tenant context: %v", err)
	}
	if count != 0 {
		t.Fatalf("unset tenant context exposed %d rows", count)
	}
	if err := WithTenantTx(ctx, runtime, shared.ID(tenantB), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM projects WHERE id=$1`, projectID).Scan(&count)
	}); err != nil {
		t.Fatalf("query tenant B: %v", err)
	}
	if count != 0 {
		t.Fatalf("tenant B exposed %d tenant A rows", count)
	}
	if err := WithTenantTx(ctx, runtime, shared.ID(tenantA), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM projects WHERE id=$1`, projectID).Scan(&count)
	}); err != nil {
		t.Fatalf("query tenant A: %v", err)
	}
	if count != 1 {
		t.Fatalf("tenant A count = %d, want 1", count)
	}
}
