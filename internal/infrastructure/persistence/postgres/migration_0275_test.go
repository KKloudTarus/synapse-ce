package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
)

// TestMigration0275ScanRunsAreTenantIsolated reproduces the measurement in #1697. Under a role that
// cannot bypass RLS, with tenant A bound, scan_runs returned tenant B's run too: isolation rested on
// every query remembering its predicate. After 0275 the database refuses the read itself.
func TestMigration0275ScanRunsAreTenantIsolated(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	stamp := time.Now().UTC().Format("150405.000000000")
	tenantA, tenantB := "sr-rls-a-"+stamp, "sr-rls-b-"+stamp
	engA, engB := "sr-rls-eng-a-"+stamp, "sr-rls-eng-b-"+stamp
	runA, runB := "sr-rls-run-a-"+stamp, "sr-rls-run-b-"+stamp

	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	for _, seed := range []struct{ tenant, eng, run string }{{tenantA, engA, runA}, {tenantB, engB, runB}} {
		if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ($1,$2,'rls')`, seed.eng, seed.tenant); err != nil {
			t.Fatalf("seed engagement: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO scan_runs (tenant_id, id, engagement_id, created_at, manifest, finding_keys) VALUES ($1,$2,$3,now(),'{}','[]')`, seed.tenant, seed.run, seed.eng); err != nil {
			t.Fatalf("seed scan run: %v", err)
		}
	}

	var forced, enabled bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='scan_runs'`).Scan(&enabled, &forced); err != nil {
		t.Fatalf("read RLS state: %v", err)
	}
	if !enabled || !forced {
		t.Fatalf("scan_runs RLS enabled=%v forced=%v, want both", enabled, forced)
	}

	const role = "scan_runs_rls_probe_role"
	for _, stmt := range []string{
		`DROP OWNED BY ` + role,
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT, INSERT ON scan_runs TO ` + role,
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})

	visible := func(tenant string) []string {
		t.Helper()
		var ids []string
		if err := postgres.WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT id FROM scan_runs WHERE id = ANY($1) ORDER BY id`, []string{runA, runB})
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				ids = append(ids, id)
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("read as %s: %v", tenant, err)
		}
		return ids
	}
	if got := visible(tenantA); len(got) != 1 || got[0] != runA {
		t.Fatalf("tenant A sees %v, want only its own run", got)
	}
	if got := visible(tenantB); len(got) != 1 || got[0] != runB {
		t.Fatalf("tenant B sees %v, want only its own run", got)
	}

	// A write naming another tenant is refused by the policy's WITH CHECK, not by a predicate.
	err := postgres.WithTenant(ctx, pool, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO scan_runs (tenant_id, id, engagement_id, created_at, manifest, finding_keys) VALUES ($1,$2,$3,now(),'{}','[]')`, tenantB, "sr-rls-forged-"+stamp, engB)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("a cross-tenant scan_runs insert was not refused by RLS: %v", err)
	}

	// The composite key itself refuses a run whose tenant disagrees with its engagement's. The 0144 bridge
	// trigger would refuse it first, so the trigger is disabled inside a rolled-back transaction to reach
	// the key, and the refusal must name it.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `ALTER TABLE scan_runs DISABLE TRIGGER trg_assign_scan_run_tenant`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO scan_runs (tenant_id, id, engagement_id, created_at, manifest, finding_keys) VALUES ($1,$2,$3,now(),'{}','[]')`, tenantA, "sr-rls-cross-"+stamp, engB)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "fk_scan_runs_engagement_tenant" {
		t.Fatalf("a run under a tenant that does not own its engagement: %v, want the composite key to refuse it", err)
	}
	_ = tx.Rollback(ctx)
	var notNull bool
	if err := pool.QueryRow(ctx, `SELECT attnotnull FROM pg_attribute WHERE attrelid='scan_runs'::regclass AND attname='tenant_id'`).Scan(&notNull); err != nil || !notNull {
		t.Fatalf("scan_runs.tenant_id NOT NULL = %v (%v)", notNull, err)
	}
	_ = shared.DefaultTenant
}
