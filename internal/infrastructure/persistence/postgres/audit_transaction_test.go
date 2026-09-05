package postgres_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// auditTxTestPool migrates and returns a pool, or skips when no integration database is configured.
func auditTxTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := postgres.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func auditRowCount(t *testing.T, pool *pgxpool.Pool, target string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE target = $1`, target).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// TestAuditRollsBackWithTheBoundTransaction is the regression for the atomicity defect: the audit
// log used to open its own transaction even when the caller was already inside one, so a business
// write that rolled back left a committed audit row claiming the change had happened. The entry
// must now share the caller's transaction and disappear with it.
func TestAuditRollsBackWithTheBoundTransaction(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("audit-tx-tenant-a")
	target := "audit-tx-rollback-" + time.Now().UTC().Format("150405.000000000")

	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	log := postgres.NewAuditLog(pool)
	runner := postgres.NewTenantTransactionRunner(pool)
	sentinel := errors.New("business write failed")

	err := runner.Run(ctx, tenant, func(txCtx context.Context) error {
		if err := log.Record(txCtx, ports.AuditEntry{
			Actor: "operator", Action: "test.rolled_back", Target: target, At: time.Now().UTC(),
		}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Run err = %v, want the business error", err)
	}

	if got := auditRowCount(t, pool, target); got != 0 {
		t.Errorf("audit rows after rollback = %d, want 0: the entry did not share the caller's transaction", got)
	}
}

// TestAuditCommitsWithTheBoundTransaction is the other half: when the caller's transaction commits,
// the entry it recorded must be there.
func TestAuditCommitsWithTheBoundTransaction(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("audit-tx-tenant-a")
	target := "audit-tx-commit-" + time.Now().UTC().Format("150405.000000000")

	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	log := postgres.NewAuditLog(pool)
	runner := postgres.NewTenantTransactionRunner(pool)

	if err := runner.Run(ctx, tenant, func(txCtx context.Context) error {
		return log.Record(txCtx, ports.AuditEntry{
			Actor: "operator", Action: "test.committed", Target: target, At: time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := auditRowCount(t, pool, target); got != 1 {
		t.Errorf("audit rows after commit = %d, want 1", got)
	}
}

// TestAuditOutsideATransactionStillCommits keeps the unbound path working: a caller with no bound
// transaction, such as a background job, still gets a durable entry.
func TestAuditOutsideATransactionStillCommits(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("audit-tx-tenant-a")
	target := "audit-tx-unbound-" + time.Now().UTC().Format("150405.000000000")

	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	log := postgres.NewAuditLog(pool)
	if err := log.Record(shared.WithTenant(ctx, tenant), ports.AuditEntry{
		Actor: "system", Action: "test.unbound", Target: target, At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if got := auditRowCount(t, pool, target); got != 1 {
		t.Errorf("audit rows = %d, want 1 for an unbound caller", got)
	}
}

// TestAuditReadsAreTenantScoped pins the isolation the audit_log RLS policy provides, so the
// route comment above listAudit stays true: a reviewer bound to tenant B must not see tenant
// A's entries even though both chains live in one table.
//
// The connecting test role is usually a superuser, which bypasses RLS entirely, so the read is
// re-run under a dedicated NOSUPERUSER NOBYPASSRLS role. That mirrors the production
// requirement CheckRLSRuntimeRole enforces at startup.
func TestAuditReadsAreTenantScoped(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	tenantA := shared.ID("audit-scope-tenant-a")
	tenantB := shared.ID("audit-scope-tenant-b")
	target := "audit-scope-" + time.Now().UTC().Format("150405.000000000")

	for _, id := range []shared.ID{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, id.String()); err != nil {
			t.Fatalf("seed tenant %s: %v", id, err)
		}
	}

	// Seed one tenant-chained (v2) row per tenant directly. AuditLog.Record cannot be used to
	// set this up here: the test pool usually connects as a superuser, row_security_active is
	// false for such a role, and Record then writes the legacy global form. Production runs as a
	// role that cannot bypass RLS (CheckRLSRuntimeRole refuses to serve otherwise), which is the
	// posture this test recreates below.
	for _, tenant := range []shared.ID{tenantA, tenantB} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO audit_log (tenant_id, actor, action, target, created_at, hash_version)
			 VALUES ($1, 'operator', 'test.scoped', $2, now(), 2)`,
			tenant.String(), target); err != nil {
			t.Fatalf("seed audit row for %s: %v", tenant, err)
		}
	}

	const role = "audit_scope_probe_role"
	for _, stmt := range []string{
		`DROP OWNED BY ` + role,
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON audit_log TO ` + role,
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})

	// countUnderRole reads audit_log as the unprivileged role with app.current_tenant bound to
	// tenant, so the policy actually applies.
	countUnderRole := func(tenant shared.ID) int {
		t.Helper()
		var n int
		if err := postgres.WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE target = $1`, target).Scan(&n)
		}); err != nil {
			t.Fatalf("read as %s under tenant %s: %v", role, tenant, err)
		}
		return n
	}

	// Both tenants have exactly one row with this target, so seeing more than its own is a leak.
	if got := countUnderRole(tenantA); got != 1 {
		t.Errorf("tenant A saw %d rows for the shared target, want only its own (1)", got)
	}
	if got := countUnderRole(tenantB); got != 1 {
		t.Errorf("tenant B saw %d rows for the shared target, want only its own (1)", got)
	}
	var total int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE target = $1`, target).Scan(&total); err != nil {
		t.Fatalf("count all rows: %v", err)
	}
	if total != 2 {
		t.Fatalf("seeded rows = %d, want 2; the per-tenant counts above are only meaningful against both", total)
	}
}
