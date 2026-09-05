package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

// rls0129Tables is the exact set migration 0129 puts under forced tenant RLS. Every entry must be
// a table that already carried a tenant_id column; the list is repeated here rather than derived
// from the schema so a table silently dropped from the migration fails the test.
var rls0129Tables = []string{
	"projects",
	"project_analyses",
	"project_analysis_hotspots",
	"project_hotspots",
	"project_hotspot_review_events",
	"project_issues",
	"project_issue_review_events",
	"quality_gates",
	"quality_profiles",
	"threat_models",
	"agent_sessions",
	"agent_approvals",
	"agent_plans",
}

// TestMigration0129EnablesTenantRLS asserts the migration leaves every one of the thirteen tables
// with RLS enabled, FORCEd (so the owning role is governed too), and carrying the single
// synapse_enable_tenant_rls policy keyed on synapse_current_tenant().
func TestMigration0129EnablesTenantRLS(t *testing.T) {
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

	for _, table := range rls0129Tables {
		t.Run(table, func(t *testing.T) {
			var enabled, forced bool
			if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&enabled, &forced); err != nil {
				t.Fatalf("inspect RLS: %v", err)
			}
			if !enabled || !forced {
				t.Fatalf("RLS not enabled and forced: enabled=%v forced=%v", enabled, forced)
			}

			var qual, withCheck string
			if err := pool.QueryRow(ctx,
				`SELECT COALESCE(qual, ''), COALESCE(with_check, '')
				 FROM pg_policies WHERE schemaname='public' AND tablename=$1 AND policyname=$2`,
				table, table+"_tenant_isolation").Scan(&qual, &withCheck); err != nil {
				t.Fatalf("isolation policy missing: %v", err)
			}
			// Both halves must key on the tenant. A USING-only policy would let a cross-tenant
			// INSERT through, which is the failure mode the WITH CHECK half exists to stop.
			for name, expr := range map[string]string{"USING": qual, "WITH CHECK": withCheck} {
				if expr == "" {
					t.Fatalf("%s expression is empty on %s_tenant_isolation", name, table)
				}
				if !containsAll(expr, "tenant_id", "synapse_current_tenant()") {
					t.Fatalf("%s expression does not key on the current tenant: %q", name, expr)
				}
			}

			// Exactly one policy: a second, looser policy would be OR'ed in and reopen the table.
			var policies int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename=$1`, table).Scan(&policies); err != nil {
				t.Fatalf("count policies: %v", err)
			}
			if policies != 1 {
				t.Fatalf("expected exactly one policy, found %d", policies)
			}
		})
	}
}

// TestMigration0129PinsAgentTenantColumns asserts the backfilled columns cannot go back to NULL.
// agent_approvals and agent_plans shipped with a nullable tenant_id that no code path wrote, so
// every pre-0129 row was NULL; under RLS a NULL tenant is invisible to every tenant, which is why
// the migration backfills it from the owning engagement and then pins it.
func TestMigration0129PinsAgentTenantColumns(t *testing.T) {
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

	for _, tc := range []struct{ table, constraint string }{
		{"agent_approvals", "agent_approvals_tenant_fk"},
		{"agent_plans", "agent_plans_tenant_fk"},
	} {
		t.Run(tc.table, func(t *testing.T) {
			var nullable string
			if err := pool.QueryRow(ctx,
				`SELECT is_nullable FROM information_schema.columns
				 WHERE table_schema='public' AND table_name=$1 AND column_name='tenant_id'`, tc.table).Scan(&nullable); err != nil {
				t.Fatalf("inspect tenant_id: %v", err)
			}
			if nullable != "NO" {
				t.Fatalf("tenant_id is still nullable (%s)", nullable)
			}
			var hasFK bool
			if err := pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname=$1 AND conrelid=$2::regclass AND contype='f')`,
				tc.constraint, tc.table).Scan(&hasFK); err != nil {
				t.Fatalf("inspect tenant fk: %v", err)
			}
			if !hasFK {
				t.Fatalf("missing tenant foreign key %s", tc.constraint)
			}
		})
	}
}

// TestMigration0129DownIsSafe asserts the rollback direction actually reopens the tables (a
// rolled-back binary that still queries the raw pool must see its rows again) and that re-applying
// restores the policies. It is the operator's escape hatch from the deployment-ordering hazard
// documented in the migration header.
func TestMigration0129DownIsSafe(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Always leave the schema fully migrated, whatever this test does.
	t.Cleanup(func() { _ = MigrateLocked(context.Background(), dsn) })

	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	if err := goose.DownTo(db, ".", 128); err != nil {
		t.Fatalf("down to 128: %v", err)
	}
	for _, table := range rls0129Tables {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("inspect %s after down: %v", table, err)
		}
		if enabled || forced {
			t.Fatalf("%s still has RLS after rollback: enabled=%v forced=%v", table, enabled, forced)
		}
		var policies int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename=$1`, table).Scan(&policies); err != nil {
			t.Fatalf("count %s policies after down: %v", table, err)
		}
		if policies != 0 {
			t.Fatalf("%s still has %d policies after rollback", table, policies)
		}
	}
	// The pinned columns relax again so a rolled-back binary that never wrote tenant_id can insert.
	for _, table := range []string{"agent_approvals", "agent_plans"} {
		var nullable string
		if err := pool.QueryRow(ctx,
			`SELECT is_nullable FROM information_schema.columns
			 WHERE table_schema='public' AND table_name=$1 AND column_name='tenant_id'`, table).Scan(&nullable); err != nil {
			t.Fatalf("inspect %s tenant_id after down: %v", table, err)
		}
		if nullable != "YES" {
			t.Fatalf("%s tenant_id is still NOT NULL after rollback", table)
		}
	}

	if err := goose.UpTo(db, ".", 129); err != nil {
		t.Fatalf("up to 129: %v", err)
	}
	for _, table := range rls0129Tables {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("inspect %s after re-apply: %v", table, err)
		}
		if !enabled || !forced {
			t.Fatalf("%s RLS not restored: enabled=%v forced=%v", table, enabled, forced)
		}
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}
