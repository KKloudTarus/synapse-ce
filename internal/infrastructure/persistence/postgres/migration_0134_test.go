package postgres

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigrationInventoryNoDuplicateGooseVersions(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	versionRegex := regexp.MustCompile(`^(\d+)_.*\.sql$`)
	seenVersions := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := versionRegex.FindStringSubmatch(entry.Name())
		if len(matches) != 2 {
			continue
		}
		version, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			t.Fatalf("parse version in %s: %v", entry.Name(), err)
		}
		if previous, exists := seenVersions[version]; exists {
			t.Fatalf("duplicate goose migration version %04d in %q and %q", version, previous, entry.Name())
		}
		seenVersions[version] = entry.Name()
	}
}

// TestMigration0134ProductionOwnerPath reproduces the production migration
// credential: the database and tables are owned by a login that is neither a
// superuser nor BYPASSRLS. A legacy row at 0133 must be backfilled even though
// engagements is already under FORCE ROW LEVEL SECURITY.
func TestMigration0134ProductionOwnerPath(t *testing.T) {
	dsn := isolatedMigrationOwnerDSN(t)
	ctx := context.Background()

	db, err := goose.OpenDBWithDriver("pgx", dsnForMigrate(dsn))
	if err != nil {
		t.Fatalf("open goose database: %v", err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", 133); err != nil {
		t.Fatalf("migrate owner database to 0133: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect owner database: %v", err)
	}
	defer pool.Close()

	const tenantID = "tenant-0134"
	const engagementID = "engagement-0134"
	const runID = "legacy-run-0134"
	if err := WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagementID, tenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO scan_runs(id,engagement_id,created_at,manifest,finding_keys)
			VALUES($1,$2,$3,'{}'::jsonb,'[]'::jsonb)
		`, runID, engagementID, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("seed pre-0134 legacy row: %v", err)
	}

	if err := goose.UpTo(db, ".", 134); err != nil {
		t.Fatalf("apply 0134 as non-bypass owner: %v", err)
	}

	var superuser, bypassRLS bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&superuser, &bypassRLS); err != nil {
		t.Fatalf("inspect owner role: %v", err)
	}
	if superuser || bypassRLS {
		t.Fatalf("migration probe role bypasses RLS: superuser=%v bypassrls=%v", superuser, bypassRLS)
	}

	var backfilledTenant string
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM scan_runs WHERE id=$1`, runID).Scan(&backfilledTenant); err != nil {
		t.Fatalf("read migrated scan run: %v", err)
	}
	if backfilledTenant != tenantID {
		t.Fatalf("legacy tenant backfill=%q, want %q", backfilledTenant, tenantID)
	}

	var engagementsForced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid='engagements'::regclass`).Scan(&engagementsForced); err != nil {
		t.Fatalf("inspect engagements RLS: %v", err)
	}
	if !engagementsForced {
		t.Fatal("migration did not restore FORCE RLS on engagements")
	}

	var nullable string
	if err := pool.QueryRow(ctx, `
		SELECT is_nullable FROM information_schema.columns
		WHERE table_schema='public' AND table_name='scan_runs' AND column_name='tenant_id'
	`).Scan(&nullable); err != nil {
		t.Fatalf("inspect scan_runs.tenant_id: %v", err)
	}
	if nullable != "YES" {
		t.Fatalf("expand migration made scan_runs.tenant_id non-nullable: %s", nullable)
	}
	var scanRunDeleteRule string
	if err := pool.QueryRow(ctx, `
		SELECT rc.delete_rule
		FROM information_schema.referential_constraints rc
		WHERE rc.constraint_schema='public' AND rc.constraint_name='fk_scan_runs_engagement'
	`).Scan(&scanRunDeleteRule); err != nil {
		t.Fatalf("inspect scan-run engagement FK: %v", err)
	}
	if scanRunDeleteRule != "RESTRICT" {
		t.Fatalf("scan-run engagement FK delete rule=%q, want RESTRICT", scanRunDeleteRule)
	}

	for _, table := range []string{"scan_run_lanes", "scan_run_lane_versions", "scan_run_lane_stages"} {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("inspect %s RLS: %v", table, err)
		}
		if !enabled || !forced {
			t.Fatalf("%s RLS enabled=%v forced=%v", table, enabled, forced)
		}
	}

	var scanRunsRLS bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity FROM pg_class WHERE oid='scan_runs'::regclass`).Scan(&scanRunsRLS); err != nil {
		t.Fatalf("inspect scan_runs RLS: %v", err)
	}
	if scanRunsRLS {
		t.Fatal("expand migration enabled scan_runs RLS before legacy writers are tenant-aware")
	}

	// Reproduce the migrate-first overlap: the old repository names only the
	// original five columns and performs an unscoped read. The transitional trigger
	// fills tenant_id from the engagement map, so both old and new readers retain
	// visibility until the later contract migration makes tenant ownership mandatory.
	const overlapRunID = "legacy-overlap-run-0134"
	if _, err := pool.Exec(ctx, `
		INSERT INTO scan_runs(id,engagement_id,created_at,manifest,finding_keys)
		VALUES($1,$2,$3,'{}'::jsonb,'[]'::jsonb)
	`, overlapRunID, engagementID, time.Now().UTC()); err != nil {
		t.Fatalf("pre-0134 writer failed during overlap: %v", err)
	}
	var overlapTenant *string
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM scan_runs WHERE id=$1`, overlapRunID).Scan(&overlapTenant); err != nil {
		t.Fatalf("pre-0134 reader failed during overlap: %v", err)
	}
	if overlapTenant == nil || *overlapTenant != tenantID {
		t.Fatalf("legacy overlap insert tenant=%v, want %q", overlapTenant, tenantID)
	}
	legacyRows, err := NewScanRunStore(pool).List(shared.WithTenant(ctx, shared.ID(tenantID)), shared.ID(engagementID))
	if err != nil {
		t.Fatalf("new tenant-scoped reader failed during overlap: %v", err)
	}
	var foundOverlap bool
	for _, row := range legacyRows {
		if row.ID == overlapRunID {
			foundOverlap = true
			break
		}
	}
	if !foundOverlap {
		t.Fatalf("new tenant-scoped reader missed legacy overlap run %q", overlapRunID)
	}

	if err := goose.DownTo(db, ".", 133); err != nil {
		t.Fatalf("roll back unsealed 0134 data: %v", err)
	}
	var childTables int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema='public' AND table_name LIKE 'scan_run_lane%'
	`).Scan(&childTables); err != nil {
		t.Fatalf("inspect rollback: %v", err)
	}
	if childTables != 0 {
		t.Fatalf("rollback left %d scan-run child tables", childTables)
	}
	var bridgeExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.scan_run_engagement_tenants') IS NOT NULL`).Scan(&bridgeExists); err != nil {
		t.Fatalf("inspect rollback tenant bridge: %v", err)
	}
	if bridgeExists {
		t.Fatal("rollback left the transitional scan-run tenant bridge")
	}
	if err := goose.UpTo(db, ".", 134); err != nil {
		t.Fatalf("reapply 0134: %v", err)
	}
}

func isolatedMigrationOwnerDSN(t *testing.T) string {
	t.Helper()
	sharedDSN := testDSN(t)
	parsed, err := url.Parse(sharedDSN)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}

	suffix := randHex(t)[:12]
	roleName := "synapse_migration_owner_" + suffix
	databaseName := "synapse_migration_0134_" + suffix
	password := "migration-owner-test-password"
	roleIdent := pgx.Identifier{roleName}.Sanitize()
	databaseIdent := pgx.Identifier{databaseName}.Sanitize()

	ctx := context.Background()
	admin, err := Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("connect migration admin: %v", err)
	}
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOBYPASSRLS", roleIdent, password)); err != nil {
		admin.Close()
		t.Fatalf("create migration owner role: %v", err)
	}
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s OWNER %s", databaseIdent, roleIdent)); err != nil {
		_, _ = admin.Exec(ctx, "DROP ROLE "+roleIdent)
		admin.Close()
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, databaseName)
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+databaseIdent); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		if _, err := admin.Exec(cleanupCtx, "DROP ROLE "+roleIdent); err != nil {
			t.Errorf("drop migration owner role: %v", err)
		}
		admin.Close()
	})

	isolated := *parsed
	isolated.Path = "/" + databaseName
	isolated.RawPath = ""
	isolated.User = url.UserPassword(roleName, password)
	return isolated.String()
}
