package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0140DefinesTenantSealedScanRunProvenance(t *testing.T) {
	data, err := migrations.FS.ReadFile("0140_scan_run_provenance.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(data)
	for _, required := range []string{
		"ADD COLUMN tenant_id TEXT", "scan_runs_engagement_fk_tenant", "scan_run_lanes", "scan_run_lane_versions", "scan_run_lane_stages",
		"synapse_enable_tenant_rls('scan_runs')", "synapse_guard_scan_run_update", "provenance = 'legacy'", "terminal_status = 'unknown'",
		"unlisted id-only scan_runs foreign keys", "cannot roll back scan-run provenance after native rows exist",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
}

func TestMigration0140UpgradeBackfillsLegacyRowsAndCompositeFK(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 128); err != nil {
		t.Fatalf("up to 0128: %v", err)
	}
	for _, statement := range []string{
		`INSERT INTO tenants(id,name) VALUES('m140-tenant-a','A'),('m140-tenant-b','B')`,
		`INSERT INTO engagements(id,tenant_id,name) VALUES('m140-eng-a','m140-tenant-a','A'),('m140-eng-b','m140-tenant-b','B')`,
		`INSERT INTO scan_runs(id,engagement_id,created_at,manifest,finding_keys) VALUES
			('m140-run-a','m140-eng-a',now(),'{}'::jsonb,'[]'::jsonb),
			('m140-run-b','m140-eng-b',now(),'{}'::jsonb,'[]'::jsonb)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("seed legacy scan runs: %v", err)
		}
	}
	if err := goose.UpTo(db, ".", 140); err != nil {
		t.Fatalf("up to 0140: %v", err)
	}

	rows, err := db.QueryContext(context.Background(), `SELECT id,tenant_id,provenance,terminal_status,manifest_schema_version,manifest_hash,sealed_at
		FROM scan_runs ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	wantTenant := map[string]string{"m140-run-a": "m140-tenant-a", "m140-run-b": "m140-tenant-b"}
	seen := 0
	for rows.Next() {
		var id, tenantID, provenance, status string
		var schemaVersion int
		var manifestHash *string
		var sealedAt *time.Time
		if err := rows.Scan(&id, &tenantID, &provenance, &status, &schemaVersion, &manifestHash, &sealedAt); err != nil {
			t.Fatal(err)
		}
		if tenantID != wantTenant[id] || provenance != "legacy" || status != "unknown" || schemaVersion != 0 || manifestHash != nil || sealedAt != nil {
			t.Fatalf("legacy row %s backfill = tenant=%q provenance=%q status=%q schema=%d hash=%v sealed=%v", id, tenantID, provenance, status, schemaVersion, manifestHash, sealedAt)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("backfilled rows=%d, want 2", seen)
	}

	var validated bool
	var definition string
	if err := db.QueryRowContext(context.Background(), `SELECT convalidated,pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='scan_runs'::regclass AND conname='scan_runs_engagement_fk_tenant'`).Scan(&validated, &definition); err != nil {
		t.Fatal(err)
	}
	if !validated || !strings.Contains(definition, "FOREIGN KEY (tenant_id, engagement_id)") {
		t.Fatalf("composite engagement FK validated=%v definition=%q", validated, definition)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO scan_runs
		(id,tenant_id,engagement_id,created_at,manifest,finding_keys,provenance,terminal_status)
		VALUES('m140-cross-tenant','m140-tenant-b','m140-eng-a',now(),'{}'::jsonb,'[]'::jsonb,'legacy','unknown')`); err == nil {
		t.Fatal("composite FK accepted a cross-tenant engagement")
	}

	var legacyEngagement string
	if err := db.QueryRowContext(context.Background(), `SELECT engagement_id FROM scan_runs WHERE id='m140-run-a'`).Scan(&legacyEngagement); err != nil || legacyEngagement != "m140-eng-a" {
		t.Fatalf("legacy id-only read engagement=%q err=%v", legacyEngagement, err)
	}
}

func TestMigration0140CatalogRejectsUnlistedIDOnlyDependents(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("dependents_%d", count), func(t *testing.T) {
			db, _ := newMigration0140DB(t)
			if err := goose.UpTo(db, ".", 128); err != nil {
				t.Fatalf("up to 0128: %v", err)
			}
			for index := 0; index < count; index++ {
				name := fmt.Sprintf("m140_dependent_%d", index)
				query := `CREATE TABLE ` + pgx.Identifier{name}.Sanitize() + ` (id TEXT PRIMARY KEY, scan_run_id TEXT REFERENCES scan_runs(id))`
				if _, err := db.ExecContext(context.Background(), query); err != nil {
					t.Fatalf("create dependent %s: %v", name, err)
				}
			}
			err := goose.UpTo(db, ".", 140)
			if count == 0 {
				if err != nil {
					t.Fatalf("zero-dependent migration failed: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "unlisted id-only scan_runs foreign keys") {
				t.Fatalf("dependent migration error=%v", err)
			}
			for index := 0; index < count; index++ {
				if name := fmt.Sprintf("m140_dependent_%d", index); !strings.Contains(err.Error(), name) {
					t.Fatalf("migration error does not name dependent %s: %v", name, err)
				}
			}
		})
	}
}

func TestMigration0140RejectsOrphanLegacyRows(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 128); err != nil {
		t.Fatalf("up to 0128: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO scan_runs(id,engagement_id,created_at,manifest,finding_keys)
		VALUES('m140-orphan','missing-engagement',now(),'{}'::jsonb,'[]'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", 140); err == nil || !strings.Contains(err.Error(), "m140-orphan") {
		t.Fatalf("orphan migration error=%v", err)
	}
}

func TestMigration0140RollbackBeforeAndAfterNativeRows(t *testing.T) {
	t.Run("legacy_only", func(t *testing.T) {
		db, _ := newMigration0140DB(t)
		if err := goose.UpTo(db, ".", 128); err != nil {
			t.Fatalf("up to 0128: %v", err)
		}
		for _, statement := range []string{
			`INSERT INTO tenants(id,name) VALUES('m140-rollback-tenant','tenant')`,
			`INSERT INTO engagements(id,tenant_id,name) VALUES('m140-rollback-eng','m140-rollback-tenant','eng')`,
			`INSERT INTO scan_runs(id,engagement_id,created_at,manifest,finding_keys) VALUES('m140-rollback-run','m140-rollback-eng',now(),'{}'::jsonb,'[]'::jsonb)`,
		} {
			if _, err := db.ExecContext(context.Background(), statement); err != nil {
				t.Fatal(err)
			}
		}
		if err := goose.UpTo(db, ".", 140); err != nil {
			t.Fatalf("up to 0140: %v", err)
		}
		if err := goose.DownTo(db, ".", 128); err != nil {
			t.Fatalf("legacy-only rollback: %v", err)
		}
		var engagementID string
		if err := db.QueryRowContext(context.Background(), `SELECT engagement_id FROM scan_runs WHERE id='m140-rollback-run'`).Scan(&engagementID); err != nil || engagementID != "m140-rollback-eng" {
			t.Fatalf("legacy row after rollback engagement=%q err=%v", engagementID, err)
		}
		var tenantColumnExists bool
		if err := db.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='scan_runs' AND column_name='tenant_id')`).Scan(&tenantColumnExists); err != nil || tenantColumnExists {
			t.Fatalf("tenant column after rollback exists=%v err=%v", tenantColumnExists, err)
		}
	})

	t.Run("native_present", func(t *testing.T) {
		db, _ := newMigration0140DB(t)
		if err := goose.UpTo(db, ".", 140); err != nil {
			t.Fatalf("up to 0140: %v", err)
		}
		for _, statement := range []string{
			`INSERT INTO tenants(id,name) VALUES('m140-native-tenant','tenant')`,
			`INSERT INTO engagements(id,tenant_id,name) VALUES('m140-native-eng','m140-native-tenant','eng')`,
			`INSERT INTO scan_runs(id,tenant_id,engagement_id,created_at,manifest,finding_keys,provenance,terminal_status)
				VALUES('m140-native-run','m140-native-tenant','m140-native-eng',now(),'{}'::jsonb,'[]'::jsonb,'native','building')`,
		} {
			if _, err := db.ExecContext(context.Background(), statement); err != nil {
				t.Fatal(err)
			}
		}
		if err := goose.DownTo(db, ".", 128); err == nil || !strings.Contains(err.Error(), "cannot roll back scan-run provenance") {
			t.Fatalf("native rollback error=%v", err)
		}
		var tenantColumnExists bool
		if err := db.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='scan_runs' AND column_name='tenant_id')`).Scan(&tenantColumnExists); err != nil || !tenantColumnExists {
			t.Fatalf("expanded schema after refused rollback exists=%v err=%v", tenantColumnExists, err)
		}
	})
}

func newMigration0140DB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedMigration0140DSN(t, sharedDSN)
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	return db, dsn
}

func isolatedMigration0140DSN(t *testing.T, sharedDSN string) string {
	t.Helper()
	u, err := url.Parse(sharedDSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}
	name := fmt.Sprintf("synapse_migration_0140_%d", time.Now().UnixNano())
	isolated := *u
	isolated.Path = "/" + name
	isolated.RawPath = ""
	admin, err := Connect(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("connect PostgreSQL admin database: %v", err)
	}
	quotedName := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+quotedName); err != nil {
		admin.Close()
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, name)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+quotedName); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		admin.Close()
	})
	return isolated.String()
}
