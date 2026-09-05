package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0123PrivacyPolicyActivationEvidenceGuards(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var rls, forced bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity
		FROM pg_class WHERE oid='privacy_policy_activations'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatalf("inspect activation RLS: %v", err)
	}
	if !rls || !forced {
		t.Fatalf("activation RLS/forced=%t/%t, want true/true", rls, forced)
	}
	for _, trigger := range []string{"privacy_policy_activations_append_only", "privacy_policy_activations_no_truncate"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger
			WHERE tgrelid='privacy_policy_activations'::regclass AND tgname=$1 AND NOT tgisinternal)`, trigger).Scan(&exists); err != nil {
			t.Fatalf("inspect activation trigger %s: %v", trigger, err)
		}
		if !exists {
			t.Fatalf("migration 0123 did not install %s", trigger)
		}
	}
	var definition string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='privacy_policy_activations'::regclass
		  AND conname='privacy_policy_activations_digest_sha256'`).Scan(&definition); err != nil {
		t.Fatalf("inspect activation digest constraint: %v", err)
	}
	if !strings.Contains(definition, "policy_digest ~ '^[0-9a-f]{64}$'") {
		t.Fatalf("activation digest constraint=%q", definition)
	}
}

func TestMigration0123RefusesRollbackWithActivationHistory(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := openLockedGooseDB(t, dsn)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `SET session_replication_role = replica`)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM privacy_policy_activations WHERE operation_id='migration-0123-probe'`)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM privacy_active_policies WHERE tenant_id='migration-0123-probe'`)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM privacy_policies WHERE tenant_id='migration-0123-probe'`)
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id='migration-0123-probe'`)
		_, _ = db.ExecContext(context.Background(), `SET session_replication_role = origin`)
		_ = db.Close()
	})
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}

	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants(id,name) VALUES('migration-0123-probe','migration-0123-probe')`); err != nil {
		t.Fatalf("seed migration tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO privacy_policies
		(tenant_id,policy_version,policy,digest,created_by,created_at)
		VALUES ('migration-0123-probe','probe:v1','{}'::jsonb,$1,'migration-test',now())`, digest); err != nil {
		t.Fatalf("seed migration policy: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO privacy_policy_activations
		(tenant_id,operation_id,revision,policy_digest,policy_version,activated_by,activated_at)
		VALUES ('migration-0123-probe','migration-0123-probe',1,$1,'probe:v1','migration-test',now())`, digest); err != nil {
		t.Fatalf("seed migration activation: %v", err)
	}
	// DownTo, not Down: Down rolls back only the NEWEST applied migration, so once a later
	// migration exists it would absorb this assertion instead of exercising 0123's guard.
	// DownTo unwinds every migration above the target, which drops those later tables, so
	// re-apply them before returning or the rest of the suite runs against a partial schema.
	t.Cleanup(func() {
		if err := goose.Up(db, "."); err != nil {
			t.Errorf("restore migrations after rollback probe: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 122); err == nil || !strings.Contains(err.Error(), "cannot roll back 0123") {
		t.Fatalf("down migration error=%v, want activation-history refusal", err)
	}
	var version int64
	if err := db.QueryRowContext(ctx, `SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&version); err != nil && err != sql.ErrNoRows {
		t.Fatalf("read migration version after refused down: %v", err)
	}
	if version != 123 {
		t.Fatalf("migration version after refused down=%d, want 123", version)
	}
}
