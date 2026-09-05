package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0081MakesIndependenceConstraintFailClosed(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	if err := MigrateLocked(context.Background(), dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatalf("goose open: %v", err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	constraint := func() string {
		t.Helper()
		var definition string
		if err := db.QueryRow(`
			SELECT pg_get_constraintdef(oid)
			FROM pg_constraint
			WHERE conrelid = 'ai_triage_reviews'::regclass
			  AND conname = 'ai_triage_reviews_independence_metadata_check'`).Scan(&definition); err != nil {
			t.Fatalf("read independence constraint: %v", err)
		}
		return definition
	}
	assertUp := func(definition string) {
		t.Helper()
		for _, legacy := range []string{"fp-gate-v1", "fp-gate-v2", "fp-gate-v3"} {
			if !strings.Contains(definition, legacy) {
				t.Fatalf("constraint lost explicit historical exemption %s: %s", legacy, definition)
			}
		}
		// v4, v5 and a future v6 must not be enumerated as the protected set. They are protected by
		// falling through the explicit legacy exemption, so a version bump cannot fail open.
		for _, protected := range []string{"fp-gate-v4", "fp-gate-v5", "fp-gate-v6"} {
			if strings.Contains(definition, protected) {
				t.Fatalf("constraint unexpectedly enumerates protected version %s: %s", protected, definition)
			}
		}
		if !strings.Contains(definition, "proposer_provider") || !strings.Contains(definition, "independence_policy") {
			t.Fatalf("constraint lost independence metadata requirements: %s", definition)
		}
	}
	assertDown := func(definition string) {
		t.Helper()
		if !strings.Contains(definition, "fp-gate-v4") || strings.Contains(definition, "fp-gate-v5") {
			t.Fatalf("down migration did not restore the v4-only historical constraint: %s", definition)
		}
	}

	assertUp(constraint())
	// Migration 0085 intentionally refuses a rollback after a tenant v2 audit
	// entry exists. Isolate this historical migration test from prior live-DSN
	// test data before rolling through 0085 to reach 0081.
	cleanupConn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("migration cleanup connection: %v", err)
	}
	if _, err := cleanupConn.ExecContext(context.Background(), "SET session_replication_role = replica"); err != nil {
		cleanupConn.Close()
		t.Fatalf("disable audit append-only trigger: %v", err)
	}
	if _, err := cleanupConn.ExecContext(context.Background(), "DELETE FROM audit_log WHERE hash_version = 2"); err != nil {
		_, _ = cleanupConn.ExecContext(context.Background(), "SET session_replication_role = origin")
		cleanupConn.Close()
		t.Fatalf("clear v2 audit rows: %v", err)
	}
	if _, err := cleanupConn.ExecContext(context.Background(), "SET session_replication_role = origin"); err != nil {
		cleanupConn.Close()
		t.Fatalf("restore audit append-only trigger: %v", err)
	}
	cleanupConn.Close()

	// DownTo(80) makes 0081 the current migration, so the following Down
	// applies exactly 0081 rather than only the latest migration. Reapply all
	// migrations afterwards to restore this shared test database to version 88.
	if err := goose.DownTo(db, ".", 80); err != nil {
		t.Fatalf("down to 0080: %v", err)
	}
	if err := goose.Down(db, "."); err != nil {
		t.Fatalf("down 0081: %v", err)
	}
	assertDown(constraint())
	if err := goose.Up(db, "."); err != nil {
		t.Fatalf("restore to 0088: %v", err)
	}
	assertUp(constraint())

	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("dedicated migration probe connection: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "SET session_replication_role = replica"); err != nil {
		t.Fatalf("disable FK triggers for isolated CHECK probe: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "SET session_replication_role = origin") }()
	probePolicy := func(policy string, withMetadata bool) error {
		provider, family, independence := "", "", ""
		if withMetadata {
			provider, family, independence = "openai", "model-a", "model_family"
		}
		tx, txErr := conn.BeginTx(context.Background(), nil)
		if txErr != nil {
			return txErr
		}
		defer tx.Rollback()
		_, err := tx.ExecContext(context.Background(), `INSERT INTO ai_triage_reviews (
			id, tenant_id, engagement_id, finding_id, dedup_key, title, severity, state, verdict, driver,
			confidence, suspected_fp, proposer_model, verifier_model, prompt_version, verified, policy_version,
			policy_reason, evidence_ref, created_at, updated_at, proposer_provider, proposer_model_family,
			verifier_provider, verifier_model_family, independence_policy
		) VALUES ($1,'probe-tenant','probe-engagement','probe-finding',$2,'probe','medium','pending','uncertain',
		'insufficient_context',50,false,'model-a','','fp-triage-v3',false,$3,'probe','probe-evidence',now(),now(),$4,$5,'','',$6)`,
			"probe-"+policy+"-"+provider, "probe:"+policy+":"+provider, policy, provider, family, independence)
		return err
	}
	if err := probePolicy("fp-gate-v6", false); err == nil {
		t.Fatal("future policy without independence metadata passed database CHECK")
	}
	if err := probePolicy("fp-gate-v6", true); err != nil {
		t.Fatalf("future policy with metadata rejected: %v", err)
	}
	if err := probePolicy("fp-gate-v3", false); err != nil {
		t.Fatalf("legacy v3 exemption rejected: %v", err)
	}
}
