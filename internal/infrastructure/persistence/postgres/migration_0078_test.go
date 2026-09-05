package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestMigration0078PersistsVerifierIndependenceIdentity(t *testing.T) {
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
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, `SELECT column_name FROM information_schema.columns
WHERE table_schema=current_schema() AND table_name='ai_triage_reviews'`)
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	columns := map[string]bool{}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			rows.Close()
			t.Fatalf("scan column: %v", err)
		}
		columns[column] = true
	}
	rows.Close()
	for _, column := range []string{"proposer_provider", "proposer_model_family", "verifier_provider", "verifier_model_family", "independence_policy"} {
		if !columns[column] {
			t.Fatalf("migration is missing %s", column)
		}
	}

	var uniqueDef, checkDef string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid='ai_triage_reviews'::regclass AND conname='ai_triage_reviews_independent_identity_unique'`).Scan(&uniqueDef); err != nil {
		t.Fatalf("read independence identity constraint: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid='ai_triage_reviews'::regclass AND conname='ai_triage_reviews_independence_metadata_check'`).Scan(&checkDef); err != nil {
		t.Fatalf("read independence metadata constraint: %v", err)
	}
	for _, required := range []string{"proposer_provider", "proposer_model_family", "verifier_provider", "verifier_model_family", "independence_policy"} {
		if !strings.Contains(strings.ToLower(uniqueDef), required) || !strings.Contains(strings.ToLower(checkDef), required) {
			t.Fatalf("constraints do not bind %s: unique=%s check=%s", required, uniqueDef, checkDef)
		}
	}
}
