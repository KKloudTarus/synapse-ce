package postgres

import (
	"context"
	"testing"
)

func TestPostgresReadinessChecks(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	if err := CheckDatabaseReady(ctx, pool); err != nil {
		t.Fatalf("migrated database should be reachable: %v", err)
	}
	if err := CheckMigrationsReady(ctx, pool); err != nil {
		t.Fatalf("all embedded migrations should be ready: %v", err)
	}

	// Goose retains migration history. Add an uncommitted latest "down" record and run the check
	// through the same transaction to prove it considers latest state rather than any historical up.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var latest int64
	if err := tx.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goose_db_version(version_id, is_applied) VALUES($1, false)`, latest); err != nil {
		t.Fatal(err)
	}
	if err := checkMigrationsReady(ctx, tx); err == nil {
		t.Fatal("a latest down record must make migrations not ready")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	pool.Close()
	if err := CheckDatabaseReady(ctx, pool); err == nil {
		t.Fatal("a closed database pool must not be ready")
	}
}
