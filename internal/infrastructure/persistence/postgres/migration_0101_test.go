package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0101AdvisoryRevisionSyncRuns(t *testing.T) {
	dsn := isolatedMigrationAt(t, 101)
	ctx := context.Background()
	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 100); err != nil {
		t.Fatalf("down to 0100: %v", err)
	}
	if err := goose.UpTo(db, ".", 101); err != nil {
		t.Fatalf("up 0101: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var table, index bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('advisory_revision_sync_runs') IS NOT NULL,to_regclass('idx_advisory_revision_sync_runs_run') IS NOT NULL`).Scan(&table, &index); err != nil || !table || !index {
		t.Fatalf("table=%v index=%v err=%v", table, index, err)
	}
}
