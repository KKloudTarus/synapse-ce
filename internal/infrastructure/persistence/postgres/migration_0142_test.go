package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0142RollbackAndReapply(t *testing.T) {
	dsn := isolatedMigrationAt(t, 142)
	ctx := context.Background()
	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 141); err != nil {
		t.Fatalf("down to 141: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='response_target_evidence_receipts')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("target evidence receipt table still exists after migration rollback")
	}
	if err := goose.UpTo(db, ".", 142); err != nil {
		t.Fatalf("up to 142: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='response_target_evidence_receipts')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("target evidence receipt table missing after migration reapply")
	}
}
