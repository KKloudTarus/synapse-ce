package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"
)

func TestMigration0170OwnershipBulkUpgrade(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 165, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('bulk-other','Other'); INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('bulk-admin','Admin','admin','bulk-default',''),('bulk-foreign','Foreign','admin','bulk-foreign','bulk-other')`); err != nil {
			t.Fatal(err)
		}
	})
	requireMigrationRLS(t, db, "ownership_bulk_requests")
	repo, err := NewOwnershipRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "default")
	hash, at := ownership.ContentHash("original"), time.Now().UTC()
	for i := 0; i < 2; i++ {
		if err := repo.ReserveOwnershipBulk(ctx, "bulk-admin", "request", hash, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.ReserveOwnershipBulk(ctx, "bulk-admin", "request", ownership.ContentHash("changed"), at); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed request accepted: %v", err)
	}
	if err := repo.ReserveOwnershipBulk(ctx, "bulk-foreign", "request", hash, at); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign actor accepted: %v", err)
	}
	if err := WithTenant(ctx, pool, "bulk-other", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ownership_bulk_requests`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("bulk reservation leaked: %d", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`UPDATE ownership_bulk_requests SET request_hash=repeat('b',64)`, `DELETE FROM ownership_bulk_requests`} {
		if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement)
			return err
		}); err == nil {
			t.Fatalf("immutable reservation accepted %s", statement)
		}
	}
	if err := goose.DownTo(db, ".", 165); err != nil {
		t.Fatal(err)
	}
	requireMigrationTable(t, db, "ownership_bulk_requests", false)
	if err := goose.UpTo(db, ".", 166); err != nil {
		t.Fatal(err)
	}
	requireMigrationRLS(t, db, "ownership_bulk_requests")
}
