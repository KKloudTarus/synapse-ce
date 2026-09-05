package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestComponentInventoryStoreListByEngagement validates the new by-engagement enumeration SQL against the
// real schema (column names, the latest-SBOM join). It asserts an empty result for an engagement with no
// SBOM (so it needs no component seeding) — the point is that the query parses and executes, and that
// tenant/engagement validation fails closed.
func TestComponentInventoryStoreListByEngagement(t *testing.T) {
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

	tenant := shared.ID("ci-" + randHex(t))
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	store := NewComponentInventoryStore(pool)
	tctx := shared.WithTenant(ctx, tenant)

	got, err := store.ListCurrentComponentsByEngagement(tctx, tenant, "eng-none")
	if err != nil {
		t.Fatalf("query must execute against the schema: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("no SBOM for the engagement must yield no components, got %d", len(got))
	}
	// Fail-closed validation.
	if _, err := store.ListCurrentComponentsByEngagement(tctx, "", "eng-none"); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing tenant must be rejected")
	}
	if _, err := store.ListCurrentComponentsByEngagement(tctx, tenant, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing engagement must be rejected")
	}
}
