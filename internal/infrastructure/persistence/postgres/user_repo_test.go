package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// TestUserRepoTenantRoundTrip covers the tenant source (migration 0035): a user's
// tenant_id persists and round-trips through GetByAPIKeyHash – the auth path the Principal
// resolves its tenant from. A user created without one defaults to ” (single-tenant). Gated
// on SYNAPSE_TEST_DB_DSN.
func TestUserRepoTenantRoundTrip(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	repo := NewUserRepository(pool)

	hash := "hash-" + randHex(t)
	u, err := user.New(shared.ID("u-"+randHex(t)), "acme", "Tenanted", user.RoleMember, hash, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByAPIKeyHash(ctx, hash)
	if err != nil {
		t.Fatalf("auth lookup: %v", err)
	}
	if got.TenantID != "acme" {
		t.Fatalf("tenant_id must round-trip through the auth path, got %q", got.TenantID)
	}

	// A user created without a tenant defaults to '' (single-tenant), proving the additive
	// migration is backward-compatible.
	hash2 := "hash2-" + randHex(t)
	u2, _ := user.New(shared.ID("u2-"+randHex(t)), "", "Default", user.RoleMember, hash2, time.Unix(1, 0).UTC())
	if err := repo.Create(ctx, u2); err != nil {
		t.Fatalf("create default: %v", err)
	}
	if got2, _ := repo.GetByAPIKeyHash(ctx, hash2); got2.TenantID != "" {
		t.Fatalf("a user without a tenant must default to '', got %q", got2.TenantID)
	}
}
