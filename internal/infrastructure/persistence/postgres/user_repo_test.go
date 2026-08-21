package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestUserRepoTenantRoundTrip covers the tenant source (migration 0035): a user's
// tenant_id persists and round-trips through GetByAPIKeyHash – the auth path the Principal
// resolves its tenant from. A user created without one defaults to ” (single-tenant). Gated
// on SYNAPSE_TEST_DB_DSN.
func TestBootstrapIsConcurrentAndAuditedOnce(t *testing.T) {
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

	id := shared.ID("bootstrap-" + randHex(t))
	u, err := user.New(id, "", "Bootstrap", user.RoleAdmin, "hash-"+randHex(t), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	auditEntry := ports.AuditEntry{
		Actor: id.String(), Action: "user.bootstrap_admin_seeded", Target: id.String(),
		Metadata: map[string]string{"idempotency_key": "bootstrap-admin:" + id.String()}, At: time.Now().UTC(),
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- NewUserRepository(pool).Bootstrap(context.Background(), u, auditEntry)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent bootstrap: %v", err)
		}
	}

	var users, audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=$1`, id.String()).Scan(&users); err != nil {
		t.Fatalf("count bootstrap users: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action=$1 AND target=$2`, auditEntry.Action, auditEntry.Target).Scan(&audits); err != nil {
		t.Fatalf("count bootstrap audits: %v", err)
	}
	if users != 1 || audits != 1 {
		t.Fatalf("bootstrap rows = users:%d audits:%d, want one each", users, audits)
	}
}

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
