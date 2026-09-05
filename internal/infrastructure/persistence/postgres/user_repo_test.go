package postgres

import (
	"context"
	"errors"
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
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM users WHERE id=$1`, id.String())
		conn, err := pool.Acquire(bg)
		if err != nil {
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(bg, `SET session_replication_role = replica`); err != nil {
			return
		}
		defer conn.Exec(bg, `SET session_replication_role = origin`)
		_, _ = conn.Exec(bg, `DELETE FROM audit_log WHERE action=$1 AND target=$2`, auditEntry.Action, auditEntry.Target)
	})

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

// TestUserRepoScopesReadsAndWritesByTenant proves the explicit tenant predicate, independent of row
// level security: a user of another tenant is invisible to reads and untouched by an update, while
// the bootstrap admin's empty tenant_id resolves to the default tenant. Gated on SYNAPSE_TEST_DB_DSN.
func TestUserRepoScopesReadsAndWritesByTenant(t *testing.T) {
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

	suffix := randHex(t)
	tenantA, tenantB := shared.ID("tenant-a-"+suffix), shared.ID("tenant-b-"+suffix)
	mk := func(tenant shared.ID, name string) *user.User {
		t.Helper()
		u, err := user.New(shared.ID(name+"-"+suffix), tenant.String(), name, user.RoleMember, "hash-"+name+"-"+suffix, time.Unix(1, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID.String()) })
		return u
	}
	inA, inB := mk(tenantA, "alice"), mk(tenantB, "bob")
	// A pre-tenant row (empty tenant_id) belongs to the default tenant.
	legacy, err := user.New(shared.ID("legacy-"+suffix), "", "Legacy", user.RoleAdmin, "hash-legacy-"+suffix, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, legacy); err != nil {
		t.Fatalf("create legacy: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, legacy.ID.String()) })

	if got, err := repo.GetByID(ctx, tenantA, inA.ID); err != nil || got.ID != inA.ID {
		t.Fatalf("own-tenant read: %+v %v", got, err)
	}
	if _, err := repo.GetByID(ctx, tenantA, inB.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant read = %v, want not found", err)
	}
	if got, err := repo.GetByID(ctx, shared.DefaultTenant, legacy.ID); err != nil || got.ID != legacy.ID {
		t.Errorf("an empty tenant_id must resolve to the default tenant: %+v %v", got, err)
	}
	if _, err := repo.GetByID(ctx, tenantA, legacy.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("default-tenant row must not leak into tenant-a: %v", err)
	}

	listed, err := repo.List(ctx, tenantA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != inA.ID {
		t.Fatalf("tenant-a list = %d rows, want only %s", len(listed), inA.ID)
	}

	// An update from the wrong tenant changes nothing.
	inB.Name = "renamed by tenant a"
	if err := repo.Update(ctx, tenantA, inB); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant update = %v, want not found", err)
	}
	unchanged, err := repo.GetByID(ctx, tenantB, inB.ID)
	if err != nil || unchanged.Name != "bob" {
		t.Fatalf("cross-tenant update mutated the row: %+v %v", unchanged, err)
	}

	// An own-tenant update writes the mutable fields and cannot move the user to another tenant.
	inA.Name, inA.Disabled, inA.TenantID = "alice renamed", true, tenantB.String()
	inA.APIKeyHash = "rotated-" + suffix
	if err := repo.Update(ctx, tenantA, inA); err != nil {
		t.Fatalf("own-tenant update: %v", err)
	}
	after, err := repo.GetByID(ctx, tenantA, inA.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if after.Name != "alice renamed" || !after.Disabled || after.APIKeyHash != "rotated-"+suffix {
		t.Errorf("update did not persist: %+v", after)
	}
	if after.TenantID != tenantA.String() {
		t.Errorf("update moved the user to tenant %q", after.TenantID)
	}
}
