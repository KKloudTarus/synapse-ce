package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Integration test – runs only when SYNAPSE_TEST_DB_DSN points at a Postgres.
func TestEngagementRepository(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	repo := NewEngagementRepository(pool)
	id := shared.ID("it-" + randHex(t))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", id.String()) })

	e, err := engagement.New(id, "", "integration", "acme", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	e.Scope = engagement.Scope{
		InScope:    []engagement.Target{{Kind: engagement.TargetRepo, Value: "/repo"}},
		OutOfScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "secret.io"}},
	}
	if err := repo.Create(ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "integration" || got.Client != "acme" {
		t.Errorf("got %+v", got)
	}
	if !got.Scope.Allows("/repo") || got.Scope.Allows("secret.io") {
		t.Errorf("scope round-trip wrong: %+v", got.Scope)
	}

	// Simulate legacy rows written before canonical scope storage. Valid values are
	// canonicalized in memory; invalid rows make the engagement unloadable rather
	// than silently dropping an out-of-scope restriction.
	if _, err := pool.Exec(ctx,
		`UPDATE scope_targets SET value='Secret.IO.' WHERE engagement_id=$1 AND in_scope=false`,
		id.String()); err != nil {
		t.Fatalf("seed legacy scope spelling: %v", err)
	}
	got, err = repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("get with canonicalizable legacy scope: %v", err)
	}
	if len(got.Scope.OutOfScope) != 1 || got.Scope.OutOfScope[0].Value != "secret.io" {
		t.Fatalf("legacy scope was not canonicalized: %+v", got.Scope.OutOfScope)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE scope_targets SET value='not a host' WHERE engagement_id=$1 AND in_scope=false`,
		id.String()); err != nil {
		t.Fatalf("seed invalid legacy scope: %v", err)
	}
	if _, err := repo.GetByID(ctx, id); err == nil {
		t.Fatal("invalid persisted scope must fail engagement loading")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE scope_targets SET value='secret.io' WHERE engagement_id=$1 AND in_scope=false`,
		id.String()); err != nil {
		t.Fatalf("restore scope row: %v", err)
	}

	list, err := repo.List(ctx, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, x := range list {
		if x.ID == id {
			found = true
			if !x.Scope.Allows("/repo") {
				t.Error("List should load each engagement's scope (in-scope /repo not allowed)")
			}
		}
	}
	if !found {
		t.Errorf("created engagement %s not in list", id)
	}

	if _, err := repo.GetByID(ctx, shared.ID("does-not-exist")); err != shared.ErrNotFound {
		t.Errorf("missing GetByID = %v, want ErrNotFound", err)
	}

	// nil authorization window round-trips as nil
	if got.AuthorizedFrom != nil || got.AuthorizedTo != nil {
		t.Errorf("nil window should stay nil: from=%v to=%v", got.AuthorizedFrom, got.AuthorizedTo)
	}

	// a set authorization window round-trips
	id2 := shared.ID("it-" + randHex(t))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", id2.String()) })
	from := time.Now().UTC().Truncate(time.Second)
	to := from.Add(48 * time.Hour)
	e2, err := engagement.New(id2, "", "windowed", "", from)
	if err != nil {
		t.Fatal(err)
	}
	e2.AuthorizedFrom = &from
	e2.AuthorizedTo = &to
	if err := repo.Create(ctx, e2); err != nil {
		t.Fatalf("create windowed: %v", err)
	}
	got2, err := repo.GetByID(ctx, id2)
	if err != nil {
		t.Fatal(err)
	}
	if got2.AuthorizedFrom == nil || !got2.AuthorizedFrom.Equal(from) ||
		got2.AuthorizedTo == nil || !got2.AuthorizedTo.Equal(to) {
		t.Errorf("auth window round-trip: got from=%v to=%v, want %v / %v", got2.AuthorizedFrom, got2.AuthorizedTo, from, to)
	}

	// tenant isolation + ownership round-trip against real Postgres
	// (migrations 0035 users.tenant_id, 0036 engagements.created_by/updated_by).
	tenA := shared.ID("tenant-" + randHex(t))
	tenB := shared.ID("tenant-" + randHex(t))
	// tenant_id is FK-constrained to tenants(id); seed both tenant rows first. Cleanups run
	// LIFO, so registering these before the engagement cleanup means the engagement (which
	// references tenA) is deleted before its tenant row.
	for _, tn := range []string{tenA.String(), tenB.String()} {
		if _, err := pool.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1,$1)", tn); err != nil {
			t.Fatalf("seed tenant %s: %v", tn, err)
		}
		tn := tn
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM tenants WHERE id=$1", tn) })
	}
	idA := shared.ID("it-" + randHex(t))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", idA.String()) })
	ea, err := engagement.New(idA, tenA, "tenantA", "acme", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ea.Audit.CreatedBy = "alice"
	ea.Audit.UpdatedBy = "alice"
	if err := repo.Create(ctx, ea); err != nil {
		t.Fatalf("create tenantA: %v", err)
	}
	// Owner (created_by/updated_by) round-trips.
	if g, err := repo.GetByID(ctx, idA); err != nil || g.Audit.CreatedBy != "alice" || g.Audit.UpdatedBy != "alice" {
		t.Fatalf("ownership round-trip: g=%+v err=%v", g, err)
	}
	// Same tenant reads it; a zero tenant (single-tenant / admin) reads it; tenant B cannot
	// (ErrNotFound – existence is not revealed cross-tenant).
	if _, err := repo.GetByIDInTenant(ctx, tenA, idA); err != nil {
		t.Errorf("same-tenant GetByIDInTenant: %v", err)
	}
	if _, err := repo.GetByIDInTenant(ctx, "", idA); err != nil {
		t.Errorf("zero-tenant GetByIDInTenant must see any row: %v", err)
	}
	if _, err := repo.GetByIDInTenant(ctx, tenB, idA); err != shared.ErrNotFound {
		t.Errorf("cross-tenant GetByIDInTenant = %v, want ErrNotFound", err)
	}
	// List is tenant-scoped: tenant B's list does not include tenant A's engagement.
	lb, err := repo.List(ctx, tenB)
	if err != nil {
		t.Fatalf("list tenantB: %v", err)
	}
	for _, x := range lb {
		if x.ID == idA {
			t.Errorf("List(tenantB) must not include tenant A's engagement %s", idA)
		}
	}
	// Update must NOT change the owner (created_by is immutable) but must update updated_by.
	cp := *ea
	cp.Audit.UpdatedBy = "bob"
	if err := repo.Update(ctx, &cp); err != nil {
		t.Fatalf("update tenantA: %v", err)
	}
	if g, err := repo.GetByID(ctx, idA); err != nil || g.Audit.CreatedBy != "alice" || g.Audit.UpdatedBy != "bob" {
		t.Fatalf("after update, owner must be immutable + updated_by=bob: g=%+v err=%v", g, err)
	}
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
