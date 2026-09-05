package postgres

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func skTestKey(t *testing.T, agent shared.ID, nb, na time.Time) fleetagent.AgentSigningKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	k, err := fleetagent.NewSigningKey(agent, fleetagent.PurposeDetectionBatch, pub, nb, na)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	return k
}

func TestAgentSigningKeyRepo(t *testing.T) {
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

	id := randHex(t)
	tenantA, tenantB := shared.ID("sk-a-"+id), shared.ID("sk-b-"+id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantA.String(), tenantB.String()); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM agent_signing_keys WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DROP OWNED BY sk_runtime`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS sk_runtime`)
	})

	repo := NewAgentSigningKeyRepository(pool)
	tctxA := shared.WithTenant(ctx, tenantA)

	older := skTestKey(t, "agent:1", time.Unix(1000, 0), time.Unix(2000, 0))
	newer := skTestKey(t, "agent:1", time.Unix(1500, 0), time.Unix(2500, 0))
	if err := repo.Register(tctxA, older); err != nil {
		t.Fatalf("register older: %v", err)
	}
	if err := repo.Register(tctxA, newer); err != nil {
		t.Fatalf("register newer: %v", err)
	}
	// Idempotent on identity; anti-rollback on a re-pointed KeyID.
	if err := repo.Register(tctxA, older); err != nil {
		t.Errorf("identical re-register must be a no-op, got %v", err)
	}
	rebind := older
	rebind.NotAfter = time.Unix(9999, 0)
	if err := repo.Register(tctxA, rebind); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("re-pointing a KeyID must conflict, got %v", err)
	}

	got, err := repo.ResolveSigningKey(tctxA, "agent:1", older.KeyID)
	if err != nil || got.KeyID != older.KeyID || !got.PublicKey.Equal(older.PublicKey) {
		t.Fatalf("resolve older: got %+v err %v", got, err)
	}
	if _, err := repo.ResolveSigningKey(tctxA, "agent:1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown key must be ErrNotFound, got %v", err)
	}
	list, _ := repo.ListByAgent(tctxA, "agent:1")
	if len(list) != 2 || list[0].KeyID != newer.KeyID {
		t.Fatalf("ListByAgent must return newest-first, got %+v", list)
	}

	// Revoke is monotonic.
	if err := repo.Revoke(tctxA, "agent:1", older.KeyID, time.Unix(1800, 0)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := repo.Revoke(tctxA, "agent:1", older.KeyID, time.Unix(1900, 0)); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	got, _ = repo.ResolveSigningKey(tctxA, "agent:1", older.KeyID)
	if !got.RevokedAt.Equal(time.Unix(1800, 0).UTC()) {
		t.Errorf("revocation must be monotonic, got %v", got.RevokedAt)
	}
	if err := repo.Revoke(tctxA, "agent:1", "nope", time.Unix(1800, 0)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("revoking an unknown key must be ErrNotFound, got %v", err)
	}

	// RLS isolation under a NOSUPERUSER NOBYPASSRLS role (the pool superuser bypasses RLS): tenant B must
	// not observe tenant A's keys. tenant B has none of its own, so it must count zero.
	role := "sk_runtime"
	for _, q := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON agent_signing_keys TO ` + role,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("prepare rls role: %v", err)
		}
	}
	countAs := func(tenant shared.ID) int {
		var n int
		tc := shared.WithTenant(context.Background(), tenant)
		if err := WithTenant(tc, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(tc, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(tc, `SELECT count(*) FROM agent_signing_keys`).Scan(&n)
		}); err != nil {
			t.Fatalf("count as %s: %v", tenant, err)
		}
		return n
	}
	if got := countAs(tenantB); got != 0 {
		t.Errorf("tenant B sees %d of tenant A's signing keys; RLS is not isolating", got)
	}
	if got := countAs(tenantA); got != 2 {
		t.Errorf("tenant A sees %d of its own keys, want 2; RLS is over-filtering", got)
	}
}
