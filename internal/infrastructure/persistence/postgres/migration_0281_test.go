package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
)

// TestMigration0281EnforcesCredentialsTenantRLS (#1687): after the contract migration, credentials carry
// forced row-level security and a NOT NULL tenant. A row whose engagement was deleted before 0277 is gone,
// a feed-provider key in the 'default' namespace keeps its tenant, and the vault still works inside a bound
// tenant while another tenant, or no tenant, sees nothing.
func TestMigration0281EnforcesCredentialsTenantRLS(t *testing.T) {
	const tenantA, tenantB, engA = "cred-rls-a", "cred-rls-b", "cred-rls-eng-a"
	pool, owner := ownershipMigrationDatabase(t, 280, 0, func(db *sql.DB) {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants(id,name) VALUES ($1,$1),($2,$2)`, []any{tenantA, tenantB}},
			// engagements forces row-level security on its owner too, so the seed binds the tenant.
			{`WITH bound AS (SELECT set_config('app.current_tenant', $2, false))
			  INSERT INTO engagements(id,tenant_id,name) SELECT $1,$2,'a' FROM bound`, []any{engA, tenantA}},
			{`SELECT set_config('app.current_tenant', '', false)`, nil},
			{`INSERT INTO credentials(tenant_id,engagement_id,name,ciphertext) VALUES ($1,$2,'kept','x')`, []any{tenantA, engA}},
			// Unattributable: its engagement no longer exists. The trigger refuses it, so plant it with the
			// trigger off, as a row that predates 0277 would sit.
			{`ALTER TABLE credentials DISABLE TRIGGER USER`, nil},
			{`INSERT INTO credentials(engagement_id,name,ciphertext) VALUES ('deleted-engagement','orphan','x'),('default','feed-key','x')`, nil},
			{`ALTER TABLE credentials ENABLE TRIGGER USER`, nil},
		} {
			if _, err := db.Exec(q.sql, q.args...); err != nil {
				t.Fatalf("seed %q: %v", q.sql, err)
			}
		}
	})

	var orphans, feedTenant, nullable string
	if err := owner.QueryRow(`SELECT count(*)::text FROM credentials WHERE name='orphan'`).Scan(&orphans); err != nil || orphans != "0" {
		t.Fatalf("orphan rows = %s (%v), want 0", orphans, err)
	}
	if err := owner.QueryRow(`SELECT is_nullable FROM information_schema.columns WHERE table_name='credentials' AND column_name='tenant_id'`).Scan(&nullable); err != nil || nullable != "NO" {
		t.Fatalf("credentials.tenant_id nullable = %q (%v), want NO", nullable, err)
	}
	ctx := context.Background()
	if err := WithTenant(ctx, pool, "default", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id FROM credentials WHERE engagement_id='default' AND name='feed-key'`).Scan(&feedTenant)
	}); err != nil || feedTenant != "default" {
		t.Fatalf("feed key tenant = %q (%v), want default", feedTenant, err)
	}

	var forced bool
	if err := owner.QueryRow(`SELECT relforcerowsecurity FROM pg_class WHERE relname='credentials'`).Scan(&forced); err != nil || !forced {
		t.Fatalf("credentials forced RLS = %v (%v)", forced, err)
	}
	var unbound int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM credentials`).Scan(&unbound); err != nil || unbound != 0 {
		t.Fatalf("an unbound read saw %d credentials (%v), want 0", unbound, err)
	}
	var visibleToB int
	if err := WithTenant(ctx, pool, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE engagement_id=$1`, engA).Scan(&visibleToB)
	}); err != nil || visibleToB != 0 {
		t.Fatalf("tenant B saw %d of tenant A's credentials (%v)", visibleToB, err)
	}

	cipher, err := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	v := vault.NewPostgresVault(pool, cipher)
	inA := shared.WithTenant(ctx, shared.ID(tenantA))
	if err := v.Put(inA, shared.ID(engA), "token", []byte("a-secret")); err != nil {
		t.Fatalf("put under forced RLS: %v", err)
	}
	if got, err := v.Resolve(inA, shared.ID(engA), "token"); err != nil || string(got) != "a-secret" {
		t.Fatalf("resolve under forced RLS = %q, %v", got, err)
	}
	if _, err := v.Resolve(shared.WithTenant(ctx, shared.ID(tenantB)), shared.ID(engA), "token"); err == nil {
		t.Fatal("tenant B resolved tenant A's credential")
	}
}

// TestMigration0281RefusesAnAttributableRowWithoutTenant: a NULL-tenant row whose engagement still exists
// means the 0277 trigger was bypassed. The migration must stop rather than delete a usable secret.
func TestMigration0281RefusesAnAttributableRowWithoutTenant(t *testing.T) {
	const tenant, eng = "cred-guard", "cred-guard-eng"
	isolated := newIsolatedMigrationDB(t, 281, 280)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES ($1,$1)`, []any{tenant}},
		{`WITH bound AS (SELECT set_config('app.current_tenant', $2, false))
		  INSERT INTO engagements(id,tenant_id,name) SELECT $1,$2,'g' FROM bound`, []any{eng, tenant}},
		{`ALTER TABLE credentials DISABLE TRIGGER USER`, nil},
		{`INSERT INTO credentials(engagement_id,name,ciphertext) VALUES ($1,'live','x')`, []any{eng}},
		{`ALTER TABLE credentials ENABLE TRIGGER USER`, nil},
	} {
		if _, err := isolated.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("seed %q: %v", q.sql, err)
		}
	}
	err := goose.UpTo(isolated.db, ".", 281)
	if err == nil || !strings.Contains(err.Error(), "migration 0281") {
		t.Fatalf("migrate to 281: err = %v, want the 0281 guard to stop it", err)
	}
	var kept int
	if err := isolated.db.QueryRow(`SELECT count(*) FROM credentials WHERE engagement_id=$1`, eng).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("the live secret was not kept: %d (%v)", kept, err)
	}
}
