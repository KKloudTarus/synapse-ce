package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestMigration0282EnforcesUsersTenantRLS (#1697): users carries forced row-level security keyed on
// ownership_tenant_id. A runtime role sees only the bound tenant's users, the default tenant's users
// (stored with tenant_id '') under 'default', nothing unbound; the owner functions still answer across
// tenants.
func TestMigration0282EnforcesUsersTenantRLS(t *testing.T) {
	const tenantA, tenantB = "users-rls-a", "users-rls-b"
	pool, owner := ownershipMigrationDatabase(t, 281, 0, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES ($1,$1),($2,$2)`, tenantA, tenantB); err != nil {
			t.Fatal(err)
		}
		// The legacy writer fence (0213) requires the tenant bound for every users write.
		for _, u := range []struct{ bind, stored, id, hash string }{
			{"default", "", "operator", "hash-operator"},
			{tenantA, tenantA, "alice", "hash-alice"},
			{tenantB, tenantB, "bob", "hash-bob"},
		} {
			if _, err := db.Exec(`WITH bound AS (SELECT set_config('app.current_tenant', $1, false))
				INSERT INTO users(id,name,role,api_key_hash,tenant_id) SELECT $2,$2,'admin',$3,$4 FROM bound`, u.bind, u.id, u.hash, u.stored); err != nil {
				t.Fatalf("seed %s: %v", u.id, err)
			}
		}
	})
	ctx := context.Background()
	var runtimeRole string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&runtimeRole); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"synapse_user_by_api_key_hash(TEXT)", "synapse_users_api_key_hash_counts(TEXT[])"} {
		if _, err := owner.Exec(`GRANT EXECUTE ON FUNCTION ` + fn + ` TO ` + pgx.Identifier{runtimeRole}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		// Runs before the fixture drops the runtime role, which a remaining grant would block.
		revoke := `REVOKE EXECUTE ON FUNCTION ` + fn + ` FROM ` + pgx.Identifier{runtimeRole}.Sanitize()
		t.Cleanup(func() {
			if _, err := owner.Exec(revoke); err != nil {
				t.Error(err)
			}
		})
	}
	visible := func(tenant string) map[string]bool {
		out := map[string]bool{}
		err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id FROM users`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				out[id] = true
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("list as %q: %v", tenant, err)
		}
		return out
	}
	if got := visible("default"); !got["operator"] || len(got) != 1 {
		t.Fatalf("default tenant sees %v, want only operator", got)
	}
	if got := visible(tenantA); !got["alice"] || len(got) != 1 {
		t.Fatalf("tenant A sees %v, want only alice", got)
	}
	if got := visible(""); len(got) != 0 {
		t.Fatalf("an unbound read sees %v, want nothing", got)
	}

	if err := WithTenant(ctx, pool, tenantA, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET name='renamed' WHERE id='bob'`)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Fatalf("tenant A updated %d of tenant B's users", tag.RowsAffected())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err := WithTenant(ctx, pool, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES ('mallory','m','admin','hash-m',$1)`, tenantB)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || (pgErr.Code != "42501" && pgErr.Code != "SYN01") {
		t.Fatalf("insert into another tenant: err = %v, want a policy or writer-fence refusal", err)
	}

	// The owner policy admits the table's owner, so the crossing functions must share it.
	var mismatched int
	if err := owner.QueryRow(`SELECT count(*) FROM pg_proc p, pg_class c
		WHERE c.oid = 'public.users'::regclass AND p.proowner <> c.relowner
		  AND p.proname IN ('synapse_user_by_api_key_hash','synapse_users_api_key_hash_counts')`).Scan(&mismatched); err != nil || mismatched != 0 {
		t.Fatalf("%d crossing functions are not owned by the users owner (%v)", mismatched, err)
	}
	// The owner functions answer without a bound tenant: authentication and the backfill's count.
	var id, tenant string
	if err := pool.QueryRow(ctx, `SELECT id, tenant_id FROM synapse_user_by_api_key_hash('hash-bob')`).Scan(&id, &tenant); err != nil || id != "bob" || tenant != tenantB {
		t.Fatalf("auth lookup = %q/%q (%v), want bob in tenant B", id, tenant, err)
	}
	var holders int
	if err := pool.QueryRow(ctx, `SELECT holders FROM synapse_users_api_key_hash_counts(ARRAY['hash-alice'])`).Scan(&holders); err != nil || holders != 1 {
		t.Fatalf("hash holder count = %d (%v), want 1", holders, err)
	}
}
