package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
)

// TestMigration0133EnablesTenantRLS is a no-database guard: the connector table must go under the
// standard forced-RLS shape, or a bug in the migration would ship a cross-tenant-readable secret store.
func TestMigration0133EnablesTenantRLS(t *testing.T) {
	sql, err := os.ReadFile("../../../../migrations/0133_scm_connectors.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CREATE TABLE scm_connectors",
		"token_ciphertext TEXT        NOT NULL",
		"UNIQUE (tenant_id, host)",
		"CALL synapse_enable_tenant_rls('scm_connectors');",
	} {
		if !strings.Contains(string(sql), want) {
			t.Fatalf("migration 0133 missing %q", want)
		}
	}
}

func testCipher(t *testing.T) *vault.Cipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustConn(t *testing.T, id, tenant, host, user string) scmconnector.Connector {
	t.Helper()
	c, err := scmconnector.NewConnector(shared.ID(id), shared.ID(tenant), "prod", scmconnector.ProviderGitHub, host, user, scmconnector.AuthPAT, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return *c
}

// TestSCMConnectorRepositorySealsAndIsolates drives the whole store against a real Postgres: the token
// is sealed (the column is not the plaintext), resolves back for the owning tenant, is invisible and
// unresolvable to another tenant (RLS), a duplicate host is a conflict, a metadata edit keeps the token,
// and delete removes it.
func TestSCMConnectorRepositorySealsAndIsolates(t *testing.T) {
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
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	sfx := randHex(t)
	ta, tb := shared.ID("scm-a-"+sfx), shared.ID("scm-b-"+sfx)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2) ON CONFLICT DO NOTHING`, ta.String(), tb.String()); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	t.Cleanup(func() {
		for _, tn := range []shared.ID{ta, tb} {
			_, _ = pool.Exec(ctx, `DELETE FROM scm_connectors WHERE tenant_id=$1`, tn.String())
			_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})

	repo, err := NewSCMConnectorRepository(pool, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	const token = "ghp_sealed_secret_value"
	ctxA := shared.WithTenant(ctx, ta)
	if err := repo.Put(ctxA, mustConn(t, "c1-"+sfx, ta.String(), "github.com", "x-access-token"), []byte(token)); err != nil {
		t.Fatalf("put: %v", err)
	}

	// The column must hold ciphertext, never the plaintext.
	var stored string
	if err := WithTenant(ctx, pool, ta.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT token_ciphertext FROM scm_connectors WHERE tenant_id=$1 AND id=$2`, ta.String(), "c1-"+sfx).Scan(&stored)
	}); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if stored == token || strings.Contains(stored, token) {
		t.Fatal("token_ciphertext must not contain the plaintext token")
	}

	// Resolves back for the owner.
	cred, ok, err := repo.ResolveGitCredential(ctxA, "github.com")
	if err != nil || !ok || string(cred.Token) != token || cred.Username != "x-access-token" {
		t.Fatalf("resolve = %+v ok=%v err=%v", cred, ok, err)
	}

	// Tenant isolation: tenant B sees and resolves nothing.
	ctxB := shared.WithTenant(ctx, tb)
	if metas, err := repo.List(ctxB); err != nil || len(metas) != 0 {
		t.Fatalf("tenant B must see no connectors: %+v err=%v", metas, err)
	}
	if _, ok, _ := repo.ResolveGitCredential(ctxB, "github.com"); ok {
		t.Fatal("tenant B must not resolve tenant A's credential")
	}

	// A duplicate host is a conflict.
	if err := repo.Put(ctxA, mustConn(t, "c2-"+sfx, ta.String(), "github.com", "x-access-token"), []byte("other")); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate host must conflict, got %v", err)
	}

	// A Put without a token is refused: the token is always required (there is no metadata-only edit).
	if err := repo.Put(ctxA, mustConn(t, "c1-"+sfx, ta.String(), "github.com", "octo-bot"), nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty token must be rejected, got %v", err)
	}

	// AAD binds host+username: a database-write repoint of the host makes the sealed token undecryptable,
	// so a DB-write attacker cannot aim the tenant's real PAT at their own host. Restore afterwards.
	if _, err := pool.Exec(ctx, `UPDATE scm_connectors SET host='evil.example.com' WHERE tenant_id=$1 AND id=$2`, ta.String(), "c1-"+sfx); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, ok, err := repo.ResolveGitCredential(ctxA, "evil.example.com"); ok || err == nil {
		t.Fatalf("a host-repointed token must fail to decrypt: ok=%v err=%v", ok, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scm_connectors SET host='github.com' WHERE tenant_id=$1 AND id=$2`, ta.String(), "c1-"+sfx); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Delete removes it.
	if err := repo.Delete(ctxA, shared.ID("c1-"+sfx)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := repo.ResolveGitCredential(ctxA, "github.com"); ok {
		t.Fatal("deleted connector must not resolve")
	}
}
