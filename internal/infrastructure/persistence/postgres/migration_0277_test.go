package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
)

// TestMigration0277CredentialsCarryTheirTenant pins the expand half of #1687: every credential row
// names its tenant, the vault reads and writes only inside the caller's tenant, and a row written by
// a binary that does not know the column still gets the owning engagement's tenant.
func TestMigration0277CredentialsCarryTheirTenant(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	stamp := time.Now().UTC().Format("150405.000000000")
	tenantA, tenantB := "cred-a-"+stamp, "cred-b-"+stamp
	engA, engB := "cred-eng-a-"+stamp, "cred-eng-b-"+stamp
	for _, seed := range []struct{ tenant, eng string }{{tenantA, engA}, {tenantB, engB}} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, seed.tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ($1,$2,'cred')`, seed.eng, seed.tenant); err != nil {
			t.Fatalf("seed engagement: %v", err)
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	v := vault.NewPostgresVault(pool, cipher)
	inA := shared.WithTenant(ctx, shared.ID(tenantA))
	inB := shared.WithTenant(ctx, shared.ID(tenantB))

	if err := v.Put(inA, shared.ID(engA), "token", []byte("a-secret")); err != nil {
		t.Fatalf("put in tenant A: %v", err)
	}
	var stored string
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM credentials WHERE engagement_id=$1 AND name='token'`, engA).Scan(&stored); err != nil || stored != tenantA {
		t.Fatalf("stored tenant = %q (%v), want %q", stored, err, tenantA)
	}
	if got, err := v.Resolve(inA, shared.ID(engA), "token"); err != nil || string(got) != "a-secret" {
		t.Fatalf("resolve in tenant A = %q, %v", got, err)
	}

	// Tenant B naming A's engagement sees nothing, lists nothing, deletes nothing.
	if _, err := v.Resolve(inB, shared.ID(engA), "token"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant B resolved tenant A's credential: %v", err)
	}
	if list, err := v.List(inB, shared.ID(engA)); err != nil || len(list) != 0 {
		t.Fatalf("tenant B listed %d of tenant A's credentials (%v)", len(list), err)
	}
	if err := v.Delete(inB, shared.ID(engA), "token"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant B deleted tenant A's credential: %v", err)
	}
	// Nor can B overwrite it through the (engagement_id, name) upsert: the trigger refuses the tenant.
	if err := v.Put(inB, shared.ID(engA), "token", []byte("forged")); err == nil {
		t.Fatal("tenant B overwrote tenant A's credential")
	}
	if got, _ := v.Resolve(inA, shared.ID(engA), "token"); string(got) != "a-secret" {
		t.Fatalf("tenant A's credential changed to %q", got)
	}

	// A context without a tenant is refused, as by every other tenant-scoped store.
	if _, err := v.Resolve(ctx, shared.ID(engA), "token"); err == nil || !strings.Contains(err.Error(), "tenant context is required") {
		t.Fatalf("an unscoped resolve was not refused: %v", err)
	}

	// A binary that predates the column inserts without it; the trigger fills the owner's tenant.
	if _, err := pool.Exec(ctx, `INSERT INTO credentials (engagement_id, name, ciphertext) VALUES ($1,'legacy','x')`, engB); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM credentials WHERE engagement_id=$1 AND name='legacy'`, engB).Scan(&stored); err != nil || stored != tenantB {
		t.Fatalf("legacy row tenant = %q (%v), want %q", stored, err, tenantB)
	}
	// And a row naming an engagement no tenant owns is refused rather than stored unowned.
	if _, err := pool.Exec(ctx, `INSERT INTO credentials (engagement_id, name, ciphertext) VALUES ('no-such-engagement-'||$1,'x','x')`, stamp); err == nil {
		t.Fatal("a credential for an unknown engagement was stored")
	}

	// Rows the backfill could not attribute are removed by 0281, which also makes tenant_id NOT NULL;
	// TestMigration0281EnforcesCredentialsTenantRLS covers them.

	// The vulnerability feed keys live under the default tenant's "default" namespace.
	inDefault := shared.WithTenant(ctx, shared.DefaultTenant)
	if err := v.Put(inDefault, shared.DefaultTenant, "feed-key-"+stamp, []byte("k")); err != nil {
		t.Fatalf("put feed key: %v", err)
	}
	if got, err := v.Resolve(inDefault, shared.DefaultTenant, "feed-key-"+stamp); err != nil || string(got) != "k" {
		t.Fatalf("resolve feed key = %q, %v", got, err)
	}
}
