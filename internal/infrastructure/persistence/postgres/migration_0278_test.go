package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
)

// TestMigration0278APIKeyLookupSurvivesATenantPolicy pins the one users read that cannot bind a
// tenant. Under the tenant policy the contract release adds, a direct read with no tenant sees no
// user; the lookup function, which runs as the owner, still resolves the key.
func TestMigration0278APIKeyLookupSurvivesATenantPolicy(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	stamp := time.Now().UTC().Format("150405.000000000")
	tenant := "key-lookup-" + stamp
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	hash := "keyhash-" + stamp
	repo := postgres.NewUserRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	u := &user.User{ID: shared.ID("u-key-" + stamp), Name: "Key holder", Role: user.RoleConsultant, APIKeyHash: hash, TenantID: tenant, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	if err := repo.Create(shared.WithTenant(ctx, shared.ID(tenant)), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	got, err := repo.GetByAPIKeyHash(ctx, hash)
	if err != nil || got.ID != u.ID || got.TenantID != tenant {
		t.Fatalf("lookup = %+v, %v", got, err)
	}
	if _, err := repo.GetByAPIKeyHash(ctx, ""); err == nil {
		t.Fatal("an empty digest resolved a user")
	}
	// The repository's tenant-scoped read still works without a bound transaction.
	if byID, err := repo.GetByID(ctx, shared.ID(tenant), u.ID); err != nil || byID.ID != u.ID {
		t.Fatalf("get by id = %+v, %v", byID, err)
	}

	// Rehearse the contract policy inside a transaction that is rolled back.
	const role = "user_key_lookup_probe_role"
	for _, stmt := range []string{`DROP OWNED BY ` + role, `DROP ROLE IF EXISTS ` + role, `CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`} {
		_, _ = pool.Exec(ctx, stmt)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, stmt := range []string{
		`ALTER TABLE users ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE users FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY users_rehearsal ON users USING (ownership_tenant_id = synapse_current_tenant())`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON users TO ` + role,
		`GRANT EXECUTE ON FUNCTION synapse_user_by_api_key_hash(TEXT) TO ` + role,
		`SET LOCAL ROLE ` + role,
	} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	var direct int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE api_key_hash=$1`, hash).Scan(&direct); err != nil {
		t.Fatalf("direct read: %v", err)
	}
	if direct != 0 {
		t.Fatalf("a read with no tenant bound saw %d users under the policy", direct)
	}
	var viaFunction string
	if err := tx.QueryRow(ctx, `SELECT id FROM synapse_user_by_api_key_hash($1)`, hash).Scan(&viaFunction); err != nil || viaFunction != u.ID.String() {
		t.Fatalf("lookup function under the policy = %q, %v", viaFunction, err)
	}
}

// TestMigration0278RepositoryResolvesKeysOnlyThroughTheFunction drives the repository, not the function:
// under a role that may execute the lookup but may not read users at all, GetByAPIKeyHash still resolves
// the key. A repository that read users directly again would be refused.
func TestMigration0278RepositoryResolvesKeysOnlyThroughTheFunction(t *testing.T) {
	pool := auditTxTestPool(t)
	ctx := context.Background()
	stamp := time.Now().UTC().Format("150405.000000000")
	tenant := "key-repo-" + stamp
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	hash := "keyhash-repo-" + stamp
	now := time.Now().UTC().Truncate(time.Microsecond)
	u := &user.User{ID: shared.ID("u-key-repo-" + stamp), Name: "Key holder", Role: user.RoleConsultant, APIKeyHash: hash, TenantID: tenant, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	if err := postgres.NewUserRepository(pool).Create(shared.WithTenant(ctx, shared.ID(tenant)), u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	const role = "user_key_repo_probe_role"
	for _, stmt := range []string{
		`DROP OWNED BY ` + role,
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT EXECUTE ON FUNCTION synapse_user_by_api_key_hash(TEXT) TO ` + role,
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	cfg, err := pgxpool.ParseConfig(os.Getenv("SYNAPSE_TEST_DB_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET ROLE `+role)
		return err
	}
	restricted, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)

	var direct int
	if err := restricted.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&direct); err == nil {
		t.Fatal("the probe role can read users directly, so this test would prove nothing")
	}
	got, err := postgres.NewUserRepository(restricted).GetByAPIKeyHash(ctx, hash)
	if err != nil || got.ID != u.ID {
		t.Fatalf("repository lookup under a role without users access = %+v, %v", got, err)
	}
}
