package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	aupuc "github.com/KKloudTarus/synapse-ce/internal/usecase/aup"
)

type aupTestClock struct{ now time.Time }

func (c aupTestClock) Now() time.Time { return c.now }

func runtimeAUPPool(ctx context.Context, adminPool *pgxpool.Pool, dsn, role string) (*pgxpool.Pool, error) {
	for _, statement := range []string{
		"CREATE ROLE " + role + " LOGIN PASSWORD 'test-password' NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA public TO " + role,
		"GRANT SELECT, INSERT ON audit_log TO " + role,
		"GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO " + role,
	} {
		if _, err := adminPool.Exec(ctx, statement); err != nil {
			return nil, err
		}
	}
	runtimeConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	runtimeConfig.ConnConfig.User = role
	runtimeConfig.ConnConfig.Password = "test-password"
	runtimeConfig.MaxConns = 1
	return pgxpool.NewWithConfig(ctx, runtimeConfig)
}

func TestAUPStoreAndAuditLog(t *testing.T) {
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
	t.Cleanup(pool.Close)

	// --- AUP acceptance ---
	ver := "test-" + randHex(t)
	store := NewAUPStore(pool)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM aup_acceptances WHERE policy_version=$1", ver) })

	if ok, err := store.Accepted(ctx, ver); err != nil || ok {
		t.Fatalf("Accepted before save = %v (err %v), want false", ok, err)
	}
	acc := aup.Acceptance{Version: ver, Actor: "operator", AcceptedAt: time.Now().UTC()}
	if err := store.Save(ctx, acc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save(ctx, acc); err != nil { // idempotent re-accept
		t.Fatalf("Save (idempotent): %v", err)
	}
	if ok, err := store.Accepted(ctx, ver); err != nil || !ok {
		t.Fatalf("Accepted after save = %v (err %v), want true", ok, err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aup_acceptances WHERE policy_version=$1", ver).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("want 1 acceptance row (idempotent), got %d", n)
	}

	// --- AUP acceptance audit under a NOSUPERUSER, NOBYPASSRLS runtime role ---
	// uniqueProbeRole owns the drop and opens its own connection for it: this test closes its
	// pools with plain defers, and Go runs those before t.Cleanup, so a cleanup using them ran
	// against a closed pool and leaked a cluster-global role on every run.
	role := uniqueProbeRole(t, dsn, "aup_runtime")
	runtimePool, err := runtimeAUPPool(ctx, pool, dsn, role)
	if err != nil {
		t.Fatalf("runtime role setup: %v", err)
	}
	defer runtimePool.Close()

	tenantID := shared.ID("tenant-aup-" + randHex(t))
	tenantCtx := shared.WithTenant(ctx, tenantID)
	version := "aup-" + randHex(t)
	svc := aupuc.NewService(NewAUPStore(pool), NewAuditLog(runtimePool), aupTestClock{now: time.Now().UTC()}, version)
	if err := svc.Accept(tenantCtx, "operator", version); err != nil {
		t.Fatalf("runtime role AUP acceptance: %v", err)
	}
	var storedTenant string
	var hashVersion int
	if err := pool.QueryRow(ctx, "SELECT tenant_id, hash_version FROM audit_log WHERE action='aup.accept' AND target=$1", "aup:"+version).Scan(&storedTenant, &hashVersion); err != nil {
		t.Fatalf("read tenant-bound AUP audit row: %v", err)
	}
	if storedTenant != tenantID.String() || hashVersion != 2 {
		t.Fatalf("audit row tenant/version = %q/%d, want %q/2", storedTenant, hashVersion, tenantID)
	}
	// Migration rollback tests share this database. Remove this test's v2 chain
	// row after exercising the runtime path because migration 0085 correctly
	// refuses to roll back while any v2 history exists.
	t.Cleanup(func() {
		bg := context.Background()
		conn, err := pool.Acquire(bg)
		if err != nil {
			t.Errorf("acquire conn for audit cleanup: %v", err)
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(bg, "SET session_replication_role = replica"); err != nil {
			t.Errorf("disable audit append-only trigger: %v", err)
			return
		}
		defer func() { _, _ = conn.Exec(bg, "SET session_replication_role = origin") }()
		if _, err := conn.Exec(bg, "DELETE FROM audit_log WHERE action='aup.accept' AND target=$1", "aup:"+version); err != nil {
			t.Errorf("remove test audit row: %v", err)
		}
	})
}
