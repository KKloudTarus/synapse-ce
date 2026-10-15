package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	aupuc "github.com/KKloudTarus/synapse-ce/internal/usecase/aup"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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

func freshAuditChainPool(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	dsn := isolatedIntegrationDatabase(t, ctx, sharedDSN)
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate isolated audit database: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect isolated audit database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, dsn
}

func TestAuditFirstObservationUsesGlobalV1ChainWhenRLSInactive(t *testing.T) {
	pool, _ := freshAuditChainPool(t)
	ctx := context.Background()
	var rlsEnforced bool
	if err := pool.QueryRow(ctx, `SELECT row_security_active('audit_log'::regclass)`).Scan(&rlsEnforced); err != nil {
		t.Fatalf("inspect audit RLS: %v", err)
	}
	if rlsEnforced {
		t.Fatal("isolated admin pool must exercise the RLS-bypassing global audit chain")
	}

	tenantA, tenantB := shared.ID("audit-global-a"), shared.ID("audit-global-b")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantA.String(), tenantB.String()); err != nil {
		t.Fatalf("seed audit tenants: %v", err)
	}
	log := NewAuditLog(pool)
	base := "audit-global-first-observation-" + randHex(t)
	if err := log.Record(ctx, ports.AuditEntry{Actor: "system", Action: "test.global.before", Target: base + ":before", At: time.Unix(1000, 0).UTC()}); err != nil {
		t.Fatalf("write ordinary global audit entry: %v", err)
	}
	first := ports.AuditEntry{
		Actor: "system", Action: "evidence.tampered", Target: base + ":observation",
		Metadata: map[string]string{"idempotency_key": "first-observation", "reason_code": "chain_invalid"},
		At:       time.Unix(1001, 0).UTC(),
	}
	if err := log.RecordFirstObservation(shared.WithTenant(ctx, tenantA), first); err != nil {
		t.Fatalf("write tenant A first observation on global chain: %v", err)
	}
	var firstHash string
	if err := pool.QueryRow(ctx, `SELECT hash FROM audit_log WHERE tenant_id=$1 AND action=$2 AND target=$3`, tenantA.String(), first.Action, first.Target).Scan(&firstHash); err != nil {
		t.Fatalf("read tenant A first observation hash: %v", err)
	}
	if err := log.Record(ctx, ports.AuditEntry{Actor: "system", Action: "test.global.after", Target: base + ":after", At: time.Unix(1002, 0).UTC()}); err != nil {
		t.Fatalf("write ordinary global audit after first observation: %v", err)
	}
	later := first
	later.At = first.At.Add(time.Hour)
	if err := log.RecordFirstObservation(shared.WithTenant(ctx, tenantA), later); err != nil {
		t.Fatalf("replay tenant A first observation with later clock: %v", err)
	}
	var retainedAt time.Time
	var retainedHash string
	if err := pool.QueryRow(ctx, `SELECT created_at, hash FROM audit_log WHERE tenant_id=$1 AND action=$2 AND target=$3`, tenantA.String(), first.Action, first.Target).Scan(&retainedAt, &retainedHash); err != nil {
		t.Fatalf("read retained tenant A first observation: %v", err)
	}
	if !retainedAt.Equal(first.At) || retainedHash != firstHash {
		t.Fatalf("later retry rewrote global first observation time/hash=%s/%q, want %s/%q", retainedAt, retainedHash, first.At, firstHash)
	}
	if err := log.RecordFirstObservation(shared.WithTenant(ctx, tenantB), later); err != nil {
		t.Fatalf("write tenant B same key first observation: %v", err)
	}
	mismatch := later
	mismatch.Metadata = map[string]string{"idempotency_key": "first-observation", "reason_code": "other"}
	if err := log.RecordFirstObservation(shared.WithTenant(ctx, tenantA), mismatch); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("metadata mismatch error=%v, want conflict", err)
	}

	report, err := log.VerifyGlobal(ctx)
	if err != nil || !report.Intact {
		t.Fatalf("global chain report=%+v err=%v", report, err)
	}
	rows, err := pool.Query(ctx, `SELECT tenant_id, hash_version, created_at FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatalf("read global audit rows: %v", err)
	}
	defer rows.Close()
	type row struct {
		tenant  string
		version int
		at      time.Time
	}
	var got []row
	for rows.Next() {
		var current row
		if err := rows.Scan(&current.tenant, &current.version, &current.at); err != nil {
			t.Fatalf("scan global audit row: %v", err)
		}
		got = append(got, current)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate global audit rows: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("global audit rows=%+v, want four without duplicate retry", got)
	}
	for _, current := range got {
		if current.version != 1 {
			t.Fatalf("global-chain row=%+v, want hash version 1", current)
		}
	}
	if got[1].tenant != tenantA.String() || !got[1].at.Equal(first.At) || got[3].tenant != tenantB.String() {
		t.Fatalf("first-observation tenant/time scope=%+v", got)
	}
}

func TestRuntimeFirstObservationUsesTenantV2AndRecordOnceKeepsExactTimestamp(t *testing.T) {
	pool, dsn := freshAuditChainPool(t)
	ctx := context.Background()
	role := uniqueProbeRole(t, dsn, "audit_first_observation")
	runtimePool, err := runtimeAUPPool(ctx, pool, dsn, role)
	if err != nil {
		t.Fatalf("set up runtime audit role: %v", err)
	}
	t.Cleanup(runtimePool.Close)
	var rlsEnforced bool
	if err := runtimePool.QueryRow(ctx, `SELECT row_security_active('audit_log'::regclass)`).Scan(&rlsEnforced); err != nil {
		t.Fatalf("inspect runtime audit RLS: %v", err)
	}
	if !rlsEnforced {
		t.Fatal("runtime audit role must exercise the tenant chain")
	}

	tenant := shared.ID("audit-runtime-tenant")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed runtime audit tenant: %v", err)
	}
	log := NewAuditLog(runtimePool)
	first := ports.AuditEntry{
		Actor: "system", Action: "evidence.tampered", Target: "runtime-first-observation",
		Metadata: map[string]string{"idempotency_key": "runtime-observation", "reason_code": "chain_invalid"},
		At:       time.Unix(1000, 0).UTC(),
	}
	tenantCtx := shared.WithTenant(ctx, tenant)
	if err := log.RecordFirstObservation(tenantCtx, first); err != nil {
		t.Fatalf("write runtime first observation: %v", err)
	}
	later := first
	later.At = first.At.Add(time.Hour)
	if err := log.RecordFirstObservation(tenantCtx, later); err != nil {
		t.Fatalf("replay runtime first observation: %v", err)
	}
	if err := log.RecordOnce(tenantCtx, later); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("ordinary RecordOnce timestamp mismatch error=%v, want conflict", err)
	}
	var version int
	var retainedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT hash_version, created_at FROM audit_log WHERE tenant_id=$1 AND action=$2`, tenant.String(), first.Action).Scan(&version, &retainedAt); err != nil {
		t.Fatalf("read runtime first observation: %v", err)
	}
	if version != 2 || !retainedAt.Equal(first.At) {
		t.Fatalf("runtime first observation version/time=%d/%s, want 2/%s", version, retainedAt, first.At)
	}
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
