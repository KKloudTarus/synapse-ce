package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestResponseHaltWriterRoleIsolation is intentionally DSN-gated because it needs three
// externally provisioned NOINHERIT roles. It proves grants, rather than repository discipline,
// keep the normal API role from forging a fence/dispatch and keep the halt identity narrow.
func TestResponseHaltWriterRoleIsolation(t *testing.T) {
	adminDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	runtimeDSN := os.Getenv("SYNAPSE_TEST_DB_RUNTIME_DSN")
	haltDSN := os.Getenv("SYNAPSE_TEST_DB_HALT_WRITER_DSN")
	if adminDSN == "" || runtimeDSN == "" || haltDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN, SYNAPSE_TEST_DB_RUNTIME_DSN, and SYNAPSE_TEST_DB_HALT_WRITER_DSN to exercise role isolation")
	}
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := GrantRuntimePrivileges(ctx, adminDSN, runtimeDSN, haltDSN); err != nil {
		t.Fatalf("grant isolated response roles: %v", err)
	}
	admin, err := Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	t.Cleanup(admin.Close)
	runtime, err := Connect(ctx, runtimeDSN)
	if err != nil {
		t.Fatalf("connect runtime: %v", err)
	}
	t.Cleanup(runtime.Close)
	halt, err := ConnectPool(ctx, haltDSN, PoolConfig{MaxConns: 2})
	if err != nil {
		t.Fatalf("connect halt writer: %v", err)
	}
	t.Cleanup(halt.Close)

	tenant := shared.ID("halt-role-" + randHex(t))
	otherTenant := shared.ID("halt-role-other-" + randHex(t))
	for _, id := range []shared.ID{tenant, otherTenant} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, id.String()); err != nil {
			t.Fatalf("seed tenant %s: %v", id, err)
		}
	}
	t.Cleanup(func() {
		cleanupResponseAuditFixture(t, admin, tenant)
		cleanupResponseAuditFixture(t, admin, otherTenant)
	})

	tenantCtx := shared.WithTenant(ctx, tenant)
	for _, query := range []string{
		`INSERT INTO response_halt_fences(tenant_id) VALUES(current_setting('app.current_tenant', true))`,
		`INSERT INTO response_halt_dispatches(tenant_id,generation,created_at) VALUES(current_setting('app.current_tenant', true),1,now())`,
	} {
		err := WithContextTenant(tenantCtx, runtime, func(tx pgx.Tx) error { _, err := tx.Exec(tenantCtx, query); return err })
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("runtime must lack protected halt insert privilege for %s: %v", query, err)
		}
	}

	engagement := shared.ID(tenant.String() + "-engagement")
	if _, err := admin.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagement.String(), tenant.String()); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	const processID = "pe_11111111111111111111111111111111"
	action, err := rdom.NewAction(shared.ID(tenant.String()+"-action"), rdom.KindStopProcess, processID)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	repo := NewResponseRepository(runtime)
	if err := repo.Put(tenantCtx, rdom.Record{ID: action.ID, TenantID: tenant, EngagementID: engagement, Action: action, State: rdom.StatePending, ApprovedBy: "reviewer", UpdatedAt: at}); err != nil {
		t.Fatalf("seed response action as runtime: %v", err)
	}
	attempt := responsesaga.ResponseAttempt{
		ActionID: action.ID, Attempt: 1, IdempotencyKey: tenant.String() + "-attempt-1",
		Target: responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: processID},
		State:  responsesaga.StateIssued, ExecutorID: "agent:response-executor", ExecutorAgentID: "response-executor", DecidedBy: "reviewer", At: at, DeadlineAt: at.Add(time.Hour),
	}
	if _, created, err := repo.StartAttempt(tenantCtx, attempt); err != nil || !created {
		t.Fatalf("start attempt without fence: created=%t err=%v", created, err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO response_halt_fences(tenant_id) VALUES($1)`, tenant.String()); err != nil {
		t.Fatalf("seed unhalted fence: %v", err)
	}
	attempt.Attempt = 2
	attempt.IdempotencyKey = tenant.String() + "-attempt-2"
	if _, created, err := repo.StartAttempt(tenantCtx, attempt); err != nil || !created {
		t.Fatalf("start attempt with unhalted fence: created=%t err=%v", created, err)
	}
	for _, query := range []string{
		`UPDATE response_halt_fences SET halted=true WHERE tenant_id=current_setting('app.current_tenant', true)`,
		`DELETE FROM response_halt_fences WHERE tenant_id=current_setting('app.current_tenant', true)`,
	} {
		err := WithContextTenant(tenantCtx, runtime, func(tx pgx.Tx) error { _, err := tx.Exec(tenantCtx, query); return err })
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("runtime must lack fence write privilege for %s: %v", query, err)
		}
	}
	if err := WithContextTenant(tenantCtx, halt, func(tx pgx.Tx) error {
		_, err := tx.Exec(tenantCtx, `UPDATE response_actions SET state='cancelled'`)
		return err
	}); err == nil {
		t.Fatal("halt writer mutated unrelated response data")
	}
	if err := WithContextTenant(tenantCtx, halt, func(tx pgx.Tx) error {
		_, err := tx.Exec(tenantCtx, `INSERT INTO evidence(id,tenant_id,kind,sha256,storage_ref,content,created_at) VALUES('forged',current_setting('app.current_tenant',true),'test','hash','forged','forged',now())`)
		return err
	}); err == nil {
		t.Fatal("halt writer inserted unrelated evidence data")
	}

	writer := NewResponseHaltWriterRepository(halt)
	intent := responseAuditIntent("halt-role:1", "response.halt_intent", tenant.String(), time.Now().UTC().Truncate(time.Microsecond))
	if _, _, _, err := writer.AdvanceHaltGenerationWithAudit(tenantCtx, 0, intent); err != nil {
		t.Fatalf("halt writer atomic commit: %v", err)
	}
	if err := WithContextTenant(shared.WithTenant(ctx, otherTenant), halt, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM response_halt_dispatches`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("halt writer crossed tenant boundary: dispatches=%d", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("check halt writer tenant isolation: %v", err)
	}
}
