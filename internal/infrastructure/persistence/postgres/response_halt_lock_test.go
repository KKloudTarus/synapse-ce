package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestResponseHaltAdmissionLock exercises real role grants and transaction ordering,
// including a tenant whose fence row has not yet been created.
func TestResponseHaltAdmissionLock(t *testing.T) {
	adminDSN, runtimeDSN, haltDSN := os.Getenv("SYNAPSE_TEST_DB_DSN"), os.Getenv("SYNAPSE_TEST_DB_RUNTIME_DSN"), os.Getenv("SYNAPSE_TEST_DB_HALT_WRITER_DSN")
	if adminDSN == "" || runtimeDSN == "" || haltDSN == "" {
		t.Skip("set admin, runtime, and halt writer test DSNs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	if err := GrantRuntimePrivileges(ctx, adminDSN, runtimeDSN, haltDSN); err != nil {
		t.Fatal(err)
	}
	admin, err := Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	runtime, err := Connect(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	halt, err := Connect(ctx, haltDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(halt.Close)

	makeTenant := func(t *testing.T) (context.Context, responsesaga.ResponseAttempt) {
		t.Helper()
		tenant := shared.ID("halt-lock-" + randHex(t))
		engagement := shared.ID(tenant.String() + "-engagement")
		if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cleanupResponseAuditFixture(t, admin, tenant) })
		if _, err := admin.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagement.String(), tenant.String()); err != nil {
			t.Fatal(err)
		}
		tc := shared.WithTenant(ctx, tenant)
		const process = "pe_11111111111111111111111111111111"
		action, err := rdom.NewAction(shared.ID(tenant.String()+"-action"), rdom.KindStopProcess, process)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		if err := NewResponseRepository(runtime).Put(tc, rdom.Record{ID: action.ID, TenantID: tenant, EngagementID: engagement, Action: action, State: rdom.StatePending, ApprovedBy: "reviewer", UpdatedAt: at}); err != nil {
			t.Fatal(err)
		}
		return tc, responsesaga.ResponseAttempt{ActionID: action.ID, Attempt: 1, IdempotencyKey: tenant.String() + "-attempt", Target: responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: process}, State: responsesaga.StateIssued, ExecutorID: "agent:response-executor", ExecutorAgentID: "response-executor", DecidedBy: "reviewer", At: at, DeadlineAt: at.Add(time.Hour)}
	}
	beginLock := func(t *testing.T, pool *pgxpool.Pool, tenantCtx context.Context, exclusive bool) (pgx.Tx, int32) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		tenant, _ := shared.TenantFrom(tenantCtx)
		if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if err := lockResponseHalt(ctx, tx, exclusive); err != nil {
			t.Fatal(err)
		}
		var pid int32
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		return tx, pid
	}
	waitBlocked := func(t *testing.T, pid int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var blocked bool
			if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("expected transaction to block on halt lock")
	}
	type attemptResult struct {
		created bool
		err     error
	}
	seedFence := func(t *testing.T, tc context.Context) {
		t.Helper()
		tenant, _ := shared.TenantFrom(tc)
		if _, err := admin.Exec(ctx, `INSERT INTO response_halt_fences(tenant_id) VALUES($1)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, existing := range []bool{false, true} {
		for _, commit := range []bool{true, false} {
			name := "rollback"
			if commit {
				name = "commit"
			}
			if existing {
				name += "-existing"
			} else {
				name += "-missing"
			}
			t.Run(name, func(t *testing.T) {
				tc, attempt := makeTenant(t)
				if existing {
					seedFence(t, tc)
				}
				tx, pid := beginLock(t, halt, tc, true)
				if _, err := tx.Exec(ctx, `INSERT INTO response_halt_fences(tenant_id,generation,halted) VALUES(current_setting('app.current_tenant',true),1,true) ON CONFLICT (tenant_id) DO UPDATE SET generation=1,halted=true`); err != nil {
					t.Fatal(err)
				}
				result := make(chan attemptResult, 1)
				go func() {
					_, created, err := NewResponseRepository(runtime).StartAttempt(tc, attempt)
					result <- attemptResult{created, err}
				}()
				waitBlocked(t, pid)
				if commit {
					err = tx.Commit(ctx)
				} else {
					err = tx.Rollback(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-result:
					if commit && (got.created || !errors.Is(got.err, responsesaga.ErrStaleHaltGeneration)) {
						t.Fatalf("committed halt admitted attempt: %+v", got)
					}
					if !commit && (!got.created || got.err != nil) {
						t.Fatalf("rolled-back halt blocked attempt: %+v", got)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			})
		}
	}
	for _, existing := range []bool{false, true} {
		name := "shared blocks halt - missing"
		if existing {
			name = "shared blocks halt - existing"
		}
		t.Run(name, func(t *testing.T) {
			tc, _ := makeTenant(t)
			if existing {
				seedFence(t, tc)
			}
			otherCtx, otherAttempt := makeTenant(t)
			tx, pid := beginLock(t, runtime, tc, false)
			tenant, _ := shared.TenantFrom(tc)
			result := make(chan error, 1)
			go func() {
				_, _, _, err := NewResponseHaltWriterRepository(halt).AdvanceHaltGenerationWithAudit(tc, 0, responseAuditIntent(tenant.String()+":halt", "response.halt_intent", tenant.String(), time.Now().UTC().Truncate(time.Microsecond)))
				result <- err
			}()
			waitBlocked(t, pid)
			if _, created, err := NewResponseRepository(runtime).StartAttempt(otherCtx, otherAttempt); err != nil || !created {
				t.Fatalf("independent tenant blocked: created=%t err=%v", created, err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatalf("halt after shared lock: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
	t.Run("reject repeatable read", func(t *testing.T) {
		tc, _ := makeTenant(t)
		tx, err := runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		tenant, _ := shared.TenantFrom(tc)
		if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if err := lockResponseHalt(ctx, tx, false); err == nil {
			t.Fatal("repeatable read must be rejected")
		}
	})
}
