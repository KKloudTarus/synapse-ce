package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type responseAuditFixture struct {
	pool   *pgxpool.Pool
	repo   *ResponseRepository
	halt   *ResponseHaltWriterRepository
	tenant shared.ID
	engage shared.ID
	ctx    context.Context
	at     time.Time
}

func newResponseAuditFixture(t *testing.T) responseAuditFixture {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	tenant := shared.ID("responseaudit-" + randHex(t))
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	engage := shared.ID(tenant.String() + "-engagement")
	if _, err := pool.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engage.String(), tenant.String()); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	t.Cleanup(func() { cleanupResponseAuditFixture(t, pool, tenant) })
	return responseAuditFixture{
		pool: pool, repo: NewResponseRepository(pool), halt: NewResponseHaltWriterRepository(pool), tenant: tenant, engage: engage,
		ctx: shared.WithTenant(ctx, tenant), at: time.Now().UTC().Truncate(time.Microsecond),
	}
}

func cleanupResponseAuditFixture(t *testing.T, pool *pgxpool.Pool, tenant shared.ID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Errorf("acquire response audit cleanup connection: %v", err)
		return
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Errorf("disable response audit cleanup triggers: %v", err)
		return
	}
	defer func() {
		if _, err := conn.Exec(ctx, `SET session_replication_role = origin`); err != nil {
			t.Errorf("restore response audit cleanup triggers: %v", err)
		}
	}()
	for _, query := range []string{
		`DELETE FROM response_target_evidence_receipts WHERE tenant_id=$1`,
		`DELETE FROM response_verification_observations WHERE tenant_id=$1`,
		`DELETE FROM response_halt_dispatches WHERE tenant_id=$1`,
		`DELETE FROM response_audit_intents WHERE tenant_id=$1`,
		`DELETE FROM fleet_audit_intents WHERE tenant_id=$1`,
		`DELETE FROM response_attempts WHERE tenant_id=$1`,
		`DELETE FROM response_actions WHERE tenant_id=$1`,
		`DELETE FROM response_halt_fences WHERE tenant_id=$1`,
		`DELETE FROM engagements WHERE tenant_id=$1`,
		`DELETE FROM tenants WHERE id=$1`,
	} {
		if _, err := conn.Exec(ctx, query, tenant.String()); err != nil {
			t.Errorf("clean response audit fixture: %v", err)
		}
	}
}

func responseAuditIntent(id, action, target string, at time.Time) ports.ResponseAuditIntent {
	return ports.ResponseAuditIntent{ID: id, Entry: ports.AuditEntry{
		Actor: "operator@example.test", Action: action, Target: target, At: at,
		Metadata: map[string]string{"idempotency_key": id, "reason": "test"},
	}}
}

func TestResponseHaltFenceAndAuditIntentCommitAtomically(t *testing.T) {
	f := newResponseAuditFixture(t)
	bad := responseAuditIntent("halt:bad", "", f.tenant.String(), f.at)
	if _, _, _, err := f.halt.AdvanceHaltGenerationWithAudit(f.ctx, 0, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed audit intent must fail, got %v", err)
	}
	if generation, err := f.halt.CurrentHaltGeneration(f.ctx); err != nil || generation != 0 {
		t.Fatalf("malformed intent changed generation to %d: %v", generation, err)
	}

	want := responseAuditIntent("halt:1", "response.halt_intent", f.tenant.String(), f.at)
	generation, committed, dispatch, err := f.halt.AdvanceHaltGenerationWithAudit(f.ctx, 0, want)
	if err != nil || generation != 1 || !ports.SameResponseAuditIntent(committed, want) || dispatch.TenantID != f.tenant || dispatch.Generation != generation {
		t.Fatalf("atomic halt commit generation=%d intent=%+v dispatch=%+v err=%v", generation, committed, dispatch, err)
	}
	pending, err := f.repo.ListPendingResponseAudits(f.ctx)
	if err != nil || len(pending) != 1 || !ports.SameResponseAuditIntent(pending[0], want) {
		t.Fatalf("pending response audits=%+v err=%v", pending, err)
	}
	if err := f.repo.AcknowledgeResponseAudit(f.ctx, want.ID); err != nil {
		t.Fatalf("acknowledge response audit: %v", err)
	}
	pending, err = f.repo.ListPendingResponseAudits(f.ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending audits after acknowledgement=%+v err=%v", pending, err)
	}
	pendingHalts, err := f.repo.ListPendingResponseHaltDispatches(f.ctx)
	if err != nil || len(pendingHalts) != 1 || pendingHalts[0] != dispatch {
		t.Fatalf("pending halt dispatches=%+v err=%v", pendingHalts, err)
	}
	if err := f.repo.AcknowledgeResponseHaltDispatch(f.ctx, generation); err != nil {
		t.Fatalf("acknowledge halt dispatch: %v", err)
	}
	pendingHalts, err = f.repo.ListPendingResponseHaltDispatches(f.ctx)
	if err != nil || len(pendingHalts) != 1 || pendingHalts[0] != dispatch {
		t.Fatalf("immutable halt dispatch after acknowledgement=%+v err=%v", pendingHalts, err)
	}
}

func TestResponseTransitionAndAuditIntentCommitAtomically(t *testing.T) {
	f := newResponseAuditFixture(t)
	action, err := rdom.NewAction("response-1", rdom.KindIsolateHost, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	record := rdom.Record{
		ID: action.ID, TenantID: f.tenant, EngagementID: f.engage, Action: action,
		State: rdom.StatePending, ApprovedBy: "alice", UpdatedAt: f.at,
	}
	if err := f.repo.Put(f.ctx, record); err != nil {
		t.Fatalf("put response: %v", err)
	}
	record.State = rdom.StateCancelled
	record.UpdatedAt = f.at.Add(time.Second)
	bad := responseAuditIntent("cancel:bad", "", record.ID.String(), record.UpdatedAt)
	if _, _, err := f.repo.TransitionWithAudit(f.ctx, record, rdom.StatePending, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed transition intent must fail, got %v", err)
	}
	stored, found, err := f.repo.Get(f.ctx, record.ID)
	if err != nil || !found || stored.State != rdom.StatePending {
		t.Fatalf("malformed intent changed response state: %+v found=%v err=%v", stored, found, err)
	}

	want := responseAuditIntent("cancel:1", "response.cancelled_by_halt", record.ID.String(), record.UpdatedAt)
	transitioned, committed, err := f.repo.TransitionWithAudit(f.ctx, record, rdom.StatePending, want)
	if err != nil || !transitioned || !ports.SameResponseAuditIntent(committed, want) {
		t.Fatalf("atomic response transition=%t intent=%+v err=%v", transitioned, committed, err)
	}
	stored, found, err = f.repo.Get(f.ctx, record.ID)
	if err != nil || !found || stored.State != rdom.StateCancelled {
		t.Fatalf("stored response after atomic transition: %+v found=%v err=%v", stored, found, err)
	}
	pending, err := f.repo.ListPendingResponseAudits(f.ctx)
	if err != nil || len(pending) != 1 || !ports.SameResponseAuditIntent(pending[0], want) {
		t.Fatalf("pending transition audit=%+v err=%v", pending, err)
	}
}

func TestMigration0144ResponseAuditIntentGuards(t *testing.T) {
	f := newResponseAuditFixture(t)
	var rls, forced bool
	if err := f.pool.QueryRow(f.ctx, `
		SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='response_audit_intents'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatalf("inspect response audit RLS: %v", err)
	}
	if !rls || !forced {
		t.Fatalf("response audit RLS/forced=%t/%t, want true/true", rls, forced)
	}
	intent := responseAuditIntent("guard:1", "response.halt_intent", f.tenant.String(), f.at)
	if _, err := f.repo.EnqueueResponseAudit(f.ctx, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM response_audit_intents WHERE tenant_id=$1 AND intent_id=$2`, f.tenant.String(), intent.ID); err == nil {
		t.Fatal("database allowed deletion of an undelivered response audit obligation")
	}
}

func TestMigration0145ResponseHaltDispatchGuards(t *testing.T) {
	f := newResponseAuditFixture(t)
	var rls, forced bool
	if err := f.pool.QueryRow(f.ctx, `
		SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='response_halt_dispatches'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatalf("inspect response halt dispatch RLS: %v", err)
	}
	if !rls || !forced {
		t.Fatalf("response halt dispatch RLS/forced=%t/%t, want true/true", rls, forced)
	}
	intent := responseAuditIntent("halt-guard:1", "response.halt_intent", f.tenant.String(), f.at)
	generation, _, _, err := f.halt.AdvanceHaltGenerationWithAudit(f.ctx, 0, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM response_halt_dispatches WHERE tenant_id=$1 AND generation=$2`, f.tenant.String(), generation); err == nil {
		t.Fatal("database allowed deletion of a response halt dispatch obligation")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE response_halt_dispatches SET completed_at=now() WHERE tenant_id=$1 AND generation=$2`, f.tenant.String(), generation); err == nil {
		t.Fatal("tenant-scoped direct SQL forged halt dispatch completion")
	}
	if _, err := f.pool.Exec(f.ctx, `SELECT acknowledge_response_halt_dispatch($1)`, generation); err == nil {
		t.Fatal("database retained an invocable halt-dispatch completion function")
	}
	if err := f.repo.AcknowledgeResponseHaltDispatch(f.ctx, generation); err != nil {
		t.Fatalf("repository acknowledgement must safely verify immutable dispatch: %v", err)
	}
	pending, err := f.repo.ListPendingResponseHaltDispatches(f.ctx)
	if err != nil || len(pending) != 1 || pending[0].Generation != generation {
		t.Fatalf("immutable halt dispatch must remain recoverable: pending=%+v err=%v", pending, err)
	}
	for _, query := range []string{
		`UPDATE response_halt_dispatches SET generation=0 WHERE tenant_id=$1 AND generation=$2`,
		`UPDATE response_halt_dispatches SET tenant_id='forged' WHERE tenant_id=$1 AND generation=$2`,
		`UPDATE response_halt_dispatches SET created_at=created_at - interval '1 second' WHERE tenant_id=$1 AND generation=$2`,
		`TRUNCATE response_halt_dispatches`,
	} {
		if _, err := f.pool.Exec(f.ctx, query, f.tenant.String(), generation); err == nil {
			t.Fatalf("database allowed immutable halt dispatch mutation: %s", query)
		}
	}
}

func TestMigration0138ResponseHaltFenceGuards(t *testing.T) {
	f := newResponseAuditFixture(t)
	intent := responseAuditIntent("halt-fence-guard:1", "response.halt_intent", f.tenant.String(), f.at)
	generation, _, _, err := f.halt.AdvanceHaltGenerationWithAudit(f.ctx, 0, intent)
	if err != nil || generation != 1 {
		t.Fatalf("advance halt fence: generation=%d err=%v", generation, err)
	}
	for _, query := range []string{
		`UPDATE response_halt_fences SET generation=0 WHERE tenant_id=$1`,
		`UPDATE response_halt_fences SET halted=FALSE WHERE tenant_id=$1`,
		`UPDATE response_halt_fences SET updated_at=updated_at - interval '1 second' WHERE tenant_id=$1`,
		`DELETE FROM response_halt_fences WHERE tenant_id=$1`,
		`TRUNCATE response_halt_fences`,
	} {
		if _, err := f.pool.Exec(f.ctx, query, f.tenant.String()); err == nil {
			t.Fatalf("database allowed unsafe halt fence mutation: %s", query)
		}
	}
}
