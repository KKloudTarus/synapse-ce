package postgres

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func newWO(t *testing.T, idem string, bucket int64) *workorder.WorkOrder {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	wo, err := workorder.New(shared.ID("wo-"+idem), "wt", "as1", "ag1", "scan.source", "eng1", idem, now.Add(time.Hour), bucket, now)
	if err != nil {
		t.Fatalf("new wo: %v", err)
	}
	wo.Signature = "sig"
	return wo
}

func TestWorkOrderRepository(t *testing.T) {
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
	t.Cleanup(func() { pool.Close() })
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('wt','WT') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM work_orders WHERE tenant_id='wt'`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id='wt'`)
	})

	repo := NewWorkOrderRepository(pool)

	// FORCE RLS on the table.
	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='work_orders'`).Scan(&forced); err != nil {
		t.Fatalf("relforce: %v", err)
	}
	if !forced {
		t.Fatalf("FORCE ROW LEVEL SECURITY not set on work_orders")
	}

	// Issue + roundtrip.
	wo := newWO(t, "idem1", 1)
	got, err := repo.Issue(ctx, wo)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got.ID != wo.ID || got.State != workorder.StateIssued {
		t.Fatalf("issue roundtrip mismatch: %+v", got)
	}

	// Idempotent re-issue: same order id, no conflict.
	again, err := repo.Issue(ctx, wo)
	if err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	if again.ID != wo.ID {
		t.Fatalf("idempotent issue must return the same order: %q vs %q", again.ID, wo.ID)
	}

	// In-flight conflict: different idempotency key, same (asset, capability, bucket) while live.
	conflict := newWO(t, "idem2", 1)
	if _, err := repo.Issue(ctx, conflict); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected in-flight ErrConflict, got %v", err)
	}

	// Claim addressed to the agent; another agent claims nothing.
	claimNow := time.Now().UTC()
	none, err := repo.Claim(ctx, "wt", "other-agent", 10, claimNow, "lease-other", claimNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("claim other: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("other agent must claim nothing, got %d", len(none))
	}
	claimed, err := repo.Claim(ctx, "wt", "ag1", 10, claimNow, "lease-1", claimNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("claim ag1: %v", err)
	}
	if len(claimed) != 1 || claimed[0].State != workorder.StateClaimed {
		t.Fatalf("ag1 should claim one order into claimed, got %+v", claimed)
	}

	// Transition CAS: claimed -> running with correct expected state.
	tnow := time.Now().UTC()
	if err := repo.TransitionLeased(ctx, "wt", wo.ID, "lease-1", workorder.StateRunning, "", workorder.StateClaimed, tnow); err != nil {
		t.Fatalf("claimed->running: %v", err)
	}
	// Stale expected state now conflicts.
	if err := repo.TransitionLeased(ctx, "wt", wo.ID, "lease-1", workorder.StateSucceeded, "", workorder.StateClaimed, tnow); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale expected state must ErrConflict, got %v", err)
	}
	// A transition on a non-existent order is ErrNotFound, not ErrConflict.
	if err := repo.Transition(ctx, "wt", "missing", workorder.StateRunning, "", workorder.StateClaimed, tnow); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("transition on missing order must ErrNotFound, got %v", err)
	}

	// GetByID + not found.
	if _, err := repo.GetByID(ctx, "wt", wo.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := repo.GetByID(ctx, "wt", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// ListByTenant (coverage projection, #413): returns this tenant's orders and is tenant-scoped —
	// a different tenant sees none of them (RLS + explicit tenant_id filter).
	mine, err := repo.ListByTenant(ctx, "wt")
	if err != nil {
		t.Fatalf("list by tenant: %v", err)
	}
	if len(mine) == 0 {
		t.Fatalf("ListByTenant(wt) must return the seeded orders, got 0")
	}
	for _, o := range mine {
		if o.TenantID != "wt" {
			t.Fatalf("ListByTenant leaked a foreign tenant's order: %q", o.TenantID)
		}
	}
	other, err := repo.ListByTenant(ctx, "someone-else")
	if err != nil {
		t.Fatalf("list by other tenant: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("ListByTenant must be tenant-scoped; foreign tenant saw %d orders", len(other))
	}
}

func TestWorkOrderClaimWithAuditPostgres(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		actor string
		bad   bool
	}{
		{name: "single", count: 1, actor: "reviewer"},
		{name: "multiple", count: 3, actor: "reviewer"},
		{name: "invalid audit rolls back", count: 3, actor: " ", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFleetAuditFixture(t)
			t.Cleanup(func() {
				if _, err := f.pool.Exec(context.Background(), `DELETE FROM work_orders WHERE tenant_id=$1`, f.tenant.String()); err != nil {
					t.Errorf("delete work orders: %v", err)
				}
			})
			repo := NewWorkOrderRepository(f.pool)
			orders := make([]*workorder.WorkOrder, 0, tc.count)
			for i := 0; i < tc.count; i++ {
				wo := newWO(t, fmt.Sprintf("claim-%s-%d", f.tenant, i), int64(i+1))
				wo.TenantID = f.tenant
				if _, err := repo.Issue(f.ctx, wo); err != nil {
					t.Fatalf("issue: %v", err)
				}
				orders = append(orders, wo)
			}
			claimed, intents, err := repo.ClaimWithAudit(f.ctx, f.tenant, "ag1", tc.count, f.at, "lease", f.at.Add(time.Minute), tc.actor)
			if tc.bad {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("invalid actor: got %v, want validation error", err)
				}
			} else if err != nil || len(claimed) != tc.count || len(intents) != tc.count {
				t.Fatalf("claim: orders=%d intents=%d err=%v", len(claimed), len(intents), err)
			}
			pending, err := repo.ListPendingFleetAudits(f.ctx)
			if err != nil {
				t.Fatalf("list audit intents: %v", err)
			}
			want := tc.count
			state := workorder.StateClaimed
			if tc.bad {
				want = 0
				state = workorder.StateIssued
			}
			if len(pending) != want {
				t.Fatalf("pending audit intents=%d, want %d", len(pending), want)
			}
			for _, wo := range orders {
				stored, err := repo.GetByID(f.ctx, f.tenant, wo.ID)
				if err != nil || stored.State != state {
					t.Fatalf("stored order %s: state=%v err=%v, want %s", wo.ID, stored, err, state)
				}
				if !tc.bad {
					found := false
					for _, intent := range pending {
						if intent.Entry.Target == wo.ID.String() && intent.Entry.Action == "work_order.claimed" {
							found = true
						}
					}
					if !found {
						t.Errorf("missing claimed audit for %s", wo.ID)
					}
				}
			}
		})
	}
}

func TestWorkOrderIssueWithAuditReplayPostgres(t *testing.T) {
	f := newFleetAuditFixture(t)
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `DELETE FROM work_orders WHERE tenant_id=$1`, f.tenant.String()); err != nil {
			t.Errorf("delete work orders: %v", err)
		}
	})
	repo := NewWorkOrderRepository(f.pool)
	wo := newWO(t, "issue-replay-"+f.tenant.String(), 1)
	wo.TenantID = f.tenant
	id := "work_order.issued:v1:" + f.tenant.String() + ":" + wo.ID.String()
	intent := ports.FleetAuditIntent{ID: id, Entry: ports.AuditEntry{
		Actor: "operator", Action: "work_order.issued", Target: wo.ID.String(), At: f.at.Add(time.Second),
		Metadata: map[string]string{"idempotency_key": id, "tenant_id": f.tenant.String()},
	}}
	stored, original, err := repo.IssueWithAudit(f.ctx, wo, intent)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	retry := intent
	retry.Entry.At = intent.Entry.At.Add(time.Minute)
	again, replayed, err := repo.IssueWithAudit(f.ctx, wo, retry)
	if err != nil || again.ID != stored.ID || !ports.SameFleetAuditIntent(original, replayed) {
		t.Fatalf("replay order=%v intent=%v err=%v", again, replayed, err)
	}
	for _, altered := range []ports.FleetAuditIntent{
		{ID: id, Entry: ports.AuditEntry{Actor: "other", Action: intent.Entry.Action, Target: intent.Entry.Target, At: retry.Entry.At, Metadata: intent.Entry.Metadata}},
		{ID: id, Entry: ports.AuditEntry{Actor: intent.Entry.Actor, Action: intent.Entry.Action, Target: intent.Entry.Target, At: retry.Entry.At, Metadata: map[string]string{"idempotency_key": id, "tenant_id": "different"}}},
	} {
		if _, _, err := repo.IssueWithAudit(f.ctx, wo, altered); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("changed audit must conflict: %v", err)
		}
	}
	pending, err := repo.ListPendingFleetAudits(f.ctx)
	if err != nil || len(pending) != 1 || !ports.SameFleetAuditIntent(original, pending[0]) {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
}

func TestWorkOrderReclaimWithAuditPostgres(t *testing.T) {
	f := newFleetAuditFixture(t)
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `DELETE FROM work_orders WHERE tenant_id=$1`, f.tenant.String()); err != nil {
			t.Errorf("delete work orders: %v", err)
		}
	})
	repo := NewWorkOrderRepository(f.pool)
	wo := newWO(t, "reclaim-"+f.tenant.String(), 1)
	wo.TenantID = f.tenant
	if _, err := repo.Issue(f.ctx, wo); err != nil {
		t.Fatalf("issue: %v", err)
	}
	var running []ports.FleetAuditIntent
	for i, lease := range []string{"lease-first", "lease-second"} {
		now := f.at.Add(time.Duration(i) * 2 * time.Minute)
		claimed, intents, err := repo.ClaimWithAudit(f.ctx, f.tenant, "ag1", 1, now, lease, now.Add(time.Minute), "operator")
		if err != nil || len(claimed) != 1 || claimed[0].LeaseID != lease || len(intents) != 1 {
			t.Fatalf("claim %s: orders=%v intents=%v err=%v", lease, claimed, intents, err)
		}
		if i == 1 {
			if _, err := repo.TransitionLeasedWithAudit(f.ctx, f.tenant, wo.ID, "lease-first", workorder.StateRunning, "", workorder.StateClaimed, now, "operator"); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("stale lease transition: %v", err)
			}
		}
		intent, err := repo.TransitionLeasedWithAudit(f.ctx, f.tenant, wo.ID, lease, workorder.StateRunning, "", workorder.StateClaimed, now, "operator")
		if err != nil {
			t.Fatalf("running %s: %v", lease, err)
		}
		running = append(running, intent)
	}
	if running[0].ID == running[1].ID {
		t.Fatal("running audits share an identity")
	}
	if _, err := repo.TransitionLeasedWithAudit(f.ctx, f.tenant, wo.ID, "lease-second", workorder.StateSucceeded, "", workorder.StateRunning, f.at.Add(2*time.Minute), "operator"); err != nil {
		t.Fatalf("complete second lease: %v", err)
	}
	pending, err := repo.ListPendingFleetAudits(f.ctx)
	if err != nil || len(pending) != 5 {
		t.Fatalf("reclaim audits=%v err=%v", pending, err)
	}
}

func TestWorkOrderFenceAuditRetryPostgres(t *testing.T) {
	f := newFleetAuditFixture(t)
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `DELETE FROM work_orders WHERE tenant_id=$1`, f.tenant.String()); err != nil {
			t.Errorf("delete work orders: %v", err)
		}
	})
	repo := NewWorkOrderRepository(f.pool)
	wo := newWO(t, "fence-"+f.tenant.String(), 1)
	wo.TenantID, wo.Capability = f.tenant, workorder.CapabilityResponseProcess
	wo.Signature = ""
	const processID = "pe_11111111111111111111111111111111"
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, processID)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	command := fleetagent.ResponseCommand{
		ProtocolVersion: fleetagent.ResponseCommandProtocolVersion, CommandID: wo.ID, TenantID: wo.TenantID,
		AgentID: wo.AgentID, AssetID: wo.AssetID, EngagementID: wo.AuthorizationID,
		Action: action, ActionDigest: digest, AttemptKey: wo.IdempotencyKey, VerificationChallenge: strings.Repeat("a", 64),
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetProcess, Value: processID},
		Target:              responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: wo.AssetID, ProcessEntityID: processID},
		IssuedAt:            f.at, NotAfter: wo.NotAfter, SigningKeyID: evidence.KeyFingerprint(private.Public().(ed25519.PublicKey)),
	}
	command.Signature = fleetagent.SignResponseCommand(private, command)
	if err := wo.AttachResponseCommand(command); err != nil {
		t.Fatalf("attach response command: %v", err)
	}
	signer, err := worksign.New([]byte("test-key-32-bytes-000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	wo.Signature = signer.Sign(wo.SigningPayload())
	if _, err := repo.Issue(f.ctx, wo); err != nil {
		t.Fatal(err)
	}
	count, original, err := repo.CancelResponsesBelowGenerationWithAudit(f.ctx, f.tenant, 1, "halt", f.at, "operator")
	if err != nil || count != 1 {
		t.Fatalf("first cancellation count=%d err=%v", count, err)
	}
	if err := repo.AcknowledgeFleetAudit(f.ctx, original.ID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, replay, err := repo.CancelResponsesBelowGenerationWithAudit(f.ctx, f.tenant, 1, "halt", f.at.Add(time.Minute), "operator")
			if err != nil || n != count || !ports.SameFleetAuditIntent(original, replay) {
				errs <- fmt.Errorf("retry count=%d audit=%v err=%v", n, replay, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for _, args := range []struct{ reason, actor string }{{"changed", "operator"}, {"halt", "other"}} {
		if _, _, err := repo.CancelResponsesBelowGenerationWithAudit(f.ctx, f.tenant, 1, args.reason, f.at.Add(time.Minute), args.actor); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("changed audit must conflict: %v", err)
		}
	}
	stored, err := repo.GetByID(f.ctx, f.tenant, wo.ID)
	if err != nil || stored.State != workorder.StateCancelled {
		t.Fatalf("stored order=%v err=%v", stored, err)
	}
}

// TestMigration0059 exercises the migration down and back up.
func TestMigration0059(t *testing.T) {
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedMigration0059DSN(t, sharedDSN)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := openLockedGooseDB(t, dsn)
	// Registered as a cleanup rather than deferred: cleanups run LIFO and AFTER every
	// deferred call, so a deferred Close would shut the handle before the schema-restore
	// cleanup below could use it.
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	// Migration 0085 refuses to roll back once tenant-chained (hash_version = 2) audit
	// rows exist, and Migrate above creates them. Clear them first: this test walks the
	// schema down through 0085 deliberately, so the guard is protecting real history it
	// does not have here.
	deleteV2AuditRowsForMigrationRollback(t, db)
	// DownTo unwinds EVERY migration above the target, so restore the full schema on the
	// way out. Without this the package is left at version 59 and any test that runs
	// later sees a partial schema. Registered after the Close cleanup so LIFO runs this
	// restore first, while the handle is still open.
	t.Cleanup(func() {
		if err := goose.Up(db, "."); err != nil {
			t.Errorf("restore migrations after rollback probe: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 58); err != nil {
		t.Fatalf("down to 58: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `SELECT 1 FROM work_orders LIMIT 1`)
	var pgErr *pgconn.PgError
	if err == nil || !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("work_orders should be undefined after down to 58, got %v", err)
	}
	if err := goose.UpTo(db, ".", 59); err != nil {
		t.Fatalf("up to 59: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1 FROM work_orders LIMIT 1`); err != nil {
		t.Fatalf("work_orders should exist after up to 59: %v", err)
	}
}

// isolatedMigration0059DSN creates a disposable database so this historical down/up test never
// rolls the shared integration schema back while other packages are using it.
func isolatedMigration0059DSN(t *testing.T, sharedDSN string) string {
	t.Helper()
	return isolatedMigrationDSN(t, sharedDSN, "0059")
}

// isolatedMigrationDSN creates a disposable database for a migration test that walks the schema
// down and back up, and drops it when the test ends.
func isolatedMigrationDSN(t *testing.T, sharedDSN, label string) string {
	t.Helper()

	u, err := url.Parse(sharedDSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN for isolated migration test: %v", err)
	}
	name := fmt.Sprintf("synapse_migration_%s_%d", label, time.Now().UnixNano())
	isolated := *u
	isolated.Path = "/" + name
	isolated.RawPath = ""

	ctx := context.Background()
	admin, err := Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("connect shared PostgreSQL database for isolated migration test: %v", err)
	}
	quotedName := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quotedName); err != nil {
		admin.Close()
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+quotedName+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		admin.Close()
	})
	return isolated.String()
}
