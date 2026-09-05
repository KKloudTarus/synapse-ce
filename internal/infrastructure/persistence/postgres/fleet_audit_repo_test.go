package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

type fleetAuditFixture struct {
	pool   *pgxpool.Pool
	tenant shared.ID
	ctx    context.Context
	at     time.Time
}

func newFleetAuditFixture(t *testing.T) fleetAuditFixture {
	t.Helper()
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
	tenant := shared.ID("fleetaudit-" + randHex(t))
	t.Cleanup(func() { cleanupFleetAuditTenants(t, pool, tenant) })
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return fleetAuditFixture{
		pool:   pool,
		tenant: tenant,
		ctx:    shared.WithTenant(ctx, tenant),
		at:     time.Now().UTC().Truncate(time.Microsecond),
	}
}

// cleanupFleetAuditTenants removes the fixture's rows on ONE pinned connection.
// session_replication_role is a session setting, so issuing it through the pool
// could leave it set on a connection a later test reuses, silently disabling that
// test's triggers and foreign keys. Pin the connection and always restore it.
func cleanupFleetAuditTenants(t *testing.T, pool *pgxpool.Pool, tenants ...shared.ID) {
	t.Helper()
	cleanupFleetAudit(t, pool, true, tenants...)
}

// cleanupFleetAuditIntents removes only the outbox rows, for fixtures that own the
// tenant row themselves. Leaving an intention behind would make migration 0125's
// rollback guard refuse every later `goose down` in this package.
func cleanupFleetAuditIntents(t *testing.T, pool *pgxpool.Pool, tenants ...shared.ID) {
	t.Helper()
	cleanupFleetAudit(t, pool, false, tenants...)
}

func cleanupFleetAudit(t *testing.T, pool *pgxpool.Pool, dropTenant bool, tenants ...shared.ID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Errorf("acquire fleet audit cleanup connection: %v", err)
		return
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Errorf("disable fleet audit cleanup triggers: %v", err)
		return
	}
	defer func() {
		if _, err := conn.Exec(ctx, `SET session_replication_role = origin`); err != nil {
			t.Errorf("restore fleet audit cleanup triggers: %v", err)
		}
	}()
	for _, tenantID := range tenants {
		if _, err := conn.Exec(ctx, `DELETE FROM fleet_audit_intents WHERE tenant_id=$1`, tenantID.String()); err != nil {
			t.Errorf("delete fleet audit intentions for %q: %v", tenantID, err)
		}
		if !dropTenant {
			continue
		}
		if _, err := conn.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()); err != nil {
			t.Errorf("delete fleet audit tenant %q: %v", tenantID, err)
		}
	}
}

func (f fleetAuditFixture) repo(t *testing.T) *FleetAuditRepository {
	t.Helper()
	repo, err := NewFleetAuditRepository(f.pool)
	if err != nil {
		t.Fatalf("new fleet audit repository: %v", err)
	}
	return repo
}

func fleetAuditIntent(id string, at time.Time) ports.FleetAuditIntent {
	return ports.FleetAuditIntent{
		ID: id,
		Entry: ports.AuditEntry{
			Actor:  "agent-1",
			Action: "fleet.telemetry.batch_commit",
			Target: "stream-1",
			At:     at,
			Metadata: map[string]string{
				"idempotency_key": id,
				"batch_id":        "batch-1",
			},
		},
	}
}

func TestNewFleetAuditRepositoryRequiresPool(t *testing.T) {
	if _, err := NewFleetAuditRepository(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error, got %v", err)
	}
}

// The insert must return the EXACT payload that became durable, because the caller
// audits the returned value. A nanosecond-carrying candidate must come back
// microsecond-normalized, or an immediate delivery and a restart-time delivery
// would hash two different entries for one intention identity.
func TestFleetAuditRepositoryReturnsExactDurablePayload(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	candidate := fleetAuditIntent("intent-exact", f.at.Add(1234*time.Nanosecond))
	stored, err := repo.insertFleetAudit(f.ctx, candidate)
	if err != nil {
		t.Fatalf("insert fleet audit: %v", err)
	}
	if stored.Entry.At.Equal(candidate.Entry.At) {
		t.Fatal("insert returned the un-normalized candidate timestamp")
	}
	if !stored.Entry.At.Equal(candidate.Entry.At.Truncate(time.Microsecond)) {
		t.Fatalf("stored at=%v, want microsecond truncation of %v", stored.Entry.At, candidate.Entry.At)
	}
	if stored.Entry.At.Location() != time.UTC {
		t.Fatalf("stored at location=%v, want UTC", stored.Entry.At.Location())
	}
	pending, err := repo.ListPendingFleetAudits(f.ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending=%d, want 1", len(pending))
	}
	// What a restart reads back must equal what the in-process caller audited.
	if !pending[0].Entry.At.Equal(stored.Entry.At) || pending[0].ID != stored.ID ||
		pending[0].Entry.Actor != stored.Entry.Actor || pending[0].Entry.Action != stored.Entry.Action ||
		pending[0].Entry.Target != stored.Entry.Target {
		t.Fatalf("reconciler payload=%#v, want %#v", pending[0].Entry, stored.Entry)
	}
	for key, want := range stored.Entry.Metadata {
		if pending[0].Entry.Metadata[key] != want {
			t.Fatalf("reconciler metadata[%s]=%q, want %q", key, pending[0].Entry.Metadata[key], want)
		}
	}
}

// An exact retry is a no-op, and metadata is compared by jsonb semantics rather
// than serialized bytes so Go's map ordering cannot fake an equivocation.
func TestFleetAuditRepositoryExactRetryIsIdempotent(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	intent := fleetAuditIntent("intent-retry", f.at)
	first, err := repo.insertFleetAudit(f.ctx, intent)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	reordered := fleetAuditIntent("intent-retry", f.at)
	reordered.Entry.Metadata = map[string]string{
		"batch_id":        "batch-1",
		"idempotency_key": "intent-retry",
	}
	second, err := repo.insertFleetAudit(f.ctx, reordered)
	if err != nil {
		t.Fatalf("exact retry must be idempotent, got %v", err)
	}
	if !second.Entry.At.Equal(first.Entry.At) {
		t.Fatalf("retry at=%v, want %v", second.Entry.At, first.Entry.At)
	}
	var rows int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM fleet_audit_intents
		WHERE tenant_id=$1 AND intent_id=$2`, f.tenant.String(), "intent-retry").Scan(&rows); err != nil {
		t.Fatalf("count intentions: %v", err)
	}
	if rows != 1 {
		t.Fatalf("intention rows=%d, want 1", rows)
	}
}

// Reusing one intention identity for different immutable content is an audit
// equivocation and must fail closed.
func TestFleetAuditRepositoryRejectsDifferentContentForSameID(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	if _, err := repo.insertFleetAudit(f.ctx, fleetAuditIntent("intent-conflict", f.at)); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	for _, tc := range []struct {
		name  string
		mutID func(ports.FleetAuditIntent) ports.FleetAuditIntent
	}{
		{"actor", func(i ports.FleetAuditIntent) ports.FleetAuditIntent { i.Entry.Actor = "other-agent"; return i }},
		{"action", func(i ports.FleetAuditIntent) ports.FleetAuditIntent { i.Entry.Action = "fleet.other"; return i }},
		{"target", func(i ports.FleetAuditIntent) ports.FleetAuditIntent { i.Entry.Target = "stream-2"; return i }},
		{"metadata", func(i ports.FleetAuditIntent) ports.FleetAuditIntent {
			i.Entry.Metadata["batch_id"] = "batch-2"
			return i
		}},
		{"occurred at", func(i ports.FleetAuditIntent) ports.FleetAuditIntent {
			i.Entry.At = i.Entry.At.Add(time.Hour)
			return i
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := repo.insertFleetAudit(f.ctx, tc.mutID(fleetAuditIntent("intent-conflict", f.at)))
			if !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("want conflict for differing %s, got %v", tc.name, err)
			}
		})
	}
}

func TestFleetAuditRepositoryRejectsMalformedIntentions(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	tests := []struct {
		name   string
		intent ports.FleetAuditIntent
	}{
		{"empty id", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("   ", f.at)
			i.Entry.Metadata["idempotency_key"] = "   "
			return i
		}()},
		{"no actor", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.Actor = " "
			return i
		}()},
		{"no action", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.Action = ""
			return i
		}()},
		{"no target", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.Target = ""
			return i
		}()},
		{"zero time", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.At = time.Time{}
			return i
		}()},
		{"no metadata", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.Metadata = nil
			return i
		}()},
		{"missing idempotency key", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			delete(i.Entry.Metadata, "idempotency_key")
			return i
		}()},
		// The idempotency key IS the intention identity. If they could differ, the audit
		// chain would dedupe on one value while the outbox tracked another.
		{"idempotency key mismatch", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.Metadata["idempotency_key"] = "something-else"
			return i
		}()},
		// The chain assigns hashes at delivery. A precomputed hash would let a caller
		// dictate chain linkage from outside the chain.
		{"precomputed hash", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.Hash = "deadbeef"
			return i
		}()},
		{"precomputed previous hash", func() ports.FleetAuditIntent {
			i := fleetAuditIntent("intent-bad", f.at)
			i.Entry.PreviousHash = "deadbeef"
			return i
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := repo.insertFleetAudit(f.ctx, tc.intent); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestFleetAuditRepositoryRequiresTenantContext(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	if _, err := repo.insertFleetAudit(context.Background(), fleetAuditIntent("intent-notenant", f.at)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error without tenant, got %v", err)
	}
}

// Acknowledgement retires an intention monotonically: a second acknowledgement is
// a no-op rather than a new completion, and an unknown id is not found.
func TestFleetAuditRepositoryAcknowledgement(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	if _, err := repo.insertFleetAudit(f.ctx, fleetAuditIntent("intent-ack", f.at)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := repo.AcknowledgeFleetAudit(f.ctx, "intent-ack"); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	pending, err := repo.ListPendingFleetAudits(f.ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("acknowledged intention still pending: %#v", pending)
	}
	var firstCompletion time.Time
	if err := f.pool.QueryRow(context.Background(), `SELECT completed_at FROM fleet_audit_intents
		WHERE tenant_id=$1 AND intent_id=$2`, f.tenant.String(), "intent-ack").Scan(&firstCompletion); err != nil {
		t.Fatalf("read completion: %v", err)
	}
	if err := repo.AcknowledgeFleetAudit(f.ctx, "intent-ack"); err != nil {
		t.Fatalf("repeat acknowledge must be idempotent, got %v", err)
	}
	var secondCompletion time.Time
	if err := f.pool.QueryRow(context.Background(), `SELECT completed_at FROM fleet_audit_intents
		WHERE tenant_id=$1 AND intent_id=$2`, f.tenant.String(), "intent-ack").Scan(&secondCompletion); err != nil {
		t.Fatalf("re-read completion: %v", err)
	}
	if !secondCompletion.Equal(firstCompletion) {
		t.Fatalf("completion moved from %v to %v; acknowledgement must be monotonic", firstCompletion, secondCompletion)
	}
	if err := repo.AcknowledgeFleetAudit(f.ctx, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error for empty id, got %v", err)
	}
	if err := repo.AcknowledgeFleetAudit(f.ctx, "intent-missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not-found for unknown id, got %v", err)
	}
}

// Pending delivery is ordered by the instant the intention was committed, so
// recovery replays committed state in the order it happened.
func TestFleetAuditRepositoryListsPendingInCommitOrder(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	third := fleetAuditIntent("intent-c", f.at.Add(2*time.Second))
	first := fleetAuditIntent("intent-a", f.at)
	second := fleetAuditIntent("intent-b", f.at.Add(time.Second))
	for _, intent := range []ports.FleetAuditIntent{third, first, second} {
		if _, err := repo.insertFleetAudit(f.ctx, intent); err != nil {
			t.Fatalf("insert %s: %v", intent.ID, err)
		}
	}
	pending, err := repo.ListPendingFleetAudits(f.ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	var ids []string
	for _, intent := range pending {
		ids = append(ids, intent.ID)
	}
	want := []string{"intent-a", "intent-b", "intent-c"}
	if len(ids) != len(want) {
		t.Fatalf("pending ids=%v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("pending ids=%v, want %v", ids, want)
		}
	}
}

// A pending intention belongs to exactly one tenant's recovery sweep; another
// tenant must never see it, let alone deliver it into its own audit chain.
func TestFleetAuditRepositoryIsolatesTenants(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	other := shared.ID("fleetaudit-other-" + randHex(t))
	t.Cleanup(func() { cleanupFleetAuditTenants(t, f.pool, other) })
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO tenants(id,name) VALUES($1,$1)`, other.String()); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}
	if _, err := repo.insertFleetAudit(f.ctx, fleetAuditIntent("intent-mine", f.at)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	otherCtx := shared.WithTenant(context.Background(), other)
	pending, err := repo.ListPendingFleetAudits(otherCtx)
	if err != nil {
		t.Fatalf("list pending for other tenant: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("another tenant sees pending intentions: %#v", pending)
	}
	// Cross-tenant acknowledgement must not retire someone else's obligation.
	if err := repo.AcknowledgeFleetAudit(otherCtx, "intent-mine"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant acknowledge=%v, want not-found", err)
	}
	mine, err := repo.ListPendingFleetAudits(f.ctx)
	if err != nil || len(mine) != 1 {
		t.Fatalf("own pending=%#v/%v, want exactly one", mine, err)
	}
}

func TestFleetAuditRepositoryHonoursCancellation(t *testing.T) {
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if _, err := repo.insertFleetAudit(ctx, fleetAuditIntent("intent-cancel", f.at)); err == nil {
		t.Fatal("insert under a cancelled context must fail")
	}
	if _, err := repo.ListPendingFleetAudits(ctx); err == nil {
		t.Fatal("list under a cancelled context must fail")
	}
}

// Migration 0125 guards: the outbox is the durable proof that committed state owes
// an audit entry, so the database must enforce tenant isolation, immutability of
// the payload, monotonic completion, and refusal to delete an undelivered
// obligation, independently of any Go-side check.
func TestMigration0125FleetAuditIntentGuards(t *testing.T) {
	f := newFleetAuditFixture(t)
	ctx := context.Background()

	var rls, forced bool
	if err := f.pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity
		FROM pg_class WHERE oid='fleet_audit_intents'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatalf("inspect outbox RLS: %v", err)
	}
	if !rls || !forced {
		t.Fatalf("outbox RLS/forced=%t/%t, want true/true", rls, forced)
	}
	for _, trigger := range []string{"fleet_audit_intents_immutable_trigger", "fleet_audit_intents_no_truncate_trigger"} {
		var exists bool
		if err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger
			WHERE tgrelid='fleet_audit_intents'::regclass AND tgname=$1 AND NOT tgisinternal)`, trigger).Scan(&exists); err != nil {
			t.Fatalf("inspect outbox trigger %s: %v", trigger, err)
		}
		if !exists {
			t.Fatalf("migration 0125 did not install %s", trigger)
		}
	}

	repo := f.repo(t)
	if _, err := repo.insertFleetAudit(f.ctx, fleetAuditIntent("intent-guard", f.at)); err != nil {
		t.Fatalf("seed intention: %v", err)
	}

	// The database rejects an intention whose identity disagrees with its idempotency
	// key even if a future caller bypasses the repository.
	_, err := f.pool.Exec(ctx, `INSERT INTO fleet_audit_intents
		(tenant_id,intent_id,actor,action,target,metadata,occurred_at)
		VALUES($1,'intent-mismatch','a','b','c','{"idempotency_key":"other"}'::jsonb,now())`, f.tenant.String())
	if err == nil {
		t.Fatal("an intention whose metadata key differs from its id must be rejected by the schema")
	}

	for _, mutation := range []struct {
		name, query string
	}{
		{"actor UPDATE", `UPDATE fleet_audit_intents SET actor='tampered' WHERE tenant_id=$1`},
		{"action UPDATE", `UPDATE fleet_audit_intents SET action='tampered' WHERE tenant_id=$1`},
		{"target UPDATE", `UPDATE fleet_audit_intents SET target='tampered' WHERE tenant_id=$1`},
		{"metadata UPDATE", `UPDATE fleet_audit_intents SET metadata='{"idempotency_key":"intent-guard","x":"1"}'::jsonb WHERE tenant_id=$1`},
		{"occurred_at UPDATE", `UPDATE fleet_audit_intents SET occurred_at=now() WHERE tenant_id=$1`},
		{"undelivered DELETE", `DELETE FROM fleet_audit_intents WHERE tenant_id=$1`},
	} {
		_, err := f.pool.Exec(ctx, mutation.query, f.tenant.String())
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("%s error=%v, want SQLSTATE P0001", mutation.name, err)
		}
	}
	_, err = f.pool.Exec(ctx, `TRUNCATE fleet_audit_intents`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("TRUNCATE error=%v, want SQLSTATE P0001", err)
	}

	// Completion advances exactly once; it can never be moved or cleared afterwards.
	if err := repo.AcknowledgeFleetAudit(f.ctx, "intent-guard"); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	for _, mutation := range []struct {
		name, query string
	}{
		{"completed_at rewrite", `UPDATE fleet_audit_intents SET completed_at=now()+interval '1 hour' WHERE tenant_id=$1`},
		{"completed_at clear", `UPDATE fleet_audit_intents SET completed_at=NULL WHERE tenant_id=$1`},
	} {
		_, err := f.pool.Exec(ctx, mutation.query, f.tenant.String())
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("%s error=%v, want SQLSTATE P0001", mutation.name, err)
		}
	}
	// A delivered intention may be reclaimed: the audit chain is the permanent record.
	if _, err := f.pool.Exec(ctx, `DELETE FROM fleet_audit_intents WHERE tenant_id=$1 AND intent_id=$2`,
		f.tenant.String(), "intent-guard"); err != nil {
		t.Fatalf("retention of a delivered intention must be allowed, got %v", err)
	}
}

// RLS must isolate the outbox under a non-superuser runtime role, not merely under
// the repository's own tenant filter.
func TestMigration0125FleetAuditIntentRLSIsolation(t *testing.T) {
	f := newFleetAuditFixture(t)
	ctx := context.Background()
	repo := f.repo(t)
	if _, err := repo.insertFleetAudit(f.ctx, fleetAuditIntent("intent-rls", f.at)); err != nil {
		t.Fatalf("seed intention: %v", err)
	}
	role := "fleet_audit_runtime_" + randHex(t)
	if _, err := f.pool.Exec(ctx, `CREATE ROLE `+role+` NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create RLS role: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = f.pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = f.pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})
	if _, err := f.pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
		t.Fatalf("grant schema usage: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `GRANT SELECT ON fleet_audit_intents TO `+role); err != nil {
		t.Fatalf("grant reads: %v", err)
	}
	visible := func(tenantID string) int {
		t.Helper()
		var count int
		if err := WithTenant(ctx, f.pool, tenantID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM fleet_audit_intents WHERE intent_id=$1`, "intent-rls").Scan(&count)
		}); err != nil {
			t.Fatalf("query outbox through RLS role: %v", err)
		}
		return count
	}
	if visible(f.tenant.String()) != 1 {
		t.Fatal("own tenant cannot see its pending intention through RLS")
	}
	if visible("another-tenant") != 0 || visible("") != 0 {
		t.Fatal("outbox RLS did not isolate pending audit obligations")
	}
}

// A pending audit obligation must survive a rollback attempt: dropping the table
// would erase the only record that committed state still owes an audit entry.
func TestMigration0125RefusesRollbackWithIntentHistory(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	f := newFleetAuditFixture(t)
	repo := f.repo(t)
	if _, err := repo.insertFleetAudit(f.ctx, fleetAuditIntent("intent-rollback", f.at)); err != nil {
		t.Fatalf("seed intention: %v", err)
	}
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatalf("goose open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	// DownTo unwinds every migration above the target. 0125 is currently newest so nothing
	// above it exists, but re-apply on the way out so adding a 0126 cannot silently leave
	// the rest of the suite running against a partial schema.
	t.Cleanup(func() {
		if err := goose.Up(db, "."); err != nil {
			t.Errorf("restore migrations after rollback probe: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 124); err == nil || !strings.Contains(err.Error(), "cannot roll back 0125") {
		t.Fatalf("down migration error=%v, want audit intention history refusal", err)
	}
	var version int64
	if err := db.QueryRowContext(context.Background(),
		`SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("read migration version after refused down: %v", err)
	}
	if version != 125 {
		t.Fatalf("migration version after refused down=%d, want 125", version)
	}
}
