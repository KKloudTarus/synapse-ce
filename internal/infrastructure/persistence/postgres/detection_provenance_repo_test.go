package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type detectionProvenancePostgresFixture struct {
	pool                    *pgxpool.Pool
	dsn                     string
	tenant, otherTenant     shared.ID
	engagement, otherEngage shared.ID
	agent, asset, detection shared.ID
	at                      time.Time
}

// requireDetectionProvenanceTestAdmin makes the elevated integration-test requirements explicit
// before migration. The fixture needs a disposable non-bypass RLS role, and append-only rows need
// trigger-suppressed cleanup; neither is silently assumed of a production runtime role.
func requireDetectionProvenanceTestAdmin(t *testing.T, dsn string) {
	t.Helper()
	pool, err := Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect for administrative preflight: %v", err)
	}
	defer pool.Close()

	var superuser, createRole bool
	if err := pool.QueryRow(context.Background(), `SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname=current_user`).Scan(&superuser, &createRole); err != nil {
		t.Fatalf("inspect administrative test capabilities: %v", err)
	}
	if !superuser || !createRole {
		t.Skipf("Postgres detection provenance integration test requires a disposable superuser CREATEROLE admin (superuser=%t createrole=%t)", superuser, createRole)
	}
}

func newDetectionProvenancePostgresFixture(t *testing.T) detectionProvenancePostgresFixture {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	requireDetectionProvenanceTestAdmin(t, dsn)

	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Cleanup is LIFO, so register Close first and it runs last.
	t.Cleanup(pool.Close)

	id := randHex(t)
	fixture := detectionProvenancePostgresFixture{
		pool:        pool,
		dsn:         dsn,
		tenant:      shared.ID("dprov-" + id),
		otherTenant: shared.ID("dprov-other-" + id),
		engagement:  shared.ID("dprov-eng-" + id),
		otherEngage: shared.ID("dprov-other-eng-" + id),
		agent:       shared.ID("dprov-agent-" + id),
		asset:       shared.ID("dprov-asset-" + id),
		detection:   shared.ID("dprov-detection-" + id),
		at:          time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
	}
	// The history trigger deliberately blocks DELETE. The explicit preflight above gates this
	// trigger-suppressed cleanup; every cleanup failure remains visible to the test result.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := pool.Acquire(cleanupCtx)
		if err != nil {
			t.Errorf("acquire detection provenance cleanup connection: %v", err)
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(cleanupCtx, `SET session_replication_role = replica`); err != nil {
			t.Errorf("disable detection provenance cleanup triggers: %v", err)
			return
		}
		defer func() {
			if _, err := conn.Exec(cleanupCtx, `SET session_replication_role = origin`); err != nil {
				t.Errorf("restore detection provenance cleanup triggers: %v", err)
			}
		}()
		for _, statement := range []struct {
			query string
			arg   shared.ID
		}{
			{`DELETE FROM detection_provenance_current WHERE tenant_id=$1`, fixture.tenant},
			{`DELETE FROM detection_provenance_current WHERE tenant_id=$1`, fixture.otherTenant},
			{`DELETE FROM detection_provenance_transitions WHERE tenant_id=$1`, fixture.tenant},
			{`DELETE FROM detection_provenance_transitions WHERE tenant_id=$1`, fixture.otherTenant},
			{`DELETE FROM engagements WHERE tenant_id=$1`, fixture.tenant},
			{`DELETE FROM engagements WHERE tenant_id=$1`, fixture.otherTenant},
			{`DELETE FROM tenants WHERE id=$1`, fixture.tenant},
			{`DELETE FROM tenants WHERE id=$1`, fixture.otherTenant},
		} {
			if _, err := conn.Exec(cleanupCtx, statement.query, statement.arg.String()); err != nil {
				t.Errorf("detection provenance cleanup %q for %q: %v", statement.query, statement.arg, err)
			}
		}
	})

	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, fixture.tenant.String(), fixture.otherTenant.String()); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1),($3,$4,$3)`, fixture.engagement.String(), fixture.tenant.String(), fixture.otherEngage.String(), fixture.otherTenant.String()); err != nil {
		t.Fatalf("seed engagements: %v", err)
	}
	return fixture
}

func (f detectionProvenancePostgresFixture) admission(t *testing.T) (detectionprovenance.Current, detectionprovenance.Transition) {
	t.Helper()
	rule, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration rule")
	}
	observed := f.at.Add(-time.Minute)
	d, err := detection.NewDetection(rule, "host-1", f.agent, []detection.Event{{
		Class: detection.ClassProcess, At: observed, Host: "host-1",
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"},
	}}, observed)
	if err != nil {
		t.Fatalf("new detection: %v", err)
	}
	refs := []fleetagent.TelemetryReference{{
		StreamID: "stream-1", Epoch: 1, Sequence: 7, EventID: "event-7", Digest: strings.Repeat("b", 64),
	}}
	item := fleetagent.DetectionBatchItemV2{
		ID: f.detection, Detection: d, AssetID: f.asset, TelemetryRefs: refs,
		Rulepack:              fleetagent.RulepackReference{ID: "builtin", Version: 1, Digest: strings.Repeat("c", 64)},
		RedactionPolicyDigest: strings.Repeat("d", 64),
	}
	ref, err := item.Reference()
	if err != nil {
		t.Fatalf("detection reference: %v", err)
	}
	input, err := (fleetagent.PendingDetectionV2{
		Batch: fleetagent.AgentBatchV2{
			Context: "synapse-agent-detection-batch:v2", Version: 2, AgentID: f.agent,
			EngagementID: f.engagement, Sequence: 1, KeyID: "test-key", Detections: []fleetagent.DetectionRefV2{ref},
		},
		Item: item,
	}).Canonical()
	if err != nil {
		t.Fatalf("canonical pending detection: %v", err)
	}
	return detectionprovenance.Current{
		TenantID: f.tenant, EngagementID: f.engagement, DetectionID: f.detection,
		Status: detectionprovenance.StatusPending, PendingInput: input, UpdatedAt: f.at,
	}, detectionprovenance.Transition{
		TenantID: f.tenant, EngagementID: f.engagement, DetectionID: f.detection, Sequence: 1,
		Kind: detectionprovenance.Received, Status: detectionprovenance.StatusPending, TelemetryRefs: refs,
		AgentID: f.agent, AssetID: f.asset, Reason: "v2 batch admitted", OccurredAt: f.at,
	}
}

func newDetectionProvenanceRLSRole(t *testing.T, fixture detectionProvenancePostgresFixture) string {
	t.Helper()
	role := "detection_provenance_runtime_" + randHex(t)
	if _, err := fixture.pool.Exec(context.Background(), `CREATE ROLE `+role+` NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create disposable RLS role: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := fixture.pool.Exec(cleanupCtx, `DROP OWNED BY `+role); err != nil {
			t.Errorf("drop owned objects for disposable RLS role %s: %v", role, err)
		}
		if _, err := fixture.pool.Exec(cleanupCtx, `DROP ROLE IF EXISTS `+role); err != nil {
			t.Errorf("drop disposable RLS role %s: %v", role, err)
		}
	})
	for _, statement := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON detection_provenance_current,detection_provenance_transitions TO ` + role,
	} {
		if _, err := fixture.pool.Exec(context.Background(), statement); err != nil {
			t.Fatalf("grant disposable RLS role: %v", err)
		}
	}
	return role
}

func withDetectionProvenanceRLSRole(ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, role string, fn func(pgx.Tx) error) error {
	return WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			return fmt.Errorf("set disposable RLS role: %w", err)
		}
		return fn(tx)
	})
}

func requireAppendOnlyMutation(t *testing.T, err error, operation string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("%s append-only mutation error=%v, want SQLSTATE P0001", operation, err)
	}
}

func assertDetectionProvenanceGUCReset(t *testing.T, fixture detectionProvenancePostgresFixture, role string) {
	t.Helper()
	ctx := context.Background()
	resetPool, err := ConnectPool(ctx, fixture.dsn, PoolConfig{MaxConns: 1})
	if err != nil {
		t.Fatalf("connect one-connection reset pool: %v", err)
	}
	t.Cleanup(resetPool.Close)
	// Keep the same physical connection for the tenant-scoped transaction and its post-commit
	// check. This reproduces WithTenant's local set_config behavior without a pool checkout gap.
	conn, err := resetPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire reset connection: %v", err)
	}
	defer conn.Release()
	tenantTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant transaction on pinned connection: %v", err)
	}
	if _, err := tenantTx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, fixture.tenant.String()); err != nil {
		t.Fatalf("set tenant on pinned connection: %v", err)
	}
	if _, err := tenantTx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
		t.Fatalf("set RLS role on pinned connection: %v", err)
	}
	var tenantCount int
	if err := tenantTx.QueryRow(ctx, `SELECT count(*) FROM detection_provenance_current WHERE engagement_id=$1 AND detection_id=$2`, fixture.engagement.String(), fixture.detection.String()).Scan(&tenantCount); err != nil {
		t.Fatalf("read tenant transaction on pinned connection: %v", err)
	}
	if tenantCount != 1 {
		t.Fatalf("tenant transaction saw %d current rows, want 1", tenantCount)
	}
	if err := tenantTx.Commit(ctx); err != nil {
		t.Fatalf("commit tenant transaction on pinned connection: %v", err)
	}
	var reset string
	if err := conn.QueryRow(ctx, `SELECT current_setting('app.current_tenant', true)`).Scan(&reset); err != nil {
		t.Fatalf("read reset tenant GUC: %v", err)
	}
	if reset != "" {
		t.Fatalf("committed tenant GUC reset=%q, want empty fail-closed placeholder", reset)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin reused reset connection transaction: %v", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback reused reset connection transaction: %v", err)
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
		t.Fatalf("set RLS role on reset connection: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM detection_provenance_current WHERE engagement_id=$1 AND detection_id=$2`, fixture.engagement.String(), fixture.detection.String()).Scan(&count); err != nil {
		t.Fatalf("read reset connection under RLS: %v", err)
	}
	if count != 0 {
		t.Fatalf("reused connection with reset tenant saw %d provenance rows", count)
	}
}

func TestDetectionProvenanceRepository(t *testing.T) {
	fixture := newDetectionProvenancePostgresFixture(t)
	ctx := shared.WithTenant(context.Background(), fixture.tenant)
	repo := mustNewDetectionProvenanceRepository(t, fixture.pool)
	current, received := fixture.admission(t)

	if err := repo.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	got, found, err := repo.Current(ctx, fixture.engagement, fixture.detection)
	if err != nil || !found {
		t.Fatalf("current after admit found=%t err=%v", found, err)
	}
	if got.Status != detectionprovenance.StatusPending || string(got.PendingInput) != string(current.PendingInput) || !got.UpdatedAt.Equal(fixture.at) {
		t.Fatalf("current after admit = %#v, want pending durable input", got)
	}
	decoded, err := fleetagent.DecodePendingDetectionV2(got.PendingInput)
	if err != nil {
		t.Fatalf("decode persisted pending v2 detection: %v", err)
	}
	if decoded.Item.ID != fixture.detection || decoded.Batch.EngagementID != fixture.engagement || decoded.Batch.AgentID != fixture.agent {
		t.Fatalf("persisted pending v2 detection lost identity: %#v", decoded)
	}
	listed, err := repo.ListCurrent(ctx, fixture.engagement)
	if err != nil || len(listed) != 1 || listed[0].DetectionID != fixture.detection {
		t.Fatalf("list current = %#v, err=%v; want admitted detection", listed, err)
	}
	history, err := repo.ListTransitions(ctx, fixture.engagement, fixture.detection)
	if err != nil || len(history) != 1 || history[0].Kind != detectionprovenance.Received || history[0].Sequence != 1 {
		t.Fatalf("admission history = %#v, err=%v; want one received transition", history, err)
	}

	laterCurrent, laterReceived := current, received
	laterCurrent.UpdatedAt = laterCurrent.UpdatedAt.Add(time.Hour)
	laterReceived.OccurredAt = laterReceived.OccurredAt.Add(time.Hour)
	if err := repo.AdmitPending(ctx, laterCurrent, laterReceived); err != nil {
		t.Fatalf("identical admission replay with later receipt clock: %v", err)
	}
	if history, err = repo.ListTransitions(ctx, fixture.engagement, fixture.detection); err != nil || len(history) != 1 || !history[0].OccurredAt.Equal(received.OccurredAt) {
		t.Fatalf("identical admission replay changed history=%#v err=%v", history, err)
	}
	conflicting := current
	conflicting.PendingInput = []byte("different immutable durable input")
	if err := repo.AdmitPending(ctx, conflicting, received); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting immutable admission error = %v, want conflict", err)
	}

	durable := detectionprovenance.Transition{
		TenantID: fixture.tenant, EngagementID: fixture.engagement, DetectionID: fixture.detection, Sequence: 2,
		Kind: detectionprovenance.TelemetryDurable, Status: detectionprovenance.StatusPending,
		Reason: "causal telemetry durable", OccurredAt: fixture.at.Add(time.Minute),
	}
	if err := repo.AppendTransition(ctx, durable); err != nil {
		t.Fatalf("append durable transition: %v", err)
	}
	if err := repo.AppendTransition(ctx, durable); err != nil {
		t.Fatalf("identical transition replay: %v", err)
	}
	history, err = repo.ListTransitions(ctx, fixture.engagement, fixture.detection)
	if err != nil || len(history) != 2 || history[1].Kind != detectionprovenance.TelemetryDurable || history[1].Sequence != 2 {
		t.Fatalf("history after durable transition = %#v, err=%v", history, err)
	}

	reconnected, err := Connect(context.Background(), fixture.dsn)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	t.Cleanup(reconnected.Close)
	reloaded := mustNewDetectionProvenanceRepository(t, reconnected)
	persisted, found, err := reloaded.Current(ctx, fixture.engagement, fixture.detection)
	if err != nil || !found {
		t.Fatalf("re-read current after reconnect found=%t err=%v", found, err)
	}
	if _, err := fleetagent.DecodePendingDetectionV2(persisted.PendingInput); err != nil {
		t.Fatalf("decode re-read persisted pending v2 detection: %v", err)
	}
	persistedHistory, err := reloaded.ListTransitions(ctx, fixture.engagement, fixture.detection)
	if err != nil || len(persistedHistory) != 2 || persistedHistory[0].Kind != detectionprovenance.Received || persistedHistory[1].Kind != detectionprovenance.TelemetryDurable {
		t.Fatalf("re-read history after reconnect = %#v, err=%v", persistedHistory, err)
	}

	otherCtx := shared.WithTenant(context.Background(), fixture.otherTenant)
	if _, found, err := repo.Current(otherCtx, fixture.engagement, fixture.detection); err != nil || found {
		t.Fatalf("known cross-tenant current found=%t err=%v; want hidden", found, err)
	}
	if states, err := repo.ListCurrent(otherCtx, fixture.engagement); err != nil || len(states) != 0 {
		t.Fatalf("known cross-tenant current list=%#v err=%v; want hidden", states, err)
	}
	if transitions, err := repo.ListTransitions(otherCtx, fixture.engagement, fixture.detection); err != nil || len(transitions) != 0 {
		t.Fatalf("known cross-tenant history=%#v err=%v; want hidden", transitions, err)
	}
	if _, _, err := repo.Current(context.Background(), fixture.engagement, fixture.detection); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant current error=%v, want validation failure", err)
	}
	if err := repo.AdmitPending(context.Background(), current, received); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant admission error=%v, want validation failure", err)
	}

	role := newDetectionProvenanceRLSRole(t, fixture)
	countKnown := func(tenant shared.ID, table string) int {
		t.Helper()
		var count int
		err := withDetectionProvenanceRLSRole(context.Background(), fixture.pool, tenant, role, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE engagement_id=$1 AND detection_id=$2`, fixture.engagement.String(), fixture.detection.String()).Scan(&count)
		})
		if err != nil {
			t.Fatalf("RLS count %s: %v", table, err)
		}
		return count
	}
	for _, table := range []string{"detection_provenance_current", "detection_provenance_transitions"} {
		if got := countKnown(fixture.tenant, table); got == 0 {
			t.Fatalf("tenant RLS query on %s saw %d rows, want a visible record", table, got)
		}
		if got := countKnown(fixture.otherTenant, table); got != 0 {
			t.Fatalf("other tenant RLS query on %s saw %d known-ID rows", table, got)
		}
		if got := countKnown("", table); got != 0 {
			t.Fatalf("unset tenant RLS query on %s saw %d known-ID rows", table, got)
		}
		var forced bool
		if err := fixture.pool.QueryRow(context.Background(), `SELECT relforcerowsecurity FROM pg_class WHERE relname=$1`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("FORCE RLS %s=%v err=%v", table, forced, err)
		}
	}
	assertDetectionProvenanceGUCReset(t, fixture, role)

	if err := WithTenant(ctx, fixture.pool, fixture.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE detection_provenance_transitions SET reason='tampered' WHERE tenant_id=$1`, fixture.tenant.String())
		return err
	}); err == nil {
		t.Fatal("UPDATE on append-only provenance transitions must be rejected")
	} else {
		requireAppendOnlyMutation(t, err, "UPDATE")
	}
	if err := WithTenant(ctx, fixture.pool, fixture.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM detection_provenance_transitions WHERE tenant_id=$1`, fixture.tenant.String())
		return err
	}); err == nil {
		t.Fatal("DELETE on append-only provenance transitions must be rejected")
	} else {
		requireAppendOnlyMutation(t, err, "DELETE")
	}
	if err := WithTenant(ctx, fixture.pool, fixture.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `TRUNCATE detection_provenance_transitions`)
		return err
	}); err == nil {
		t.Fatal("TRUNCATE on append-only provenance transitions must be rejected")
	} else {
		requireAppendOnlyMutation(t, err, "TRUNCATE")
	}
	if _, err := fixture.pool.Exec(ctx, `DELETE FROM engagements WHERE id=$1`, fixture.engagement.String()); err == nil {
		t.Fatal("engagement deletion must not cascade durable detection provenance")
	}
}

func TestDetectionProvenanceRepositoryChainForkGuard(t *testing.T) {
	fixture := newDetectionProvenancePostgresFixture(t)
	ctx := shared.WithTenant(context.Background(), fixture.tenant)
	repo := mustNewDetectionProvenanceRepository(t, fixture.pool)
	current, received := fixture.admission(t)
	if err := repo.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	history, err := repo.ListTransitions(ctx, fixture.engagement, fixture.detection)
	if err != nil || len(history) != 1 {
		t.Fatalf("read genesis history = %#v, %v", history, err)
	}

	fork := detectionprovenance.SealTransition(detectionprovenance.Transition{
		TenantID: fixture.tenant, EngagementID: fixture.engagement, DetectionID: fixture.detection,
		Sequence: 2, Kind: detectionprovenance.TelemetryDurable, Status: detectionprovenance.StatusPending,
		Reason: "fork", OccurredAt: fixture.at.Add(time.Second),
	}, history[0].Hash)
	refs, err := json.Marshal(fork.TelemetryRefs)
	if err != nil {
		t.Fatalf("marshal fork references: %v", err)
	}
	insert := func(sequence uint64, entryHash string) error {
		return WithTenant(ctx, fixture.pool, fixture.tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO detection_provenance_transitions
				(tenant_id,engagement_id,detection_id,sequence,kind,status,evidence_id,agent_id,asset_id,telemetry_refs,reason,previous_hash,entry_hash,occurred_at)
				VALUES ($1,$2,$3,$4,$5,$6,NULL,NULL,NULL,$7::jsonb,$8,$9,$10,$11)`,
				fixture.tenant.String(), fixture.engagement.String(), fixture.detection.String(), int64(sequence),
				string(fork.Kind), string(fork.Status), refs, fork.Reason, fork.PreviousHash, entryHash, fork.OccurredAt)
			return err
		})
	}
	if err := insert(fork.Sequence, fork.Hash); err != nil {
		t.Fatalf("insert first child: %v", err)
	}
	if err := insert(fork.Sequence+1, strings.Repeat("f", 64)); err == nil {
		t.Fatal("database accepted two provenance children for one predecessor")
	}
}

func TestDetectionProvenanceRepositoryConcurrentAdmissionIsIdempotent(t *testing.T) {
	fixture := newDetectionProvenancePostgresFixture(t)
	ctx := shared.WithTenant(context.Background(), fixture.tenant)
	repo := mustNewDetectionProvenanceRepository(t, fixture.pool)
	current, received := fixture.admission(t)

	const callers = 12
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			errs <- repo.AdmitPending(ctx, current, received)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent identical admission: %v", err)
		}
	}
	history, err := repo.ListTransitions(ctx, fixture.engagement, fixture.detection)
	if err != nil || len(history) != 1 || history[0].Kind != detectionprovenance.Received || history[0].Sequence != 1 {
		t.Fatalf("concurrent admission history=%#v err=%v; want one received transition", history, err)
	}
}

func TestDetectionProvenanceRepositoryConcurrentTransitionIsIdempotent(t *testing.T) {
	fixture := newDetectionProvenancePostgresFixture(t)
	ctx := shared.WithTenant(context.Background(), fixture.tenant)
	repo := mustNewDetectionProvenanceRepository(t, fixture.pool)
	current, received := fixture.admission(t)
	if err := repo.AdmitPending(ctx, current, received); err != nil {
		t.Fatalf("admit pending: %v", err)
	}
	durable := detectionprovenance.Transition{
		TenantID: fixture.tenant, EngagementID: fixture.engagement, DetectionID: fixture.detection, Sequence: 2,
		Kind: detectionprovenance.TelemetryDurable, Status: detectionprovenance.StatusPending,
		Reason: "causal telemetry durable", OccurredAt: fixture.at.Add(time.Minute),
	}

	const callers = 12
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			errs <- repo.AppendTransition(ctx, durable)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent identical transition: %v", err)
		}
	}
	history, err := repo.ListTransitions(ctx, fixture.engagement, fixture.detection)
	if err != nil || len(history) != 2 || history[1].Kind != detectionprovenance.TelemetryDurable || history[1].Sequence != 2 {
		t.Fatalf("concurrent transition history=%#v err=%v; want received then one durable transition", history, err)
	}
}
