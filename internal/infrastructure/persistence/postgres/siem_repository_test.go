package postgres

import (
	"bytes"
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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/observability"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/siem/ocsf"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
)

func TestSIEMPostgresSinkWritesAndExpiredLeaseAdoption(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN for PostgreSQL regression")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	id := fmt.Sprintf("siem-fix-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1)`, id); err != nil {
		t.Fatal(err)
	}
	tenantCtx := shared.WithTenant(ctx, shared.ID(id))
	repo := NewSIEMRepository(pool)
	now := time.Now().UTC()
	sink := siem.Sink{
		ID: shared.ID(id), TenantID: shared.ID(id), Name: "Regression", Provider: siem.ProviderSplunk,
		Origin: "https://splunk.example", Target: "/services/collector/event", DataClass: siem.ClassSignal,
		AckMode: siem.AckHECAcceptance, Enabled: true, Generation: 1, SecretVersion: 1,
		Version: 1, Channel: "channel", CreatedAt: now, UpdatedAt: now,
	}
	if err := repo.CreateSink(tenantCtx, sink, "sealed"); err != nil {
		t.Fatalf("create with omitted allow_hosts: %v", err)
	}
	if other, err := repo.GetSink(shared.WithTenant(ctx, "default"), sink.ID); err == nil {
		t.Fatalf("cross-tenant read returned sink %+v", other)
	}
	sink.Version++
	sink.Paused = true
	if err := repo.UpdateSink(tenantCtx, sink, 1); err != nil {
		t.Fatalf("update sink: %v", err)
	}
	sink.Paused = false
	sink.Version++
	if err := repo.UpdateSink(tenantCtx, sink, 2); err != nil {
		t.Fatalf("resume sink: %v", err)
	}
	leaseA, err := repo.Claim(tenantCtx, "worker-a", sink, siem.SourceIncidentLive, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pos := siem.Position{Source: siem.SourceIncidentLive, Phase: siem.PhaseLive, StreamSeq: 1, IncidentID: "incident", EventSeq: 1}
	batch := siem.Batch{
		ID: shared.ID(id + "-batch"), TenantID: sink.TenantID, SinkID: sink.ID,
		Source: siem.SourceIncidentLive, Generation: 1, LeaseToken: leaseA.Token,
		State: siem.BatchPrepared, PolicyVersion: "signal/v1", MappingVersion: "v1",
		Items: []siem.BatchItem{{Ordinal: 0, RecordID: "record", Position: pos,
			Disposition: siem.ItemPending, PayloadDigest: "digest", DataClass: siem.ClassSignal}},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := repo.SaveBatch(tenantCtx, batch, []string{"sealed-payload"}); err != nil {
		t.Fatal(err)
	}
	zeroAckID := int64(0)
	batch.State = siem.BatchAwaitingAck
	batch.IndexerAckID = &zeroAckID
	if err := repo.SaveBatch(tenantCtx, batch, nil); err != nil {
		t.Fatalf("persist indexer receipt zero: %v", err)
	}
	leaseB, err := repo.Claim(tenantCtx, "worker-b", sink, siem.SourceIncidentLive, now.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	adopted, _, ok, err := repo.OpenBatch(tenantCtx, sink.ID, siem.SourceIncidentLive)
	if err != nil || !ok || adopted.LeaseToken != leaseB.Token || leaseB.Token <= leaseA.Token ||
		adopted.State != siem.BatchAwaitingAck || adopted.IndexerAckID == nil || *adopted.IndexerAckID != 0 {
		t.Fatalf("expired batch was not adopted: batch=%+v lease=%+v err=%v", adopted, leaseB, err)
	}
	if err := repo.SaveBatch(tenantCtx, batch, nil); err != siem.ErrStaleLease {
		t.Fatalf("stale owner overwrote adopted batch: %v", err)
	}
	adopted.State = siem.BatchAcked
	adopted.IndexerAckID = nil
	adopted.Items[0].Disposition = siem.ItemAcked
	cp := siem.Checkpoint{SinkID: sink.ID, TenantID: sink.TenantID, Source: siem.SourceIncidentLive,
		Generation: 1, Position: pos, UpdatedAt: now.Add(2 * time.Second)}
	if err := repo.Commit(tenantCtx, leaseB, adopted, cp, now.Add(2*time.Second)); err != nil {
		t.Fatalf("adopted batch could not commit: %v", err)
	}
	if err := repo.Release(tenantCtx, leaseB); err != nil {
		t.Fatal(err)
	}
	leaseC, err := repo.Claim(tenantCtx, "worker-c", sink, siem.SourceIncidentLive, now.Add(3*time.Second), time.Minute)
	if err != nil || leaseC.Token <= leaseB.Token {
		t.Fatalf("lease token reused after release: %+v %v", leaseC, err)
	}
	fault := errors.New("injected audit failure")
	err = NewTenantTransactionRunner(pool).Run(tenantCtx, sink.TenantID, func(txCtx context.Context) error {
		if err := repo.PutSecret(txCtx, sink.ID, 2, "new-sealed"); err != nil {
			return err
		}
		changed := sink
		changed.Version++
		changed.SecretVersion = 2
		if err := repo.UpdateSink(txCtx, changed, sink.Version); err != nil {
			return err
		}
		if err := NewAuditLog(pool).Record(txCtx, ports.AuditEntry{
			Actor: "ada", Action: "siem.sink.rotate_secret", Target: sink.ID.String(), At: now,
			Metadata: map[string]string{"provider": string(sink.Provider)},
		}); err != nil {
			return err
		}
		return fault
	})
	if !errors.Is(err, fault) {
		t.Fatalf("fault was not returned: %v", err)
	}
	stored, err := repo.GetSink(tenantCtx, sink.ID)
	if err != nil || stored.Version != sink.Version || stored.SecretVersion != 1 {
		t.Fatalf("rolled back secret rotation changed sink: %+v %v", stored, err)
	}
	if _, err := repo.GetSecret(tenantCtx, sink.ID, 2); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rolled back secret rotation left a credential: %v", err)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action=$2`, id, "siem.sink.rotate_secret").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 0 {
		t.Fatalf("rolled back config mutation left %d audit rows", audits)
	}
}

func TestSIEMCaptureActivationAndRetainedAnchor(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN for PostgreSQL regression")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	id := fmt.Sprintf("siem-capture-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1)`, id); err != nil {
		t.Fatal(err)
	}
	appendIncident := func(name string) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO incident_events
			(tenant_id, incident_id, seq, kind, occurred_at, actor, payload)
			VALUES ($1,$2,1,'created',$3,'tester','{"Severity":"high","Title":"Detected"}')`,
			id, name, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
	}
	countCapture := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM siem_incident_capture WHERE tenant_id=$1`, id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	appendIncident("before-sink")
	if got := countCapture(); got != 0 {
		t.Fatalf("no-sink tenant captured %d events", got)
	}
	repo := NewSIEMRepository(pool)
	tenantCtx := shared.WithTenant(ctx, shared.ID(id))
	now := time.Now().UTC()
	sink := siem.Sink{ID: shared.ID(id + "-sink-1"), TenantID: shared.ID(id), Name: "First",
		Provider: siem.ProviderSplunk, Origin: "https://splunk.example", Target: "/services/collector/event",
		DataClass: siem.ClassSignal, AckMode: siem.AckHECAcceptance, Enabled: true,
		Generation: 1, SecretVersion: 1, Version: 1, Channel: "channel", CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateSink(tenantCtx, sink, "sealed"); err != nil {
		t.Fatal(err)
	}
	disabled := false
	disabledPool, err := ConnectPool(ctx, dsn, PoolConfig{SIEMCaptureEnabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	defer disabledPool.Close()
	if err := WithTenant(ctx, disabledPool, id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO incident_events
			(tenant_id, incident_id, seq, kind, occurred_at, actor, payload)
			VALUES ($1,'disabled',1,'created',$2,'tester','{}')`, id, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := countCapture(); got != 0 {
		t.Fatalf("kill switch captured %d events", got)
	}
	enabled := true
	enabledPool, err := ConnectPool(ctx, dsn, PoolConfig{SIEMCaptureEnabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	defer enabledPool.Close()
	if err := WithTenant(ctx, enabledPool, id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO incident_events
			(tenant_id, incident_id, seq, kind, occurred_at, actor, payload)
			VALUES ($1,'one',1,'created',$2,'tester','{}')`, id, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"two", "three"} {
		appendIncident(name)
	}
	if got := countCapture(); got != 3 {
		t.Fatalf("active tenant captured %d events", got)
	}
	backlog, err := repo.AggregateBacklog(tenantCtx)
	if err != nil || backlog[siem.SourceIncidentLive].Records != 3 {
		t.Fatalf("aggregate live backlog: %+v err=%v", backlog, err)
	}
	cp := siem.Checkpoint{SinkID: sink.ID, TenantID: sink.TenantID, Source: siem.SourceIncidentLive,
		Generation: 1, Position: siem.Position{Source: siem.SourceIncidentLive,
			Phase: siem.PhaseLive, StreamSeq: 3, IncidentID: "three", EventSeq: 1}, UpdatedAt: now}
	if err := repo.ResetPartition(tenantCtx, sink, siem.SourceIncidentLive, cp); err != nil {
		t.Fatal(err)
	}
	if err := repo.Prune(tenantCtx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := countCapture(); got != 1 {
		t.Fatalf("retention did not keep exactly the cursor anchor: %d", got)
	}
	second := sink
	second.ID = shared.ID(id + "-sink-2")
	second.Name = "Second"
	if err := repo.CreateSink(tenantCtx, second, "sealed"); err != nil {
		t.Fatal(err)
	}
	seeded, found, err := repo.Checkpoint(tenantCtx, second.ID, siem.SourceIncidentLive)
	if err != nil || !found || seeded.Position.StreamSeq != 3 {
		t.Fatalf("new sink did not start at retained anchor: %+v found=%v err=%v", seeded, found, err)
	}
	var pruned int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM siem_incident_pruned WHERE tenant_id=$1`, id).Scan(&pruned); err != nil {
		t.Fatal(err)
	}
	if pruned != 2 {
		t.Fatalf("pruned identities = %d, want 2", pruned)
	}
	filled, err := repo.BackfillIncidents(tenantCtx, 50)
	if err != nil {
		t.Fatal(err)
	}
	// before-sink and the kill-switch event were never captured. Backfill may
	// copy those. The two identities retention removed must stay gone.
	if filled != 2 {
		t.Fatalf("backfill after prune wrote %d rows, want the two never-captured events", filled)
	}
	var revived int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM siem_incident_capture WHERE tenant_id=$1 AND incident_id IN ('one','two')`, id).Scan(&revived); err != nil {
		t.Fatal(err)
	}
	if revived != 0 {
		t.Fatalf("pruned identities were captured again: %d", revived)
	}
	again, err := repo.BackfillIncidents(tenantCtx, 50)
	if err != nil || again != 0 {
		t.Fatalf("second backfill = %d err=%v", again, err)
	}
	var liveNext, histNext int64
	if err := pool.QueryRow(ctx, `SELECT live_next, hist_next FROM siem_incident_counters WHERE tenant_id=$1`, id).Scan(&liveNext, &histNext); err != nil {
		t.Fatal(err)
	}
	if liveNext < 4 || histNext <= 1 {
		t.Fatalf("incident counter was reset: live=%d historical=%d", liveNext, histNext)
	}
}

func TestSIEMBackfillWaitsForRetentionLock(t *testing.T) {
	pool, tenantCtx, id := siemTestTenant(t, "siem-lock")
	ctx := context.Background()
	repo := NewSIEMRepository(pool)
	holdCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	started := make(chan struct{})
	var startOnce sync.Once
	holdErr := make(chan error, 1)
	go func() {
		holdErr <- WithTenant(holdCtx, pool, id, func(tx pgx.Tx) error {
			if _, err := tx.Exec(holdCtx, `SELECT pg_advisory_xact_lock(1484, hashtext($1))`, id); err != nil {
				return err
			}
			startOnce.Do(func() { close(started) })
			<-holdCtx.Done()
			return holdCtx.Err()
		})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("retention lock holder did not start")
	}
	done := make(chan error, 1)
	go func() {
		_, err := repo.BackfillIncidents(tenantCtx, 10)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND wait_event='advisory'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			waiting = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("backfill did not wait on the retention lock")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("backfill after lock release: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backfill did not finish after the retention lock was released")
	}
	if err := <-holdErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("lock holder: %v", err)
	}
}

func TestSIEMPostgresIndexerAckAndMetrics(t *testing.T) {
	pool, tenantCtx, id := siemTestTenant(t, "siem-ack")
	ctx := context.Background()
	repo := NewSIEMRepository(pool)
	now := time.Now().UTC()
	sink := siem.Sink{
		ID: shared.ID(id + "-sink"), TenantID: shared.ID(id), Name: "Ack", Provider: siem.ProviderSplunk,
		Origin: "https://splunk.example", Target: "/services/collector/event", DataClass: siem.ClassSignal,
		AckMode: siem.AckIndexer, IndexerAckSupported: true, Enabled: true, Generation: 1, SecretVersion: 1,
		Version: 1, Channel: "channel", CreatedAt: now, UpdatedAt: now,
	}
	if err := repo.CreateSink(tenantCtx, sink, "sealed-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO incident_events
		(tenant_id, incident_id, seq, kind, occurred_at, actor, payload)
		VALUES ($1,'incident-1',1,'created',$2,'tester','{"Severity":"high","Title":"Detected"}')`,
		id, now); err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewRegistry()
	metrics := observability.NewSIEMMetrics(registry)
	driver := &siemAckDriver{}
	clock := &siemMovingClock{now: now}
	schema, err := ocsf.New()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := siemuc.NewService(repo, repo, siemOnlyTenant{id: shared.ID(id)}, siemEchoSealer{}, map[siem.Provider]ports.SIEMDriver{
		siem.ProviderSplunk: driver,
	}, nil, clock, &siemSeqIDs{}, schema)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetMetrics(metrics)
	svc.SetRNG(func() float64 { return 0 })
	stats, err := svc.Tick(tenantCtx, "siem-pg", siemuc.TickBudget{MaxPartitions: 8, Deadline: clock.now.Add(5 * time.Second)})
	if err != nil {
		t.Fatalf("first tick: %v %+v", err, stats)
	}
	if driver.posts != 1 || driver.polls != 0 {
		t.Fatalf("first tick posts=%d polls=%d", driver.posts, driver.polls)
	}
	var state string
	var ackID *int64
	if err := pool.QueryRow(ctx, `SELECT state, indexer_ack_id FROM siem_batches WHERE tenant_id=$1 AND source='incident_live'`, id).Scan(&state, &ackID); err != nil {
		t.Fatal(err)
	}
	if state != string(siem.BatchAwaitingAck) || ackID == nil || *ackID != 0 {
		t.Fatalf("receipt was not stored: state=%s ack=%v", state, ackID)
	}
	clock.now = clock.now.Add(2 * time.Second)
	stats, err = svc.Tick(tenantCtx, "siem-pg", siemuc.TickBudget{MaxPartitions: 8, Deadline: clock.now.Add(5 * time.Second)})
	if err != nil {
		t.Fatalf("second tick: %v %+v", err, stats)
	}
	if driver.posts != 1 || driver.polls != 1 {
		t.Fatalf("ack poll posted again or skipped the receipt: posts=%d polls=%d", driver.posts, driver.polls)
	}
	var cursor int64
	if err := pool.QueryRow(ctx, `SELECT (position->>'StreamSeq')::bigint FROM siem_checkpoints WHERE tenant_id=$1 AND sink_id=$2 AND source='incident_live'`, id, sink.ID.String()).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 1 {
		t.Fatalf("checkpoint stream seq = %d, want 1", cursor)
	}
	if got := siemSample(t, registry, "synapse_siem_items_total", map[string]string{"provider": "splunk_hec", "disposition": "acked"}); got != 1 {
		t.Fatalf("acked metric = %v, want 1", got)
	}
	if got := siemSample(t, registry, "synapse_siem_dropped_total", map[string]string{"provider": "splunk_hec", "disposition": "acked"}); got != 0 {
		t.Fatalf("acked metric was also dropped: %v", got)
	}
	if !siemFamilyPresent(t, registry, "synapse_siem_backlog_age_seconds") {
		t.Fatal("worker metrics registry did not expose backlog age")
	}
}

func TestSIEMMigrationAndTenantIsolation(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	var table string
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public.siem_sinks')::text`).Scan(&table); err != nil || table == "" {
		t.Fatalf("siem_sinks missing after migrate: %v %q", err, table)
	}
	var trigger string
	if err := admin.QueryRow(ctx, `SELECT tgname FROM pg_trigger WHERE tgname = 'siem_incident_events_capture'`).Scan(&trigger); err != nil {
		t.Fatalf("capture trigger missing: %v", err)
	}
	var indexValid bool
	if err := admin.QueryRow(ctx, `SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'siem_audit_v2_keyset_idx'`).Scan(&indexValid); err != nil || !indexValid {
		t.Fatalf("audit keyset index valid=%v err=%v", indexValid, err)
	}
	var functionBody string
	if err := admin.QueryRow(ctx, `SELECT pg_get_functiondef('siem_capture_incident_event()'::regprocedure)`).Scan(&functionBody); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(functionBody, "pg_advisory_xact_lock") {
		t.Fatal("capture function does not take the retention lock")
	}
	var prunedTable string
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public.siem_incident_pruned')::text`).Scan(&prunedTable); err != nil || prunedTable == "" {
		t.Fatalf("siem_incident_pruned missing: %v %q", err, prunedTable)
	}
	const role = "synapse_siem_rls_test"
	_, _ = admin.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = admin.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	if _, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD 'test-password' NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT SELECT ON tenants, audit_log TO `+role); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT SELECT, INSERT, UPDATE, DELETE ON siem_sinks, siem_sink_secrets, siem_checkpoints, siem_leases, siem_batches, siem_batch_items, siem_incident_counters, siem_incident_capture, siem_incident_pruned TO `+role); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = role
	config.ConnConfig.Password = "test-password"
	restricted, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)
	repo := NewSIEMRepository(restricted)
	if _, err := repo.ListSinks(shared.WithTenant(ctx, "tenant-a")); err != nil {
		t.Fatal(err)
	}

	// Exercise the source reader through the same non-bypass RLS connection.
	now := time.Now().UTC().Truncate(time.Microsecond)
	tenantA := fmt.Sprintf("siem-source-a-%d", now.UnixNano())
	tenantB := fmt.Sprintf("siem-source-b-%d", now.UnixNano())
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := admin.Begin(cleanupCtx)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = tx.Rollback(cleanupCtx) }()
		if _, err := tx.Exec(cleanupCtx, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only`); err != nil {
			t.Error(err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM audit_log WHERE tenant_id IN ($1,$2)`, tenantA, tenantB); err != nil {
			t.Error(err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only`); err != nil {
			t.Error(err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Error(err)
		}
	})
	entry := ports.AuditEntry{Actor: "ada", Action: "finding.status", Target: "finding-a", At: now, Metadata: map[string]string{"engagement": "eng-a", "status": "remediated", "note": "PRIVATE-NOTE"}}
	if err := WithTenant(ctx, admin, tenantA, func(tx pgx.Tx) error { return appendTenantAudit(ctx, tx, tenantA, entry) }); err != nil {
		t.Fatal(err)
	}
	entry.Target = "finding-b"
	if err := WithTenant(ctx, admin, tenantB, func(tx pgx.Tx) error { return appendTenantAudit(ctx, tx, tenantB, entry) }); err != nil {
		t.Fatal(err)
	}
	rows, metadata, anchor, err := repo.ReadAudit(shared.WithTenant(ctx, shared.ID(tenantA)), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	verified, problem := siem.VerifyAuditContent(siem.Position{}, rows, metadata, anchor)
	if !problem.None() {
		t.Fatalf("source verification: %+v", problem)
	}
	var exported siem.Exported
	foundFinding := false
	for _, row := range verified {
		if row.Target == "finding-b" {
			t.Fatal("RLS source exposed another tenant")
		}
		if row.Target == "finding-a" {
			foundFinding = true
			if row.FindingID != "finding-a" || row.EngagementID != "eng-a" || row.FindingStatus != "remediated" || row.Severity != "" {
				t.Fatalf("wrong stored source facts: %+v", row)
			}
			exported = siem.ExportAudit(tenantA, row, siem.ClassSignal, nil, "")
			schema, err := ocsf.New()
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(exported.Body); err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(exported.Body, &doc); err != nil {
				t.Fatal(err)
			}
			if doc["activity_id"] != float64(3) || doc["severity_id"] != float64(0) || bytes.Contains(exported.Body, []byte("PRIVATE-NOTE")) {
				t.Fatalf("unsafe source export: %s", exported.Body)
			}
		}
	}
	if !foundFinding {
		t.Fatal("real stored finding audit was not exported")
	}
	replay, _, _, err := repo.ReadAudit(shared.WithTenant(ctx, shared.ID(tenantA)), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range replay {
		if row.Target == "finding-a" && !bytes.Equal(siem.ExportAudit(tenantA, row, siem.ClassSignal, nil, "").Body, exported.Body) {
			t.Fatal("source replay changed")
		}
	}
	ids, err := repo.TenantIDs(ctx)
	if err != nil || len(ids) == 0 {
		t.Fatalf("tenant directory: %v %v", ids, err)
	}
	if err := WithTenant(ctx, restricted, "tenant-a", func(tx pgx.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM siem_incident_pruned`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
}

func siemTestTenant(t *testing.T, prefix string) (*pgxpool.Pool, context.Context, string) {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN for PostgreSQL regression")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	id := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1,$1)`, id); err != nil {
		t.Fatal(err)
	}
	return pool, shared.WithTenant(ctx, shared.ID(id)), id
}

type siemOnlyTenant struct{ id shared.ID }

func (d siemOnlyTenant) TenantIDs(context.Context) ([]shared.ID, error) {
	return []shared.ID{d.id}, nil
}

type siemMovingClock struct{ now time.Time }

func (c *siemMovingClock) Now() time.Time { return c.now }

type siemSeqIDs struct{ n int }

func (s *siemSeqIDs) NewID() shared.ID {
	s.n++
	return shared.ID(fmt.Sprintf("siem-batch-%d", s.n))
}

type siemEchoSealer struct{}

func (siemEchoSealer) Seal(_ context.Context, plain, _ []byte) (string, error) {
	return "sealed:" + string(plain), nil
}

func (siemEchoSealer) Open(_ context.Context, ciphertext string, _ []byte) ([]byte, error) {
	return []byte(strings.TrimPrefix(ciphertext, "sealed:")), nil
}

type siemAckDriver struct {
	posts int
	polls int
}

func (d *siemAckDriver) Deliver(context.Context, siem.Delivery) (siem.DeliveryResult, error) {
	d.posts++
	zero := int64(0)
	return siem.DeliveryResult{IndexerAckID: &zero}, nil
}

func (d *siemAckDriver) PollAck(context.Context, siem.Delivery, int64) (bool, time.Duration, error) {
	d.polls++
	return true, 0, nil
}

func siemSample(t *testing.T, registry *prometheus.Registry, name string, want map[string]string) float64 {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			got := map[string]string{}
			for _, label := range metric.GetLabel() {
				got[label.GetName()] = label.GetValue()
			}
			match := true
			for key, value := range want {
				if got[key] != value {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			if metric.GetCounter() != nil {
				return metric.GetCounter().GetValue()
			}
			if metric.GetGauge() != nil {
				return metric.GetGauge().GetValue()
			}
		}
	}
	return 0
}

func siemFamilyPresent(t *testing.T, registry *prometheus.Registry, name string) bool {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == name && len(family.GetMetric()) > 0 {
			return true
		}
	}
	return false
}
