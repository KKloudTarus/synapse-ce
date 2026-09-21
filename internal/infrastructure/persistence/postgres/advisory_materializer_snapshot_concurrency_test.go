package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAdvisoryMaterializerPostgresSnapshotLockSerializesLaterMaterialize(t *testing.T) {
	fixture := newAdvisorySnapshotPostgresFixture(t)
	ctx := fixture.ctx
	advisoryID := fixture.advisoryID()
	initial := fixture.record(advisoryID, "initial")
	if _, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{initial}); err != nil {
		t.Fatalf("seed authoritative snapshot: %v", err)
	}

	// Holding the existing alias makes the snapshot stop after it has acquired its table
	// lock and written the first uncommitted observation, without adding a production hook.
	aliasBarrier := holdAdvisorySnapshotBarrier(t, ctx, fixture.pool,
		`SELECT alias_id FROM advisory_aliases WHERE alias_id=$1 FOR UPDATE`, advisoryID)
	snapshot := initial
	snapshot.Observation.Advisory.Summary = "snapshot"
	snapshotDone := make(chan error, 1)
	go func() {
		_, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{snapshot})
		snapshotDone <- err
	}()
	waitForAdvisorySnapshotTableLock(t, ctx, fixture.pool, "ShareRowExclusiveLock", true)
	waitForAdvisoryAliasLockWait(t, ctx, fixture.pool)

	ordinary := initial
	ordinary.Observation.Advisory.Summary = "ordinary"
	ordinaryDone := make(chan error, 1)
	go func() {
		_, err := fixture.materializer.Materialize(ctx, []advisory.ObservationRecord{ordinary})
		ordinaryDone <- err
	}()
	waitForAdvisorySnapshotTableLock(t, ctx, fixture.pool, "RowExclusiveLock", false)

	if err := aliasBarrier.Release(ctx); err != nil {
		t.Fatalf("release snapshot alias barrier: %v", err)
	}
	if err := waitForAdvisorySnapshotOperation(t, ctx, snapshotDone, "snapshot publication"); err != nil {
		t.Fatalf("snapshot publication: %v", err)
	}
	if err := waitForAdvisorySnapshotOperation(t, ctx, ordinaryDone, "ordinary materialization"); err != nil {
		t.Fatalf("ordinary materialization: %v", err)
	}

	canonical, err := fixture.materializer.GetCanonical(ctx, advisoryID)
	if err != nil || canonical.Advisory.Summary != "ordinary" {
		t.Fatalf("final canonical=%+v err=%v, want later ordinary write", canonical, err)
	}
	var current int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM advisory_observations WHERE source_id=$1 AND record_id=$2 AND is_current`, fixture.sourceID.String(), initial.Observation.RecordID).Scan(&current); err != nil || current != 1 {
		t.Fatalf("current observation count=%d err=%v, want 1", current, err)
	}
}

func TestAdvisoryMaterializerPostgresSnapshotLockAllowsCommittedApplicationReads(t *testing.T) {
	fixture := newAdvisorySnapshotPostgresFixture(t)
	ctx := fixture.ctx
	firstID := fixture.advisoryID()
	secondID := fixture.advisoryID()
	first := fixture.record(firstID, "before first")
	second := fixture.record(secondID, "before second")
	if _, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{first, second}); err != nil {
		t.Fatalf("seed authoritative snapshot: %v", err)
	}

	aliasBarrier := holdAdvisorySnapshotBarrier(t, ctx, fixture.pool,
		`SELECT alias_id FROM advisory_aliases WHERE alias_id=$1 FOR UPDATE`, firstID)
	retired := first
	retired.Observation.Advisory.Summary = ""
	retired.Observation.Advisory.Affected = nil
	retired.Observation.AbsenceRetirement = true
	replacement := second
	replacement.Observation.Advisory.Summary = "after second"
	snapshotDone := make(chan error, 1)
	go func() {
		_, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{retired, replacement})
		snapshotDone <- err
	}()
	waitForAdvisorySnapshotTableLock(t, ctx, fixture.pool, "ShareRowExclusiveLock", true)
	waitForAdvisoryAliasLockWait(t, ctx, fixture.pool)

	var before []string
	if err := fixture.materializer.CurrentSourceRecordIDsBounded(ctx, fixture.sourceID.String(), 2, func(recordID string) error {
		before = append(before, recordID)
		return nil
	}); err != nil || len(before) != 2 || before[0] != first.Observation.RecordID || before[1] != second.Observation.RecordID {
		t.Fatalf("application read during snapshot=%v err=%v, want committed records", before, err)
	}
	canonical, err := fixture.materializer.GetCanonical(ctx, firstID)
	if err != nil || canonical.Advisory.Summary != "before first" {
		t.Fatalf("canonical read during snapshot=%+v err=%v, want committed state", canonical, err)
	}

	if err := aliasBarrier.Release(ctx); err != nil {
		t.Fatalf("release snapshot alias barrier: %v", err)
	}
	if err := waitForAdvisorySnapshotOperation(t, ctx, snapshotDone, "snapshot publication"); err != nil {
		t.Fatalf("snapshot publication: %v", err)
	}
	var after []string
	if err := fixture.materializer.CurrentSourceRecordIDsBounded(ctx, fixture.sourceID.String(), 2, func(recordID string) error {
		after = append(after, recordID)
		return nil
	}); err != nil || len(after) != 1 || after[0] != second.Observation.RecordID {
		t.Fatalf("application read after snapshot=%v err=%v, want only active replacement", after, err)
	}
}

func TestAdvisoryMaterializerPostgresSnapshotLockCancellationRollsBackPublication(t *testing.T) {
	fixture := newAdvisorySnapshotPostgresFixture(t)
	ctx := fixture.ctx
	advisoryID := fixture.advisoryID()
	initial := fixture.record(advisoryID, "initial")
	if _, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{initial}); err != nil {
		t.Fatalf("seed authoritative snapshot: %v", err)
	}

	tableBarrier := holdAdvisorySnapshotBarrier(t, ctx, fixture.pool,
		`LOCK TABLE advisory_observations IN SHARE ROW EXCLUSIVE MODE`)
	publicationCtx, cancel := context.WithCancel(shared.WithTenant(ctx, fixture.tenantID))
	defer cancel()
	replacement := initial
	replacement.Observation.Advisory.Summary = "replacement"
	replacement.SyncRunID = fixture.runID.String()
	publicationDone := make(chan error, 1)
	go func() {
		_, err := fixture.materializer.PublishSourceSnapshot(publicationCtx, ports.SourceSnapshotPublication{
			SyncRunID: fixture.runID, NextCheckpoint: []byte(`{"cursor":"next"}`),
		}, []advisory.ObservationRecord{replacement})
		publicationDone <- err
	}()
	waitForAdvisorySnapshotTableLock(t, ctx, fixture.pool, "ShareRowExclusiveLock", false)

	cancel()
	if err := waitForAdvisorySnapshotOperation(t, ctx, publicationDone, "cancelled snapshot publication"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot publication error=%v, want context cancellation", err)
	}
	if err := tableBarrier.Release(ctx); err != nil {
		t.Fatalf("release snapshot table barrier: %v", err)
	}

	canonical, err := fixture.materializer.GetCanonical(ctx, advisoryID)
	if err != nil || canonical.Advisory.Summary != "initial" {
		t.Fatalf("canonical after cancelled publication=%+v err=%v, want prior committed state", canonical, err)
	}
	var currentObservations int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM advisory_observations WHERE source_id=$1 AND is_current`, fixture.sourceID.String()).Scan(&currentObservations); err != nil || currentObservations != 1 {
		t.Fatalf("current observations after cancelled publication=%d err=%v, want 1", currentObservations, err)
	}
	var receipts int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_source_snapshot_publications WHERE sync_run_id=$1`, fixture.runID.String()).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("publication receipts after cancellation=%d err=%v, want 0", receipts, err)
	}
}

func TestAdvisoryMaterializerPostgresSnapshotLockCancellationLateBatchRollsBackPublication(t *testing.T) {
	fixture := newAdvisorySnapshotPostgresFixture(t)
	ctx := fixture.ctx
	count := advisory.MaxMaterializationBatch + 1
	ids := make([]string, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("CVE-2026-SNAPSHOT-%s-%04d", fixture.suffix, index)
		fixture.advisoryIDs = append(fixture.advisoryIDs, ids[index])
	}
	lastID := ids[len(ids)-1]
	initial := fixture.record(lastID, "initial")
	if _, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{initial}); err != nil {
		t.Fatalf("seed authoritative snapshot: %v", err)
	}

	aliasBarrier := holdAdvisorySnapshotBarrier(t, ctx, fixture.pool,
		`SELECT alias_id FROM advisory_aliases WHERE alias_id=$1 FOR UPDATE`, lastID)
	publicationCtx, cancel := context.WithCancel(shared.WithTenant(ctx, fixture.tenantID))
	defer cancel()
	records := make([]advisory.ObservationRecord, count)
	for index, advisoryID := range ids {
		records[index] = fixture.record(advisoryID, "replacement")
		records[index].SyncRunID = fixture.runID.String()
	}
	publicationDone := make(chan error, 1)
	go func() {
		_, err := fixture.materializer.PublishSourceSnapshot(publicationCtx, ports.SourceSnapshotPublication{
			SyncRunID: fixture.runID, NextCheckpoint: []byte(`{"cursor":"next"}`),
		}, records)
		publicationDone <- err
	}()
	waitForAdvisoryAliasLockWait(t, ctx, fixture.pool)

	cancel()
	if err := waitForAdvisorySnapshotOperation(t, ctx, publicationDone, "cancelled late-batch snapshot publication"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled late-batch snapshot publication error=%v, want context cancellation", err)
	}
	if err := aliasBarrier.Release(ctx); err != nil {
		t.Fatalf("release snapshot alias barrier: %v", err)
	}

	canonical, err := fixture.materializer.GetCanonical(ctx, lastID)
	if err != nil || canonical.Advisory.Summary != "initial" {
		t.Fatalf("canonical after cancelled publication=%+v err=%v, want prior committed state", canonical, err)
	}
	var revisions, observations, receipts, receiptResults, links int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM advisory_revisions WHERE advisory_id=ANY($1::text[])`, ids).Scan(&revisions); err != nil || revisions != 1 {
		t.Fatalf("revisions after cancelled publication=%d err=%v, want 1 initial revision", revisions, err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM advisory_observations WHERE source_id=$1 AND is_current`, fixture.sourceID.String()).Scan(&observations); err != nil || observations != 1 {
		t.Fatalf("current observations after cancelled publication=%d err=%v, want 1 initial observation", observations, err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_source_snapshot_publications WHERE sync_run_id=$1`, fixture.runID.String()).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("publication receipts after cancellation=%d err=%v, want 0", receipts, err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_source_snapshot_results WHERE sync_run_id=$1`, fixture.runID.String()).Scan(&receiptResults); err != nil || receiptResults != 0 {
		t.Fatalf("publication receipt results after cancellation=%d err=%v, want 0", receiptResults, err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM advisory_revision_sync_runs WHERE sync_run_id=$1`, fixture.runID.String()).Scan(&links); err != nil || links != 0 {
		t.Fatalf("revision links after cancellation=%d err=%v, want 0", links, err)
	}
}

func TestAdvisoryMaterializerPostgresSnapshotLockValidatesAfterEarlierWriter(t *testing.T) {
	fixture := newAdvisorySnapshotPostgresFixture(t)
	ctx := fixture.ctx
	advisoryID := fixture.advisoryID()
	initial := fixture.record(advisoryID, "initial")
	if _, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{initial}); err != nil {
		t.Fatalf("seed authoritative snapshot: %v", err)
	}

	aliasBarrier := holdAdvisorySnapshotBarrier(t, ctx, fixture.pool,
		`SELECT alias_id FROM advisory_aliases WHERE alias_id=$1 FOR UPDATE`, advisoryID)
	legacy := initial
	legacy.Observation.Advisory.Summary = "legacy"
	legacy.Observation.Advisory.Aliases = []string{"LEGACY-" + fixture.suffix}
	ordinaryDone := make(chan error, 1)
	go func() {
		_, err := fixture.materializer.Materialize(ctx, []advisory.ObservationRecord{legacy})
		ordinaryDone <- err
	}()
	waitForAdvisoryAliasLockWait(t, ctx, fixture.pool)

	snapshot := initial
	snapshot.Observation.Advisory.Summary = "snapshot"
	snapshotDone := make(chan error, 1)
	go func() {
		_, err := fixture.materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{snapshot})
		snapshotDone <- err
	}()
	waitForAdvisorySnapshotTableLock(t, ctx, fixture.pool, "ShareRowExclusiveLock", false)

	if err := aliasBarrier.Release(ctx); err != nil {
		t.Fatalf("release ordinary alias barrier: %v", err)
	}
	if err := waitForAdvisorySnapshotOperation(t, ctx, ordinaryDone, "ordinary materialization"); err != nil {
		t.Fatalf("ordinary materialization: %v", err)
	}
	if err := waitForAdvisorySnapshotOperation(t, ctx, snapshotDone, "snapshot publication"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("snapshot after earlier legacy writer error=%v, want validation error", err)
	}

	canonical, err := fixture.materializer.GetCanonical(ctx, advisoryID)
	if err != nil || canonical.Advisory.Summary != "legacy" {
		t.Fatalf("final canonical=%+v err=%v, want earlier ordinary writer", canonical, err)
	}
}

type advisorySnapshotPostgresFixture struct {
	ctx          context.Context
	pool         *pgxpool.Pool
	materializer *AdvisoryMaterializer
	sourceID     shared.ID
	tenantID     shared.ID
	jobID        string
	runID        shared.ID
	suffix       string
	advisoryIDs  []string
}

func newAdvisorySnapshotPostgresFixture(t *testing.T) *advisorySnapshotPostgresFixture {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	fixture := &advisorySnapshotPostgresFixture{
		ctx:          ctx,
		pool:         pool,
		materializer: NewAdvisoryMaterializer(pool),
		sourceID:     shared.ID("src-snapshot-lock-" + suffix),
		tenantID:     shared.ID("tenant-snapshot-lock-" + suffix),
		jobID:        "job-snapshot-lock-" + suffix,
		runID:        shared.ID("run-snapshot-lock-" + suffix),
		suffix:       strings.ToUpper(suffix),
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES($1,$2,$2,'oval',$3,3600,7200,'full')`, fixture.sourceID.String(), "oval-snapshot-lock-"+suffix, "https://example.test/"+fixture.sourceID.String()); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, fixture.tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status) VALUES($1,$2,'vulnerability_sync','{}','queued')`, fixture.jobID, fixture.tenantID.String()); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sync_runs(id,source_id,adapter_type,mode,trigger,actor,durable_job_id,state)
		VALUES($1,$2,'oval','full','manual','test',$3,'queued')`, fixture.runID.String(), fixture.sourceID.String(), fixture.jobID); err != nil {
		t.Fatalf("seed sync run: %v", err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`DELETE FROM advisory_observations WHERE source_id=$1`, []any{fixture.sourceID.String()}},
			{`DELETE FROM advisories WHERE id=ANY($1::text[])`, []any{fixture.advisoryIDs}},
			{`DELETE FROM vulnerability_sync_runs WHERE id=$1`, []any{fixture.runID.String()}},
			{`DELETE FROM jobs WHERE id=$1`, []any{fixture.jobID}},
			{`DELETE FROM tenants WHERE id=$1`, []any{fixture.tenantID.String()}},
			{`DELETE FROM vulnerability_sources WHERE id=$1`, []any{fixture.sourceID.String()}},
		} {
			if _, err := pool.Exec(cleanup, statement.query, statement.args...); err != nil {
				t.Errorf("cleanup advisory snapshot fixture: %v", err)
			}
		}
	})
	return fixture
}

func (f *advisorySnapshotPostgresFixture) advisoryID() string {
	id := fmt.Sprintf("CVE-2026-SNAPSHOT-%s-%d", f.suffix, len(f.advisoryIDs)+1)
	f.advisoryIDs = append(f.advisoryIDs, id)
	return id
}

func (f *advisorySnapshotPostgresFixture) record(advisoryID, summary string) advisory.ObservationRecord {
	record := postgresObservationRecord(f.sourceID.String(), advisoryID, advisoryID, summary)
	record.Observation.SourceType = "oval"
	return record
}

type advisorySnapshotBarrier struct {
	conn     *pgxpool.Conn
	tx       pgx.Tx
	released bool
}

func holdAdvisorySnapshotBarrier(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) *advisorySnapshotBarrier {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire snapshot barrier connection: %v", err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		conn.Release()
		t.Fatalf("begin snapshot barrier: %v", err)
	}
	if _, err := tx.Exec(ctx, query, args...); err != nil {
		_ = tx.Rollback(ctx)
		conn.Release()
		t.Fatalf("acquire snapshot barrier: %v", err)
	}
	barrier := &advisorySnapshotBarrier{conn: conn, tx: tx}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := barrier.Release(cleanupCtx); err != nil {
			t.Errorf("release snapshot barrier during cleanup: %v", err)
		}
	})
	return barrier
}

func (b *advisorySnapshotBarrier) Release(ctx context.Context) error {
	if b.released {
		return nil
	}
	b.released = true
	err := b.tx.Rollback(ctx)
	b.conn.Release()
	return err
}

func waitForAdvisorySnapshotTableLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, mode string, granted bool) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var found bool
		err := pool.QueryRow(waitCtx, `SELECT EXISTS(
			SELECT 1 FROM pg_locks
			WHERE relation='advisory_observations'::regclass AND mode=$1 AND granted=$2
		)`, mode, granted).Scan(&found)
		if err != nil {
			t.Fatalf("inspect advisory observation locks: %v", err)
		}
		if found {
			return
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("did not observe %s granted=%t on advisory_observations: %v", mode, granted, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func waitForAdvisoryAliasLockWait(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := pool.QueryRow(waitCtx, `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity
			WHERE wait_event_type='Lock'
				AND query LIKE '%FROM advisory_aliases WHERE alias_id = ANY%'
		)`).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect advisory alias lock wait: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("did not observe advisory alias lock wait: %v", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func waitForAdvisorySnapshotOperation(t *testing.T, ctx context.Context, done <-chan error, operation string) error {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case err := <-done:
		return err
	case <-waitCtx.Done():
		t.Fatalf("%s did not complete: %v", operation, waitCtx.Err())
		return nil
	}
}
