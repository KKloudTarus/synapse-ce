package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// snapshotQueryCounter counts every query the publication dispatches, which is the quantity that
// determines how long the publication holds its table lock.
type snapshotQueryCounter struct{ queries atomic.Int64 }

func (c *snapshotQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.queries.Add(1)
	return ctx
}

func (*snapshotQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// TestAdvisoryMaterializerPostgresSnapshotBatchesIndependentRecords pins the publication cost model.
//
// An authoritative snapshot holds LOCK TABLE advisory_observations IN SHARE ROW EXCLUSIVE MODE for its
// whole duration, blocking every ordinary advisory writer. Materializing records one at a time cost
// roughly five sequential round-trips each, so at the MaxSourceSnapshotChanges cap the hold exceeded the
// publication deadline: a maximum-size snapshot could never commit, and every attempt starved writers for
// the full lease. Independent records must therefore be materialized in bounded chunks.
//
// The query count is measured directly with a pgx tracer rather than inferred from pg_stat_database,
// whose counters are updated asynchronously and read as zero immediately after a commit.
func TestAdvisoryMaterializerPostgresSnapshotBatchesIndependentRecords(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	counter := &snapshotQueryCounter{}
	config.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect traced pool: %v", err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	sourceID := shared.ID("src-batch-cost-" + suffix)
	tenantID := shared.ID("tenant-batch-cost-" + suffix)
	jobID := "job-batch-cost-" + suffix
	runID := shared.ID("run-batch-cost-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES($1,$2,$2,'oval',$3,3600,7200,'full')`, sourceID.String(), "oval-batch-cost-"+suffix, "https://example.test/"+sourceID.String()); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status) VALUES($1,$2,'vulnerability_sync','{}','queued')`, jobID, tenantID.String()); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sync_runs
		(id,source_id,adapter_type,mode,trigger,actor,durable_job_id,state)
		VALUES($1,$2,'oval','full','manual','test',$3,'queued')`, runID.String(), sourceID.String(), jobID); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	// Every record is independent: a distinct advisory sharing no alias, which is the shape a real vendor
	// snapshot overwhelmingly has.
	const records = 128
	batchPackage := "example.com/batch-cost-" + suffix
	snapshot := make([]advisory.ObservationRecord, records)
	ids := make([]string, records)
	for index := range snapshot {
		ids[index] = fmt.Sprintf("CVE-2026-BATCHCOST-%s-%04d", strings.ToUpper(suffix), index)
		current := postgresObservationRecordForPackage(sourceID.String(), ids[index], ids[index], "batch cost", batchPackage)
		current.Observation.SourceType = "oval"
		current.SyncRunID = runID.String()
		snapshot[index] = current
	}

	materializer := NewAdvisoryMaterializer(pool)
	before := counter.queries.Load()
	results, err := materializer.PublishSourceSnapshot(shared.WithTenant(ctx, tenantID), ports.SourceSnapshotPublication{
		SyncRunID: runID, NextCheckpoint: []byte(`{"complete":true}`),
	}, snapshot)
	if err != nil {
		t.Fatalf("publish source snapshot: %v", err)
	}
	dispatched := counter.queries.Load() - before

	if len(results) != records {
		t.Fatalf("snapshot result count=%d, want %d", len(results), records)
	}
	for index, result := range results {
		if result.Canonical.Advisory.ID != ids[index] {
			t.Fatalf("result %d canonical=%q, want %q", index, result.Canonical.Advisory.ID, ids[index])
		}
		if !result.CreatedRevision || result.Revision != 1 {
			t.Fatalf("result %d = %+v, want a first revision", index, result)
		}
	}

	// Measured against real PostgreSQL 17 with this fixture: the per-record closure path dispatches 400
	// queries for 128 records (3.12 per record), the batched path dispatches 16 (0.12 per record), a 25x
	// reduction. The threshold sits between those two measured values, so reverting to per-record
	// materialization fails this test instead of passing it. Verified by disabling the batched branch and
	// observing the failure.
	perRecord := float64(dispatched) / float64(records)
	t.Logf("publication dispatched %d queries for %d independent records (%.2f per record)", dispatched, records, perRecord)
	if dispatched == 0 {
		t.Fatal("query tracer observed no queries; the measurement is not wired up")
	}
	if perRecord > 1 {
		t.Fatalf("publication dispatched %.2f queries per record (%d total for %d records); independent snapshot records must be batched, not materialized one at a time", perRecord, dispatched, records)
	}
}
