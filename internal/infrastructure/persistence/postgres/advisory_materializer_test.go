package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
)

func postgresObservationRecord(source, record, id, summary string) advisory.ObservationRecord {
	return advisory.ObservationRecord{Observation: advisory.Observation{
		SourceType: source,
		SourceID:   source,
		RecordID:   record,
		Status:     advisory.StatusActive,
		ModifiedAt: time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		Advisory:   advisory.Advisory{ID: id, Summary: summary, Affected: []advisory.AffectedPackage{{Ecosystem: "Go", Package: "example.com/pkg", Versions: []string{"1.0.0"}}}},
	}}
}

func TestAdvisoryMaterializerPostgresReplayAndConcurrency(t *testing.T) {
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
		t.Fatal(err)
	}
	defer pool.Close()

	sourceID := shared.ID("src-mat-" + randHex(t))
	tenantID := shared.ID("tenant-mat-" + randHex(t))
	jobID := "job-mat-" + randHex(t)
	runID := "run-mat-" + randHex(t)
	sourceKey := "osv-mat-" + randHex(t)
	source := `INSERT INTO vulnerability_sources
		(id, source_key, display_name, adapter_type, endpoint, cadence_seconds, stale_after_seconds, sync_mode)
		VALUES ($1,$2,'OSV materializer test','osv',$3,3600,7200,'incremental')`
	if _, err := pool.Exec(ctx, source, sourceID.String(), sourceKey, "https://osv.dev/"+sourceID.String()); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status) VALUES($1,$2,'vulnerability_sync','{}','queued')`, jobID, tenantID.String()); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sync_runs(id,source_id,adapter_type,mode,trigger,actor,durable_job_id,state) VALUES($1,$2,'osv','incremental','manual','test',$3,'queued')`, runID, sourceID.String(), jobID); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	advisoryID := "CVE-2026-" + strings.ToUpper(randHex(t))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM advisory_observations WHERE source_id=$1`, sourceID.String())
		_, _ = pool.Exec(ctx, `DELETE FROM advisories WHERE id=$1`, advisoryID)
		_, _ = pool.Exec(ctx, `DELETE FROM vulnerability_sync_runs WHERE id=$1`, runID)
		_, _ = pool.Exec(ctx, `DELETE FROM jobs WHERE id=$1`, jobID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
		_, _ = pool.Exec(ctx, `DELETE FROM vulnerability_sources WHERE id=$1`, sourceID.String())
	})

	materializer := NewAdvisoryMaterializer(pool)
	record := postgresObservationRecord(sourceID.String(), "record-1", advisoryID, "initial")
	record.SyncRunID = runID
	if _, err := materializer.Materialize(ctx, []advisory.ObservationRecord{record}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant error=%v", err)
	}
	if _, err := materializer.Materialize(shared.WithTenant(ctx, "other-tenant"), []advisory.ObservationRecord{record}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant provenance error=%v", err)
	}
	var rejectedRevisions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_revisions WHERE advisory_id=$1`, advisoryID).Scan(&rejectedRevisions); err != nil || rejectedRevisions != 0 {
		t.Fatalf("rejected materialization revisions=%d err=%v", rejectedRevisions, err)
	}
	tenantCtx := shared.WithTenant(ctx, tenantID)
	results := make([]advisory.MaterializationResult, 2)
	errors := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errors[index] = materializer.Materialize(tenantCtx, []advisory.ObservationRecord{record})
		}(index)
	}
	wait.Wait()
	for index, err := range errors {
		if err != nil {
			t.Fatalf("concurrent materialization %d: %v", index, err)
		}
	}
	created := 0
	for _, result := range results {
		if result.CreatedRevision {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent identical writes created %d revisions, want 1: %+v", created, results)
	}
	var revisions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_revisions WHERE advisory_id=$1`, advisoryID).Scan(&revisions); err != nil || revisions != 1 {
		t.Fatalf("revision count=%d err=%v, want 1", revisions, err)
	}

	replay, err := materializer.Materialize(tenantCtx, []advisory.ObservationRecord{record})
	if err != nil || replay.CreatedRevision || replay.Revision != 1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	changed := postgresObservationRecord(sourceID.String(), "record-1", advisoryID, "changed")
	changed.SyncRunID = runID
	changed.Observation.Advisory.Affected[0].Versions = []string{"2.0.0"}
	changedResult, err := materializer.Materialize(tenantCtx, []advisory.ObservationRecord{changed})
	if err != nil || !changedResult.CreatedRevision || changedResult.Revision != 2 {
		t.Fatalf("changed=%+v err=%v", changedResult, err)
	}
	revisionPage, err := materializer.ListVulnerabilityAdvisoryRevisions(tenantCtx, vulnerabilityintel.AdvisoryRevisionQuery{AdvisoryID: advisoryID, Limit: 10})
	if err != nil || len(revisionPage.Items) != 2 || len(revisionPage.Items[0].SyncRunIDs) != 1 || revisionPage.Items[0].SyncRunIDs[0] != shared.ID(runID) {
		t.Fatalf("revision provenance=%+v err=%v", revisionPage, err)
	}
	links, err := materializer.ListVulnerabilitySyncRunRevisions(tenantCtx, []shared.ID{shared.ID(runID)}, 10)
	if err != nil || len(links[shared.ID(runID)].Items) != 2 || links[shared.ID(runID)].Items[0].Revision != 2 {
		t.Fatalf("run revision links=%+v err=%v", links, err)
	}
	otherLinks, err := materializer.ListVulnerabilitySyncRunRevisions(shared.WithTenant(ctx, "other-tenant"), []shared.ID{shared.ID(runID)}, 10)
	if err != nil || len(otherLinks[shared.ID(runID)].Items) != 0 {
		t.Fatalf("cross-tenant run links=%+v err=%v", otherLinks, err)
	}

	store := NewAdvisoryRepository(pool)
	matches, err := store.ByPackage(ctx, "Go", "example.com/pkg")
	if err != nil || len(matches) != 1 || matches[0].ID != advisoryID {
		t.Fatalf("owned advisory projection=%+v err=%v", matches, err)
	}
	canonical, err := materializer.GetCanonical(ctx, advisoryID)
	if err != nil || canonical.Advisory.Summary != "changed" {
		t.Fatalf("canonical=%+v err=%v", canonical, err)
	}
}
