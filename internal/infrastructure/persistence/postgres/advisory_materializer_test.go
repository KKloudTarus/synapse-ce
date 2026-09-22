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

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func postgresObservationRecord(source, record, id, summary string) advisory.ObservationRecord {
	return postgresObservationRecordForPackage(source, record, id, summary, "example.com/pkg")
}

// postgresObservationRecordForPackage builds an observation bound to an explicit package key.
//
// The shared Postgres database is reused across packages and the suite is run a second time against
// the same database in CI, so a test that materialises an advisory under the default
// "example.com/pkg" key leaves a row that a later run can still see. Snapshot publication receipts
// are deliberately immutable and their sync-run rows are ON DELETE RESTRICT, so those advisories
// cannot be cleaned up afterwards. Tests that publish receipts therefore take their own package key,
// which keeps TestAdvisoryMaterializerPostgresReplayAndConcurrency's "exactly one advisory projects
// onto this package" assertion true on a re-run instead of counting another test's residue.
func postgresObservationRecordForPackage(source, record, id, summary, packageName string) advisory.ObservationRecord {
	return advisory.ObservationRecord{Observation: advisory.Observation{
		SourceType: source,
		SourceID:   source,
		RecordID:   record,
		Status:     advisory.StatusActive,
		ModifiedAt: time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		Advisory:   advisory.Advisory{ID: id, Summary: summary, Affected: []advisory.AffectedPackage{{Ecosystem: "Go", Package: packageName, Versions: []string{"1.0.0"}}}},
	}}
}

func TestSourceSnapshotPublicationMigrationBlocksTruncate(t *testing.T) {
	migration, err := migrations.FS.ReadFile("0180_advisory_source_snapshot_publications.sql")
	if err != nil {
		t.Fatalf("read source snapshot publication migration: %v", err)
	}
	text := string(migration)
	for _, required := range []string{
		"vulnerability_source_snapshot_publications_no_truncate",
		"vulnerability_source_snapshot_results_no_truncate",
		"BEFORE TRUNCATE ON vulnerability_source_snapshot_publications",
		"BEFORE TRUNCATE ON vulnerability_source_snapshot_results",
		"FOR EACH STATEMENT EXECUTE FUNCTION synapse_guard_authoritative_snapshot_mutation()",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("source snapshot publication migration lacks %q", required)
		}
	}
}

func TestAdvisoryMaterializerPostgresReplayAndConcurrency(t *testing.T) {
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

	sourceID := shared.ID("src-mat-" + randHex(t))
	tenantID := shared.ID("tenant-mat-" + randHex(t))
	jobID := "job-mat-" + randHex(t)
	runID := "run-mat-" + randHex(t)
	sourceKey := "oval-mat-" + randHex(t)
	source := `INSERT INTO vulnerability_sources
		(id, source_key, display_name, adapter_type, endpoint, cadence_seconds, stale_after_seconds, sync_mode)
		VALUES ($1,$2,'OVAL materializer test','oval',$3,3600,7200,'full')`
	if _, err := pool.Exec(ctx, source, sourceID.String(), sourceKey, "https://osv.dev/"+sourceID.String()); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status) VALUES($1,$2,'vulnerability_sync','{}','queued')`, jobID, tenantID.String()); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sync_runs(id,source_id,adapter_type,mode,trigger,actor,durable_job_id,state) VALUES($1,$2,'oval','full','manual','test',$3,'queued')`, runID, sourceID.String(), jobID); err != nil {
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
	// This test publishes a snapshot receipt below, and receipts are immutable with their sync run held
	// ON DELETE RESTRICT, so the cleanup DELETE cannot remove this advisory. Bind it to a per-run package
	// key so the projection assertion further down stays exact when CI runs the suite a second time
	// against the same database.
	ownedPackage := "example.com/replay-" + strings.ToLower(strings.TrimPrefix(advisoryID, "CVE-2026-"))
	record := postgresObservationRecordForPackage(sourceID.String(), advisoryID, advisoryID, "initial", ownedPackage)
	record.Observation.SourceType = "oval"
	publishedAt := time.Now().UTC().Add(-time.Second)
	record.Observation.PublishedAt = publishedAt
	record.SyncRunID = runID
	tenantCtx := shared.WithTenant(ctx, tenantID)
	dailySince := publishedAt.Add(-time.Minute)
	impactBefore, err := materializer.CountVulnerabilityAdvisoryDailyImpact(tenantCtx, dailySince)
	if err != nil {
		t.Fatalf("count daily impact before materialization: %v", err)
	}
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
	results := make([]advisory.MaterializationResult, 2)
	materializationErrs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], materializationErrs[index] = materializer.Materialize(tenantCtx, []advisory.ObservationRecord{record})
		}(index)
	}
	wait.Wait()
	for index, err := range materializationErrs {
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
	changed := postgresObservationRecordForPackage(sourceID.String(), advisoryID, advisoryID, "changed", ownedPackage)
	changed.Observation.SourceType = "oval"
	changed.Observation.PublishedAt = publishedAt
	changed.SyncRunID = runID
	changed.Observation.Advisory.Affected[0].Versions = []string{"2.0.0"}
	changedResult, err := materializer.Materialize(tenantCtx, []advisory.ObservationRecord{changed})
	if err != nil || !changedResult.CreatedRevision || changedResult.Revision != 2 {
		t.Fatalf("changed=%+v err=%v", changedResult, err)
	}
	impactAfter, err := materializer.CountVulnerabilityAdvisoryDailyImpact(tenantCtx, dailySince)
	if err != nil || impactAfter.NewlyDisclosed != impactBefore.NewlyDisclosed+1 || impactAfter.NewlyIngested != impactBefore.NewlyIngested+1 {
		t.Fatalf("daily impact before=%+v after=%+v err=%v", impactBefore, impactAfter, err)
	}
	snapshot := changed
	snapshot.Observation.Advisory.Summary = "snapshot"
	snapshotResults, err := materializer.PublishSourceSnapshot(tenantCtx, ports.SourceSnapshotPublication{
		SyncRunID: shared.ID(runID), NextCheckpoint: []byte(`{"complete":true}`),
	}, []advisory.ObservationRecord{snapshot})
	if err != nil || len(snapshotResults) != 1 || !snapshotResults[0].CreatedRevision || snapshotResults[0].Revision != 3 {
		t.Fatalf("snapshot results=%+v err=%v", snapshotResults, err)
	}
	published, found, err := materializer.PublishedSourceSnapshot(tenantCtx, shared.ID(runID))
	if err != nil || !found || published.SourceID != sourceID || published.AdapterType != "oval" || len(published.Results) != 1 || !published.Results[0].CreatedRevision || published.Results[0].Revision != 3 {
		t.Fatalf("published=%+v found=%t err=%v", published, found, err)
	}
	var checkpoint map[string]bool
	if err := json.Unmarshal(published.NextCheckpoint, &checkpoint); err != nil || len(checkpoint) != 1 || !checkpoint["complete"] {
		t.Fatalf("published checkpoint=%s err=%v, want complete=true", published.NextCheckpoint, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_source_snapshot_publications SET next_checkpoint='{}' WHERE sync_run_id=$1`, runID); err == nil {
		t.Fatal("source snapshot publication was mutable")
	}
	if _, err := pool.Exec(ctx, `UPDATE vulnerability_source_snapshot_results SET created_revision=FALSE WHERE sync_run_id=$1`, runID); err == nil {
		t.Fatal("source snapshot result was mutable")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM vulnerability_source_snapshot_results WHERE sync_run_id=$1`, runID); err == nil {
		t.Fatal("source snapshot result was erasable")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM vulnerability_source_snapshot_publications WHERE sync_run_id=$1`, runID); err == nil {
		t.Fatal("source snapshot publication was erasable")
	}
	if _, err := pool.Exec(ctx, `TRUNCATE vulnerability_source_snapshot_results`); err == nil {
		t.Fatal("source snapshot result receipt was truncatable")
	}
	if _, err := pool.Exec(ctx, `TRUNCATE vulnerability_source_snapshot_publications, vulnerability_source_snapshot_results`); err == nil {
		t.Fatal("source snapshot publication receipt was truncatable")
	}
	revisionPage, err := materializer.ListVulnerabilityAdvisoryRevisions(tenantCtx, vulnerabilityintel.AdvisoryRevisionQuery{AdvisoryID: advisoryID, Limit: 10})
	if err != nil || len(revisionPage.Items) != 3 || len(revisionPage.Items[0].SyncRunIDs) != 1 || revisionPage.Items[0].SyncRunIDs[0] != shared.ID(runID) {
		t.Fatalf("revision provenance=%+v err=%v", revisionPage, err)
	}
	links, err := materializer.ListVulnerabilitySyncRunRevisions(tenantCtx, []shared.ID{shared.ID(runID)}, 10)
	if err != nil || len(links[shared.ID(runID)].Items) != 3 || links[shared.ID(runID)].Items[0].Revision != 3 {
		t.Fatalf("run revision links=%+v err=%v", links, err)
	}
	otherLinks, err := materializer.ListVulnerabilitySyncRunRevisions(shared.WithTenant(ctx, "other-tenant"), []shared.ID{shared.ID(runID)}, 10)
	if err != nil || len(otherLinks[shared.ID(runID)].Items) != 0 {
		t.Fatalf("cross-tenant run links=%+v err=%v", otherLinks, err)
	}

	store := NewAdvisoryRepository(pool)
	matches, err := store.ByPackage(ctx, "Go", ownedPackage)
	if err != nil || len(matches) != 1 || matches[0].ID != advisoryID {
		t.Fatalf("owned advisory projection=%+v err=%v", matches, err)
	}
	canonical, err := materializer.GetCanonical(ctx, advisoryID)
	if err != nil || canonical.Advisory.Summary != "snapshot" {
		t.Fatalf("canonical=%+v err=%v", canonical, err)
	}
	page, err := materializer.ListVulnerabilityAdvisories(tenantCtx, tenantID, vulnerabilityintel.AdvisoryQuery{Search: advisoryID, Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].Canonical.Advisory.ID != advisoryID {
		t.Fatalf("server-search advisory page=%+v err=%v", page, err)
	}
	page, err = materializer.ListVulnerabilityAdvisories(tenantCtx, tenantID, vulnerabilityintel.AdvisoryQuery{
		Search: advisoryID, RiskTrends: []vulnerabilityintel.RiskTrend{vulnerabilityintel.RiskTrendNone}, NoActions: true, Limit: 1,
	})
	if err != nil || len(page.Items) != 1 || page.Items[0].Canonical.Advisory.ID != advisoryID {
		t.Fatalf("server-filtered advisory page=%+v err=%v", page, err)
	}
	coverage, err := materializer.SummarizeVulnerabilityCoverage(tenantCtx, tenantID, []vulnerabilityintel.AdvisoryCoverageRequest{{AdvisoryID: advisoryID, Revision: 3}})
	if err != nil || coverage[advisoryID].State != vulnerabilityintel.CoverageIncompleteInventory || coverage[advisoryID].Reason != "no_authoritative_inventory" {
		t.Fatalf("coverage without inventory=%+v err=%v", coverage, err)
	}

	absence := snapshot
	absence.Observation.Advisory.Summary = ""
	absence.Observation.Advisory.Affected = nil
	absence.Observation.AbsenceRetirement = true
	if _, err := materializer.MaterializeSourceSnapshot(tenantCtx, []advisory.ObservationRecord{absence}); err != nil {
		t.Fatalf("materialize source absence: %v", err)
	}
	var currentRecordIDs []string
	if err := materializer.CurrentSourceRecordIDsBounded(ctx, sourceID.String(), 2, func(recordID string) error {
		currentRecordIDs = append(currentRecordIDs, recordID)
		return nil
	}); err != nil || len(currentRecordIDs) != 0 {
		t.Fatalf("active source records=%v err=%v", currentRecordIDs, err)
	}
	var absenceRetirement bool
	if err := pool.QueryRow(ctx, `SELECT absence_retirement FROM advisory_observations WHERE source_id=$1 AND record_id=$2 AND is_current`, sourceID.String(), snapshot.Observation.RecordID).Scan(&absenceRetirement); err != nil || !absenceRetirement {
		t.Fatalf("current absence_retirement=%t err=%v", absenceRetirement, err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO advisory_observations(id,source_id,record_id,identity_ids,normalized_payload,content_hash,is_current,absence_retirement)
		VALUES($1,$2,$3,$4,'{}',$5,TRUE,FALSE),($6,$2,$7,$8,'{}',$9,TRUE,FALSE)`,
		"overflow-one-"+randHex(t), sourceID.String(), "overflow-one", []string{"overflow-one"}, "overflow-hash-one-"+randHex(t),
		"overflow-two-"+randHex(t), "overflow-two", []string{"overflow-two"}, "overflow-hash-two-"+randHex(t)); err != nil {
		t.Fatalf("seed overflowing source membership: %v", err)
	}
	yielded := 0
	if err := materializer.CurrentSourceRecordIDsBounded(ctx, sourceID.String(), 1, func(string) error {
		yielded++
		return nil
	}); !errors.Is(err, shared.ErrValidation) || yielded != 0 {
		t.Fatalf("overflow membership error=%v yielded=%d", err, yielded)
	}
}

func TestAdvisoryMaterializerPostgresAuthoritativeCSAFSnapshotRetiresMissingRecord(t *testing.T) {
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
	sourceID := shared.ID("src-csaf-snapshot-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES($1,$2,$2,'csaf',$3,3600,7200,'full')`, sourceID.String(), "csaf-snapshot-"+suffix, "https://example.test/"+sourceID.String()); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	ids := []string{
		"CVE-2026-CSAF-A-" + strings.ToUpper(suffix),
		"CVE-2026-CSAF-B-" + strings.ToUpper(suffix),
		"CVE-2026-CSAF-C-" + strings.ToUpper(suffix),
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM advisory_observations WHERE source_id=$1`, sourceID.String())
		_, _ = pool.Exec(ctx, `DELETE FROM advisories WHERE id=ANY($1::text[])`, ids)
		_, _ = pool.Exec(ctx, `DELETE FROM vulnerability_sources WHERE id=$1`, sourceID.String())
	})

	record := func(id, summary string) advisory.ObservationRecord {
		current := postgresObservationRecord(sourceID.String(), id, id, summary)
		current.Observation.SourceType = "csaf"
		return current
	}
	present := record(ids[0], "affected")
	removed := record(ids[1], "affected")
	materializer := NewAdvisoryMaterializer(pool)
	if _, err := materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{present, removed}); err != nil {
		t.Fatalf("seed CSAF snapshot: %v", err)
	}
	replacement := present
	replacement.Observation.Advisory.Summary = "fixed"
	absence := removed
	absence.Observation.Advisory.Summary = ""
	absence.Observation.Advisory.Affected = nil
	absence.Observation.AbsenceRetirement = true
	if _, err := materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{replacement, absence}); err != nil {
		t.Fatalf("replace CSAF snapshot: %v", err)
	}
	var active []string
	if err := materializer.CurrentSourceRecordIDsBounded(ctx, sourceID.String(), 3, func(recordID string) error {
		active = append(active, recordID)
		return nil
	}); err != nil || len(active) != 1 || active[0] != ids[0] {
		t.Fatalf("active CSAF records=%v err=%v", active, err)
	}
	retired, err := materializer.GetCanonical(ctx, ids[1])
	if err != nil || len(retired.Advisory.Affected) != 0 {
		t.Fatalf("retired CSAF canonical=%+v err=%v", retired, err)
	}

	legacy := record(ids[2], "legacy")
	legacy.Observation.Advisory.Aliases = []string{"RHSA-2026:" + strings.ToUpper(suffix)}
	if _, err := materializer.Materialize(ctx, []advisory.ObservationRecord{legacy}); err != nil {
		t.Fatalf("seed legacy CSAF record: %v", err)
	}
	legacyReplacement := record(ids[2], "replacement")
	if _, err := materializer.MaterializeSourceSnapshot(ctx, []advisory.ObservationRecord{replacement, legacyReplacement}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("aliased legacy CSAF history error=%v", err)
	}
	current, err := materializer.GetCanonical(ctx, ids[2])
	if err != nil || current.Advisory.Summary != "legacy" {
		t.Fatalf("legacy CSAF canonical=%+v err=%v", current, err)
	}
}

func TestAdvisoryMaterializerPostgresSnapshotReceiptPreservesOrderedResults(t *testing.T) {
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
	sourceID := shared.ID("src-receipt-" + suffix)
	linkSourceID := shared.ID("src-receipt-link-" + suffix)
	tenantID := shared.ID("tenant-receipt-" + suffix)
	jobID := "job-receipt-" + suffix
	runID := shared.ID("run-receipt-" + suffix)
	for _, source := range []struct {
		id, key, adapter string
	}{
		{sourceID.String(), "oval-receipt-" + suffix, "oval"},
		{linkSourceID.String(), "osv-receipt-" + suffix, "osv"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
			(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
			VALUES($1,$2,$2,$3,$4,3600,7200,'full')`, source.id, source.key, source.adapter, "https://osv.dev/"+source.id); err != nil {
			t.Fatalf("seed source %s: %v", source.id, err)
		}
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

	linkedID := "CVE-2026-RECEIPT-A-" + strings.ToUpper(suffix)
	aliasID := "CVE-2026-RECEIPT-B-" + strings.ToUpper(suffix)
	freshID := "CVE-2026-RECEIPT-C-" + strings.ToUpper(suffix)
	materializer := NewAdvisoryMaterializer(pool)
	// Receipt rows are immutable and their sync run is ON DELETE RESTRICT, so this test's advisories
	// survive cleanup. Scope them to their own package so they never inflate another test's projection.
	receiptPackage := "example.com/receipt-linked-" + suffix
	link := postgresObservationRecordForPackage(linkSourceID.String(), "link-"+suffix, linkedID, "linked receipt", receiptPackage)
	link.Observation.SourceType = "osv"
	link.Observation.Advisory.Aliases = []string{aliasID}
	if _, err := materializer.Materialize(ctx, []advisory.ObservationRecord{link}); err != nil {
		t.Fatalf("seed linked canonical: %v", err)
	}

	record := func(id string) advisory.ObservationRecord {
		current := postgresObservationRecordForPackage(sourceID.String(), id, id, "linked receipt", receiptPackage)
		current.Observation.SourceType = "oval"
		current.SyncRunID = runID.String()
		return current
	}
	records := []advisory.ObservationRecord{record(linkedID), record(aliasID), record(freshID)}
	results, err := materializer.PublishSourceSnapshot(shared.WithTenant(ctx, tenantID), ports.SourceSnapshotPublication{
		SyncRunID: runID, NextCheckpoint: []byte(`{"complete":true}`),
	}, records)
	if err != nil {
		t.Fatalf("publish source snapshot: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("snapshot result count=%d, want 3", len(results))
	}
	if results[0].Canonical.Advisory.ID != linkedID || results[1].Canonical.Advisory.ID != linkedID || results[0].Revision != results[1].Revision {
		t.Fatalf("connected source results=%+v, want the same canonical revision", results[:2])
	}
	if results[2].Canonical.Advisory.ID != freshID || results[2].ChangedFields != nil {
		t.Fatalf("fresh source result=%+v, want nil in-memory changes before receipt encoding", results[2])
	}

	var duplicateReceiptRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_source_snapshot_results
		WHERE sync_run_id=$1 AND advisory_id=$2 AND revision=$3`, runID.String(), linkedID, results[0].Revision).Scan(&duplicateReceiptRows); err != nil || duplicateReceiptRows != 2 {
		t.Fatalf("connected receipt rows=%d err=%v, want 2", duplicateReceiptRows, err)
	}
	var freshChangedFields string
	if err := pool.QueryRow(ctx, `SELECT changed_fields::text FROM vulnerability_source_snapshot_results
		WHERE sync_run_id=$1 AND advisory_id=$2`, runID.String(), freshID).Scan(&freshChangedFields); err != nil || freshChangedFields != `[]` {
		t.Fatalf("fresh changed_fields=%q err=%v, want []", freshChangedFields, err)
	}
	published, found, err := materializer.PublishedSourceSnapshot(shared.WithTenant(ctx, tenantID), runID)
	if err != nil || !found || len(published.Results) != 3 {
		t.Fatalf("published receipt=%+v found=%t err=%v", published, found, err)
	}
	if published.Results[2].ChangedFields == nil || len(published.Results[2].ChangedFields) != 0 {
		t.Fatalf("loaded fresh changed fields=%v, want non-nil empty array", published.Results[2].ChangedFields)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM vulnerability_sync_runs WHERE id=$1`, runID.String()); err == nil {
		t.Fatal("publication parent sync run was erasable")
	}
}

func TestAdvisoryMaterializerPostgresSnapshotReceiptBatchesResultsAndRevisionLinks(t *testing.T) {
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

	suffix := strings.ToUpper(randHex(t))
	sourceID := shared.ID("src-receipt-batch-" + strings.ToLower(suffix))
	tenantID := shared.ID("tenant-receipt-batch-" + strings.ToLower(suffix))
	jobID := "job-receipt-batch-" + strings.ToLower(suffix)
	runID := shared.ID("run-receipt-batch-" + strings.ToLower(suffix))
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES($1,$2,$2,'oval',$3,3600,7200,'full')`, sourceID.String(), "oval-receipt-batch-"+strings.ToLower(suffix), "https://example.test/"+sourceID.String()); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status) VALUES($1,$2,'vulnerability_sync','{}','queued')`, jobID, tenantID.String()); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sync_runs(id,source_id,adapter_type,mode,trigger,actor,durable_job_id,state)
		VALUES($1,$2,'oval','full','manual','test',$3,'queued')`, runID.String(), sourceID.String(), jobID); err != nil {
		t.Fatalf("seed sync run: %v", err)
	}

	count := advisory.MaxMaterializationBatch + 1
	ids := make([]string, count)
	records := make([]advisory.ObservationRecord, count)
	for index := range records {
		ids[index] = fmt.Sprintf("CVE-2026-RECEIPT-BATCH-%s-%04d", suffix, index)
		records[index] = postgresObservationRecordForPackage(sourceID.String(), ids[index], ids[index], "batched receipt", "example.com/receipt-batch-"+suffix)
		records[index].Observation.SourceType = "oval"
		records[index].SyncRunID = runID.String()
	}
	materializer := NewAdvisoryMaterializer(pool)
	results, err := materializer.PublishSourceSnapshot(shared.WithTenant(ctx, tenantID), ports.SourceSnapshotPublication{
		SyncRunID: runID, NextCheckpoint: []byte(`{"complete":true}`),
	}, records)
	if err != nil {
		t.Fatalf("publish source snapshot: %v", err)
	}
	if len(results) != count {
		t.Fatalf("published result count=%d, want %d", len(results), count)
	}
	for index, result := range results {
		if result.Canonical.Advisory.ID != ids[index] || result.Revision != 1 || !result.CreatedRevision {
			t.Fatalf("published result %d=%+v, want advisory %s revision 1 created", index, result, ids[index])
		}
	}

	var receiptCount int
	if err := pool.QueryRow(ctx, `SELECT result_count FROM vulnerability_source_snapshot_publications WHERE sync_run_id=$1`, runID.String()).Scan(&receiptCount); err != nil || receiptCount != count {
		t.Fatalf("receipt count=%d err=%v, want %d", receiptCount, err, count)
	}
	rows, err := pool.Query(ctx, `SELECT result_index,advisory_id,revision,changed_fields::text,created_revision
		FROM vulnerability_source_snapshot_results WHERE sync_run_id=$1 ORDER BY result_index`, runID.String())
	if err != nil {
		t.Fatalf("list source snapshot receipt results: %v", err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var resultIndex int
		var advisoryID, changedFields string
		var revision int64
		var createdRevision bool
		if err := rows.Scan(&resultIndex, &advisoryID, &revision, &changedFields, &createdRevision); err != nil {
			t.Fatalf("scan source snapshot receipt result: %v", err)
		}
		if resultIndex != index || advisoryID != ids[index] || revision != 1 || changedFields != `[]` || !createdRevision {
			t.Fatalf("receipt result %d=(index=%d advisory=%s revision=%d changed=%s created=%t), want ordered new revision", index, resultIndex, advisoryID, revision, changedFields, createdRevision)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate source snapshot receipt results: %v", err)
	}
	if index != count {
		t.Fatalf("receipt row count=%d, want %d", index, count)
	}
	var linkedResults, links int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_source_snapshot_results results
		JOIN advisory_revision_sync_runs links ON links.advisory_id=results.advisory_id
			AND links.revision=results.revision AND links.sync_run_id=results.sync_run_id
		WHERE results.sync_run_id=$1`, runID.String()).Scan(&linkedResults); err != nil || linkedResults != count {
		t.Fatalf("receipt revision links=%d err=%v, want %d", linkedResults, err, count)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_revision_sync_runs WHERE sync_run_id=$1`, runID.String()).Scan(&links); err != nil || links != count {
		t.Fatalf("sync run revision links=%d err=%v, want %d", links, err, count)
	}
	published, found, err := materializer.PublishedSourceSnapshot(shared.WithTenant(ctx, tenantID), runID)
	if err != nil || !found || len(published.Results) != count {
		t.Fatalf("published snapshot found=%t results=%d err=%v, want %d ordered results", found, len(published.Results), err, count)
	}
	for index, result := range published.Results {
		if result.Canonical.Advisory.ID != ids[index] || result.Revision != 1 || result.ChangedFields == nil || len(result.ChangedFields) != 0 {
			t.Fatalf("loaded receipt result %d=%+v, want ordered revision with empty changed fields", index, result)
		}
	}
}

// D1.3: the materializer projects the canonical's merged risk signals (KEV/EPSS) into the scan-time
// `advisories` projection, so an offline scan reading ByPackage gets exploitation-priority data with no
// network.
func TestAdvisoryMaterializerProjectsRisk(t *testing.T) {
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

	sourceID := shared.ID("src-risk-" + randHex(t))
	tenantID := shared.ID("tenant-risk-" + randHex(t))
	jobID := "job-risk-" + randHex(t)
	runID := "run-risk-" + randHex(t)
	sourceKey := "osv-risk-" + randHex(t)
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id, source_key, display_name, adapter_type, endpoint, cadence_seconds, stale_after_seconds, sync_mode)
		VALUES ($1,$2,'OSV risk test','osv',$3,3600,7200,'incremental')`, sourceID.String(), sourceKey, "https://osv.dev/"+sourceID.String()); err != nil {
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
	advisoryID := "CVE-2026-RISK-" + strings.ToUpper(randHex(t))
	pkg := "example.com/risk-" + randHex(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM advisory_observations WHERE source_id=$1`, sourceID.String())
		_, _ = pool.Exec(ctx, `DELETE FROM advisories WHERE id=$1`, advisoryID)
		_, _ = pool.Exec(ctx, `DELETE FROM vulnerability_sync_runs WHERE id=$1`, runID)
		_, _ = pool.Exec(ctx, `DELETE FROM jobs WHERE id=$1`, jobID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
		_, _ = pool.Exec(ctx, `DELETE FROM vulnerability_sources WHERE id=$1`, sourceID.String())
	})

	kev := true
	epss := 0.91
	record := advisory.ObservationRecord{Observation: advisory.Observation{
		SourceType: sourceID.String(), SourceID: sourceID.String(), RecordID: "record-risk",
		Status: advisory.StatusActive, ModifiedAt: time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		KEV: &kev, EPSS: &epss,
		Advisory: advisory.Advisory{ID: advisoryID, Summary: "risky", Affected: []advisory.AffectedPackage{{Ecosystem: "Go", Package: pkg, Versions: []string{"1.0.0"}}}},
	}}
	record.SyncRunID = runID
	if _, err := NewAdvisoryMaterializer(pool).Materialize(shared.WithTenant(ctx, tenantID), []advisory.ObservationRecord{record}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	matches, err := NewAdvisoryRepository(pool).ByPackage(ctx, "Go", pkg)
	if err != nil || len(matches) != 1 {
		t.Fatalf("ByPackage = %+v err=%v", matches, err)
	}
	if !matches[0].KEV || matches[0].EPSS != 0.91 {
		t.Errorf("projection must carry the merged KEV/EPSS, got KEV=%v EPSS=%v", matches[0].KEV, matches[0].EPSS)
	}
}
