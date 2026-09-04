package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresFindingLineageBackfillRunnerRLSAndReconciliation(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 136); err != nil {
		t.Fatalf("up to 0136: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tenantID, otherTenantID := shared.ID("lineage-backfill-pg"), shared.ID("lineage-backfill-other")
	suffix := "backfill-pg"
	assessmentID := shared.ID("lineage-assessment-" + suffix)
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, suffix)
	ensureTestTenantAndEngagement(t, ctx, pool, otherTenantID, "lineage-backfill-other-assessment", "", "")
	now := time.Now().UTC().Add(time.Minute)
	findings := []finding.Finding{
		{ID: "lineage-backfill-manual", EngagementID: assessmentID, Title: "Manual", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindManual, DedupKey: "manual:lineage-backfill-manual", Audit: shared.Audit{CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}},
		{ID: "lineage-backfill-sast", EngagementID: assessmentID, Title: "SAST", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSAST, RuleKey: "go-sql", DedupKey: "cq:sast:go-sql:src/db.go:42", Audit: shared.Audit{CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}},
		{ID: "lineage-backfill-dast", EngagementID: assessmentID, Title: "DAST", Severity: shared.SeverityMedium, Status: finding.StatusOpen, Kind: finding.KindDAST, DedupKey: "dast:legacy", Audit: shared.Audit{CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}},
	}
	if err := NewFindingRepository(pool).Upsert(shared.WithTenant(ctx, tenantID), findings); err != nil {
		t.Fatal(err)
	}
	audit := NewAuditLog(pool)
	clock := postgresLineageClock{now: now}
	ids := &postgresLineageIDs{prefix: "lineage-backfill-generated"}
	lineage, err := lineageuc.NewService(NewFindingLineageRepository(pool), NewTenantTransactionRunner(pool), audit, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	backfillRepository := NewFindingLineageBackfillRepository(pool)
	filtered, err := backfillRepository.ListFindingLineageBackfillSources(ctx, tenantID, "", now, []string{"manual"}, 10)
	if err != nil || len(filtered) != 1 || filtered[0].FindingID != findings[0].ID {
		t.Fatalf("producer-filtered sources=%+v err=%v", filtered, err)
	}
	runner, err := lineageuc.NewFindingLineageBackfillRunner(
		lineage, backfillRepository, backfillRepository, NewAssessmentSnapshotRepository(pool),
		NewVulnerabilityOccurrenceStore(pool), NewJudgmentRepository(pool), ids, clock, audit, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunBackfill(ctx, lineageuc.FindingLineageBackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "postgres", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != ports.FindingLineageBackfillCompleted || run.ProcessedCount != 3 || run.ObservationCreatedCount != 1 || run.ProvisionalCandidateCount != 1 || run.SkippedCount != 1 {
		t.Fatalf("unexpected PostgreSQL backfill run: %+v", run)
	}
	if run.ProcessedCount != run.ObservationCreatedCount+run.ProvisionalCandidateCount+run.SkippedCount {
		t.Fatalf("PostgreSQL counts do not reconcile: %+v", run)
	}
	lineageRepository := NewFindingLineageRepository(pool)
	observations, err := lineageRepository.ListObservationsBySnapshot(ctx, tenantID, cycleID, snapshotID)
	if err != nil || len(observations) != 2 {
		t.Fatalf("observations=%+v err=%v", observations, err)
	}
	candidates, err := lineageRepository.ListOpenCandidatesBySnapshot(ctx, tenantID, cycleID, snapshotID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	skips, err := lineageRepository.ListSkipsBySnapshot(ctx, tenantID, cycleID, snapshotID)
	if err != nil || len(skips) != 1 || skips[0].DetailCode != lineageuc.BackfillReasonProducerMatcherUnavailable {
		t.Fatalf("skips=%+v err=%v", skips, err)
	}
	if _, err := backfillRepository.GetFindingLineageBackfillRun(ctx, otherTenantID, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant run read=%v", err)
	}
	if _, err := backfillRepository.GetFindingLineageBackfillItem(ctx, otherTenantID, run.ID, findings[0].ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant item read=%v", err)
	}
}

func TestPostgresFindingLineageBackfillConcurrentLeaseAndCompositeOwnership(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 136); err != nil {
		t.Fatalf("up to 0136: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tenantID := shared.ID("lineage-backfill-lease")
	assessmentID := shared.ID("lineage-assessment-lineage-backfill-lease")
	createFindingLineageSnapshot(t, ctx, pool, tenantID, "lineage-backfill-lease")
	now := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	if err := NewFindingRepository(pool).Upsert(shared.WithTenant(ctx, tenantID), []finding.Finding{{
		ID: "lineage-backfill-lease-finding", EngagementID: assessmentID, Title: "Manual", Severity: shared.SeverityHigh,
		Status: finding.StatusOpen, Kind: finding.KindManual, DedupKey: "manual:lineage-backfill-lease-finding", Audit: shared.Audit{CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)},
	}}); err != nil {
		t.Fatal(err)
	}
	repository := NewFindingLineageBackfillRepository(pool)
	requests := []ports.FindingLineageBackfillAcquireRequest{
		{Run: ports.FindingLineageBackfillRun{TenantID: tenantID, ID: "lease-run-a", SchemaVersion: 1, BatchSize: 500, SnapshotAt: now, State: ports.FindingLineageBackfillRunning, LeaseOwner: "owner-a", LeaseToken: "token-a", CreatedBy: "operator", CreatedAt: now, UpdatedAt: now}, LeaseDuration: time.Minute},
		{Run: ports.FindingLineageBackfillRun{TenantID: tenantID, ID: "lease-run-b", SchemaVersion: 1, BatchSize: 500, SnapshotAt: now, State: ports.FindingLineageBackfillRunning, LeaseOwner: "owner-b", LeaseToken: "token-b", CreatedBy: "operator", CreatedAt: now, UpdatedAt: now}, LeaseDuration: time.Minute},
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, request := range requests {
		request := request
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, err := repository.AcquireFindingLineageBackfillRun(ctx, request)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, shared.ErrConflict):
			conflicted++
		default:
			t.Fatalf("unexpected lease error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("lease results succeeded=%d conflicted=%d", succeeded, conflicted)
	}

	var active ports.FindingLineageBackfillRun
	for _, runID := range []shared.ID{"lease-run-a", "lease-run-b"} {
		if run, err := repository.GetFindingLineageBackfillRun(ctx, tenantID, runID); err == nil {
			active = run
		}
	}
	resumed, wasResumed, err := repository.AcquireFindingLineageBackfillRun(ctx, ports.FindingLineageBackfillAcquireRequest{
		Run: ports.FindingLineageBackfillRun{
			TenantID: tenantID, ID: "lease-run-resume", SchemaVersion: 1, BatchSize: active.BatchSize, ProducerFilters: active.ProducerFilters,
			SnapshotAt: active.SnapshotAt, State: ports.FindingLineageBackfillRunning, LeaseOwner: "owner-resumed", LeaseToken: "lease-token-resume", CreatedBy: "operator", CreatedAt: now.Add(2 * time.Minute), UpdatedAt: now.Add(2 * time.Minute),
		},
		LeaseDuration: time.Minute,
	})
	if err != nil || !wasResumed || resumed.ID != active.ID || resumed.LeaseOwner != "owner-resumed" {
		t.Fatalf("expired lease resume=%+v resumed=%v err=%v", resumed, wasResumed, err)
	}
	active = resumed
	item := ports.FindingLineageBackfillItem{
		TenantID: tenantID, RunID: active.ID, AssessmentID: "wrong-assessment", SourceFindingID: "lineage-backfill-lease-finding",
		SchemaVersion: 1, MatcherVersion: 1, IdempotencyKey: "ownership-key", SourceHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Outcome: lineageuc.BackfillOutcomeSkipped, ReasonCode: lineageuc.BackfillReasonInvalidOwnership, ProcessedAt: now,
	}
	if _, _, err := repository.CommitFindingLineageBackfillItem(ctx, tenantID, active.ID, active.LeaseToken, now.Add(2*time.Minute), func(context.Context) (ports.FindingLineageBackfillItem, error) { return item, nil }); err == nil {
		t.Fatal("composite Finding ownership accepted a mismatched Assessment")
	}
}

var _ ports.IDGenerator = idgen.RandomID{}
