package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresAssessmentComparisonRepositoryLifecycle(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("comparison-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)

	identity, baselineObservation := postgresFindingLineagePair(t, tenantID, cycleID, baseline.ID, "comparison-identity-"+suffix, "comparison-baseline-observation-"+suffix, "baseline-source-"+suffix, "CVE-2026-1", now)
	baselineRisk := 8000
	baselineObservation.RiskScoreMilli = &baselineRisk
	lineageRepository := NewFindingLineageRepository(pool)
	if err := lineageRepository.CreateIdentityWithObservation(ctx, identity, baselineObservation); err != nil {
		t.Fatal(err)
	}
	currentObservation := baselineObservation
	currentRisk := 5000
	currentObservation.ID = shared.ID("comparison-current-observation-" + suffix)
	currentObservation.SnapshotID = current.ID
	currentObservation.SourceFindingID = "current-source-" + suffix
	currentObservation.Severity = shared.SeverityMedium
	currentObservation.RiskScoreMilli = &currentRisk
	currentObservation.ObservedAt = now.Add(time.Second)
	if err := lineageRepository.AppendObservation(ctx, currentObservation); err != nil {
		t.Fatal(err)
	}
	fixedIdentity, fixedObservation := postgresFindingLineagePair(t, tenantID, cycleID, baseline.ID, "comparison-fixed-identity-"+suffix, "comparison-fixed-observation-"+suffix, "fixed-source-"+suffix, "CVE-2026-3", now)
	if err := lineageRepository.CreateIdentityWithObservation(ctx, fixedIdentity, fixedObservation); err != nil {
		t.Fatal(err)
	}

	queued := postgresQueuedComparison(t, tenantID, cycleID, shared.ID("comparison-"+suffix), baseline, current, 1, now)
	repository := NewAssessmentComparisonRepository(pool)
	stored, created, err := repository.CreateQueued(ctx, queued)
	if err != nil || !created {
		t.Fatalf("create stored=%+v created=%v err=%v", stored, created, err)
	}
	backlog, err := repository.GetAssessmentComparisonBacklog(ctx, tenantID)
	if err != nil || backlog.Queued != 1 || backlog.OldestActiveAt == nil {
		t.Fatalf("queued backlog=%+v err=%v", backlog, err)
	}
	replay := queued
	replay.ID = "different-id"
	stored, created, err = repository.CreateQueued(ctx, replay)
	if err != nil || created || stored.ID != queued.ID {
		t.Fatalf("replay stored=%+v created=%v err=%v", stored, created, err)
	}
	bodyMismatch := replay
	bodyMismatch.InputPayload = []byte(`{"different":true}`)
	if _, _, err := repository.CreateQueued(ctx, bodyMismatch); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("input hash body mismatch error=%v", err)
	}
	if err := queued.Start(1, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateCAS(ctx, queued, 1); err != nil {
		t.Fatal(err)
	}
	backlog, err = repository.GetAssessmentComparisonBacklog(ctx, tenantID)
	if err != nil || backlog.Generating != 1 || backlog.Queued != 0 {
		t.Fatalf("generating backlog=%+v err=%v", backlog, err)
	}
	if err := repository.UpdateCAS(ctx, queued, 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale CAS error=%v", err)
	}
	item, err := assessmentcomparison.ClassifyLifecycle(assessmentcomparison.ClassifyInput{
		IdentityID: identity.ID, Baseline: &baselineObservation, Current: &currentObservation,
		BaselineActionable: true, CurrentActionable: true, BaselineRiskMilli: int64(baselineRisk), CurrentRiskMilli: int64(currentRisk),
	})
	if err != nil {
		t.Fatal(err)
	}
	item.ReviewCandidateIDs = []shared.ID{"candidate-a-" + shared.ID(suffix), "candidate-b-" + shared.ID(suffix)}
	fixedItem, err := assessmentcomparison.ClassifyLifecycle(assessmentcomparison.ClassifyInput{
		IdentityID: fixedIdentity.ID, Baseline: &fixedObservation, CurrentCoverage: assessmentsnapshot.Comparable,
		BaselineActionable: true, BaselineRiskMilli: 8000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := queued.Complete([]assessmentcomparison.Item{item, fixedItem}, 2, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateCAS(ctx, queued, 2); err != nil {
		t.Fatal(err)
	}
	backlog, err = repository.GetAssessmentComparisonBacklog(ctx, tenantID)
	if err != nil || backlog.Active() != 0 {
		t.Fatalf("completed backlog=%+v err=%v", backlog, err)
	}
	failedRows, err := repository.ListFailedAssessmentComparisons(ctx, tenantID, 10)
	if err != nil || len(failedRows) != 0 {
		t.Fatalf("failed rows=%+v err=%v", failedRows, err)
	}
	loaded, err := repository.Get(ctx, tenantID, queued.ID)
	if err != nil || loaded.Status != assessmentcomparison.StatusComplete || loaded.ContentHash == "" || len(loaded.Items) != 2 {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	var detected, fixed assessmentcomparison.Item
	for _, loadedItem := range loaded.Items {
		if loadedItem.IdentityID == identity.ID {
			detected = loadedItem
		}
		if loadedItem.IdentityID == fixedIdentity.ID {
			fixed = loadedItem
		}
	}
	if detected.BaselineObservationID != baselineObservation.ID || detected.CurrentObservationID != currentObservation.ID || fixed.FixedBasis != assessmentcomparison.FixedByComparableAbsence {
		t.Fatalf("loaded detected=%+v fixed=%+v", detected, fixed)
	}
	if loaded.Summary.ComparisonID != loaded.ID || loaded.Summary.BaselineSnapshotID != baseline.ID || loaded.Summary.CurrentSnapshotID != current.ID || loaded.Summary.RiskModelVersion != 1 {
		t.Fatalf("loaded summary=%+v", loaded.Summary)
	}
	metadata, err := repository.GetMetadata(ctx, tenantID, queued.ID)
	if err != nil || len(metadata.Items) != 0 || metadata.ContentHash != loaded.ContentHash {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	storedItem, err := repository.GetItem(ctx, tenantID, queued.ID, detected.ID)
	if err != nil || storedItem.ID != detected.ID || storedItem.Position != detected.Position || len(storedItem.ReviewCandidateIDs) != 2 || storedItem.ReviewCandidateIDs[0] != item.ReviewCandidateIDs[0] || storedItem.CurrentObservation.Severity != shared.SeverityMedium || storedItem.ProducerKind != "sca" {
		t.Fatalf("stored item=%+v err=%v", storedItem, err)
	}
	firstPage, err := repository.ListItems(ctx, tenantID, queued.ID, ports.AssessmentComparisonItemFilter{AfterPosition: -1, Limit: 1})
	if err != nil || len(firstPage.Items) != 1 || !firstPage.HasMore || firstPage.NextPosition != firstPage.Items[0].Position {
		t.Fatalf("first page=%+v err=%v", firstPage, err)
	}
	secondPage, err := repository.ListItems(ctx, tenantID, queued.ID, ports.AssessmentComparisonItemFilter{AfterPosition: firstPage.NextPosition, Limit: 1})
	if err != nil || len(secondPage.Items) != 1 || secondPage.HasMore || secondPage.Items[0].ID == firstPage.Items[0].ID {
		t.Fatalf("second page=%+v err=%v", secondPage, err)
	}
	presencePage, err := repository.ListItems(ctx, tenantID, queued.ID, ports.AssessmentComparisonItemFilter{AfterPosition: -1, Limit: 10, Presence: string(assessmentcomparison.PresenceNotDetected)})
	if err != nil || len(presencePage.Items) != 1 || presencePage.Items[0].ID != fixed.ID {
		t.Fatalf("presence page=%+v err=%v", presencePage, err)
	}
	changePage, err := repository.ListItems(ctx, tenantID, queued.ID, ports.AssessmentComparisonItemFilter{AfterPosition: -1, Limit: 10, ChangeFlag: assessmentcomparison.SeverityDecreased})
	if err != nil || len(changePage.Items) != 1 || changePage.Items[0].ID != detected.ID {
		t.Fatalf("change page=%+v err=%v", changePage, err)
	}
	severityPage, err := repository.ListItems(ctx, tenantID, queued.ID, ports.AssessmentComparisonItemFilter{AfterPosition: -1, Limit: 10, Severity: shared.SeverityMedium, ProducerKind: "sca", FindingKind: "vulnerability", ReviewState: "needs_review"})
	if err != nil || len(severityPage.Items) != 1 || severityPage.Items[0].ID != detected.ID {
		t.Fatalf("severity/review page=%+v err=%v", severityPage, err)
	}
	dispositionPage, err := repository.ListItems(ctx, tenantID, queued.ID, ports.AssessmentComparisonItemFilter{AfterPosition: -1, Limit: 10, Disposition: "baseline_only"})
	if err != nil || len(dispositionPage.Items) != 1 || dispositionPage.Items[0].ID != fixed.ID {
		t.Fatalf("disposition page=%+v err=%v", dispositionPage, err)
	}
	if _, err := repository.Get(ctx, "different-tenant", queued.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get error=%v", err)
	}
	if _, err := repository.GetMetadata(ctx, "different-tenant", queued.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant metadata error=%v", err)
	}
	if _, err := repository.GetItem(ctx, "different-tenant", queued.ID, detected.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant item error=%v", err)
	}
	if _, err := repository.ListItems(ctx, "different-tenant", queued.ID, ports.AssessmentComparisonItemFilter{AfterPosition: -1, Limit: 10}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant list error=%v", err)
	}

	assertAssessmentComparisonImmutable(t, ctx, pool, tenantID, cycleID, queued.ID)
	assertAssessmentComparisonRLS(t, ctx, pool, tenantID, queued.ID)
	for _, table := range []string{"assessment_comparisons", "assessment_comparison_items"} {
		var forced bool
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("FORCE RLS %s=%v err=%v", table, forced, err)
		}
	}
}

func TestPostgresAssessmentComparisonRepositoryConcurrentInputReplay(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("comparison-race-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	comparisons := []assessmentcomparison.Comparison{
		postgresQueuedComparison(t, tenantID, cycleID, shared.ID("comparison-race-a-"+suffix), baseline, current, 2, now),
		postgresQueuedComparison(t, tenantID, cycleID, shared.ID("comparison-race-b-"+suffix), baseline, current, 2, now),
	}
	type result struct {
		stored  assessmentcomparison.Comparison
		created bool
		err     error
	}
	results := make(chan result, len(comparisons))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for _, comparison := range comparisons {
		comparison := comparison
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			stored, created, err := NewAssessmentComparisonRepository(pool).CreateQueued(ctx, comparison)
			results <- result{stored: stored, created: created, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	createdCount := 0
	var retainedID shared.ID
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			createdCount++
		}
		if retainedID.IsZero() {
			retainedID = result.stored.ID
		} else if result.stored.ID != retainedID {
			t.Fatalf("concurrent replay retained different IDs: %s and %s", retainedID, result.stored.ID)
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent replay created=%d want=1", createdCount)
	}
}

func TestPostgresAssessmentComparisonRepositoryRejectsCrossCycleSnapshots(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("comparison-fk-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	cycleA, baselineA, _ := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix+"-a")
	_, _, currentB := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix+"-b")
	comparison := postgresQueuedComparison(t, tenantID, cycleA, shared.ID("comparison-cross-cycle-"+suffix), baselineA, currentB, 1, time.Now().UTC())
	if _, _, err := NewAssessmentComparisonRepository(pool).CreateQueued(ctx, comparison); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-cycle snapshot ownership error=%v", err)
	}
}

func TestPostgresAssessmentComparisonServiceParity(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("comparison-service-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	identity, baselineObservation := postgresFindingLineagePair(t, tenantID, cycleID, baseline.ID, "service-identity-"+suffix, "service-baseline-observation-"+suffix, "service-baseline-source-"+suffix, "CVE-2026-2", now)
	lineageRepository := NewFindingLineageRepository(pool)
	if err := lineageRepository.CreateIdentityWithObservation(ctx, identity, baselineObservation); err != nil {
		t.Fatal(err)
	}
	currentObservation := baselineObservation
	currentObservation.ID = shared.ID("service-current-observation-" + suffix)
	currentObservation.SnapshotID = current.ID
	currentObservation.SourceFindingID = "service-current-source-" + suffix
	currentObservation.Severity = shared.SeverityMedium
	currentObservation.ObservedAt = now.Add(time.Second)
	if err := lineageRepository.AppendObservation(ctx, currentObservation); err != nil {
		t.Fatal(err)
	}
	verification, err := comparisonuc.NewRetestVerificationReader(lineageRepository, NewAssessmentSnapshotRepository(pool), NewRetestRepository(pool))
	if err != nil {
		t.Fatal(err)
	}
	service, err := comparisonuc.NewService(
		NewAssessmentComparisonRepository(pool), NewAssessmentSnapshotRepository(pool), NewAssessmentCycleRepository(pool), lineageRepository,
		NewTenantTransactionRunner(pool), postgresLineageAudit{}, postgresLineageClock{now: now.Add(2 * time.Second)}, &postgresLineageIDs{prefix: "comparison-service-id"}, verification, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	queued, created, decision, err := service.Queue(ctx, comparisonuc.QueueInput{
		TenantID: tenantID, BaselineSnapshotID: baseline.ID, CurrentSnapshotID: current.ID,
		Mode: assessmentcomparison.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1, Actor: "integration-test",
	})
	if err != nil || !created || !decision.Allowed {
		t.Fatalf("queue=%+v created=%v decision=%+v err=%v", queued, created, decision, err)
	}
	completed, err := service.Generate(ctx, comparisonuc.WorkInput{TenantID: tenantID, ComparisonID: queued.ID, Actor: "worker", MaxAttempts: 3})
	if err != nil || completed.Status != assessmentcomparison.StatusComplete || len(completed.Items) != 1 || completed.Items[0].Presence != assessmentcomparison.PresenceDetected {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	loaded, err := NewAssessmentComparisonRepository(pool).Get(ctx, tenantID, completed.ID)
	if err != nil || loaded.ContentHash != completed.ContentHash || loaded.Summary.ComparisonID != completed.ID {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
}

func TestMigration0143RollbackGuard(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 137); err != nil {
		t.Fatalf("up to 0137: %v", err)
	}
	pool, err := Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("comparison-rollback-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	assessmentID := shared.ID("lineage-assessment-" + suffix)
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants (id,name) VALUES ($1,$2)`, tenantID.String(), "Rollback tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO engagements (id,tenant_id,name,status) VALUES ($1,$2,$3,'draft')`, assessmentID.String(), tenantID.String(), "Rollback assessment"); err != nil {
		t.Fatal(err)
	}
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, context.Background(), pool, tenantID, suffix)
	comparison := postgresQueuedComparison(t, tenantID, cycleID, shared.ID("comparison-rollback-row-"+suffix), baseline, current, 1, time.Now().UTC())
	if _, created, err := NewAssessmentComparisonRepository(pool).CreateQueued(context.Background(), comparison); err != nil || !created {
		pool.Close()
		t.Fatalf("create rollback guard row created=%v err=%v", created, err)
	}
	pool.Close()
	if err := goose.DownTo(db, ".", 136); err == nil || !strings.Contains(err.Error(), "cannot roll back assessment comparisons") {
		t.Fatalf("rollback guard error=%v", err)
	}
	var exists bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.assessment_comparisons') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("assessment comparisons after blocked rollback exists=%v err=%v", exists, err)
	}
}

func createAssessmentComparisonSnapshots(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID shared.ID, suffix string) (shared.ID, *assessmentsnapshot.Snapshot, *assessmentsnapshot.Snapshot) {
	t.Helper()
	cycleID, baselineID := createFindingLineageSnapshot(t, ctx, pool, tenantID, suffix)
	assessmentID := shared.ID("lineage-assessment-" + suffix)
	runID := shared.ID("comparison-run-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	run := postgresNativeRun(t, tenantID, assessmentID, runID, strings.Repeat("c", 64))
	runRepository := NewScanRunStore(pool)
	sealPostgresNativeRun(t, ctx, runRepository, &run, now)
	snapshot := postgresAssessmentSnapshot(t, tenantID, cycleID, assessmentID, "comparison-current-"+suffix, "comparison-request-"+suffix, run)
	current, created, err := NewAssessmentSnapshotRepository(pool).CreateFinalizedCAS(ctx, snapshot, 1)
	if err != nil || !created {
		t.Fatalf("current snapshot=%+v created=%v err=%v", current, created, err)
	}
	baseline, err := NewAssessmentSnapshotRepository(pool).Get(ctx, tenantID, baselineID)
	if err != nil {
		t.Fatal(err)
	}
	return cycleID, baseline, current
}

func postgresQueuedComparison(t *testing.T, tenantID, cycleID, comparisonID shared.ID, baseline, current *assessmentsnapshot.Snapshot, riskModelVersion int, now time.Time) assessmentcomparison.Comparison {
	t.Helper()
	input := assessmentcomparison.GenerationInput{
		Mode:             assessmentcomparison.ModeLifecycle,
		Baseline:         assessmentcomparison.SnapshotHashRef{ID: baseline.ID, ContentHash: baseline.ContentHash},
		Current:          assessmentcomparison.SnapshotHashRef{ID: current.ID, ContentHash: current.ContentHash},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: riskModelVersion, CoveragePolicyVersion: 1,
	}
	payload, inputHash, err := assessmentcomparison.HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := assessmentcomparison.NewQueued(tenantID, cycleID, comparisonID, input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	return comparison
}

func assertAssessmentComparisonImmutable(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, cycleID, comparisonID shared.ID) {
	t.Helper()
	for name, statement := range map[string]string{
		"comparison":  `UPDATE assessment_comparisons SET version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`,
		"item update": `UPDATE assessment_comparison_items SET current_risk_milli=current_risk_milli+1 WHERE tenant_id=$1 AND cycle_id=$2 AND comparison_id=$3`,
		"item delete": `DELETE FROM assessment_comparison_items WHERE tenant_id=$1 AND cycle_id=$2 AND comparison_id=$3`,
	} {
		err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, tenantID.String(), cycleID.String(), comparisonID.String())
			return err
		})
		if err == nil {
			t.Fatalf("completed %s accepted mutation", name)
		}
	}
}

func assertAssessmentComparisonRLS(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, comparisonID shared.ID) {
	t.Helper()
	role := fmt.Sprintf("synapse_comparison_rls_%d", time.Now().UnixNano())
	quotedRole := pgx.Identifier{role}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+quotedRole+` NOLOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+quotedRole)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+quotedRole)
	})
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+quotedRole); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT ON assessment_comparisons,assessment_comparison_items TO `+quotedRole); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+quotedRole); err != nil {
		t.Fatal(err)
	}
	for tenant, want := range map[string]int64{"different-tenant": 0, tenantID.String(): 1} {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		var count int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM assessment_comparisons WHERE id=$1`, comparisonID.String()).Scan(&count); err != nil || count != want {
			t.Fatalf("RLS tenant=%s count=%d want=%d err=%v", tenant, count, want, err)
		}
	}
}
