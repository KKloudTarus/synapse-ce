package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type closureRoundTripReferences struct{}

func (closureRoundTripReferences) ListAssessmentClosureReferences(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery) ([]assessmentclosure.Reference, error) {
	return nil, nil
}
func (closureRoundTripReferences) ResolveAssessmentClosureReference(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery, assessmentclosure.Reference) error {
	return nil
}

type closureReportFailAfterAppend struct {
	next ports.NotificationOutbox
	err  error
}

func (o closureReportFailAfterAppend) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return o.err
}

type closureReportSaveBarrier struct {
	next    ports.AssessmentClosureReportStore
	arrived chan<- struct{}
	release <-chan struct{}
}

func (store closureReportSaveBarrier) GetClosureReport(ctx context.Context, tenantID, cycleID, manifestID shared.ID, rendererVersion string) (ports.AssessmentClosureReportArtifact, error) {
	return store.next.GetClosureReport(ctx, tenantID, cycleID, manifestID, rendererVersion)
}

func (store closureReportSaveBarrier) SaveClosureReport(ctx context.Context, report ports.AssessmentClosureReportArtifact) (ports.AssessmentClosureReportArtifact, bool, error) {
	select {
	case store.arrived <- struct{}{}:
	case <-ctx.Done():
		return ports.AssessmentClosureReportArtifact{}, false, ctx.Err()
	}
	select {
	case <-store.release:
	case <-ctx.Done():
		return ports.AssessmentClosureReportArtifact{}, false, ctx.Err()
	}
	return store.next.SaveClosureReport(ctx, report)
}

// Exercise the repository and real report renderer, not SQL-only migration
// fixtures: empty lists and JSONB object ordering must preserve domain hashes.
func TestPostgresAssessmentClosureRoundTripReportAndReopen(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("closure-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	comparisons, cycles := NewAssessmentComparisonRepository(pool), NewAssessmentCycleRepository(pool)
	comparison := postgresQueuedComparison(t, tenantID, cycleID, shared.ID("comparison-"+suffix), baseline, current, 1, now)
	if _, _, err := comparisons.CreateQueued(ctx, comparison); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Start(1, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 1); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Complete(nil, 2, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 2); err != nil {
		t.Fatal(err)
	}
	cycle, err := cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		t.Fatal(err)
	}
	version := cycle.Version
	manifest, err := assessmentclosure.NewManifest(shared.ID("manifest-"+suffix), assessmentclosure.ManifestInput{
		TenantID: tenantID, CycleID: cycleID, ManifestVersion: 1, CycleVersion: version + 1,
		RootAssessmentID: baseline.AssessmentID, FinalAssessmentID: current.AssessmentID,
		InitialSnapshot: baseline, FinalSnapshot: current, Comparison: &comparison,
		Path:       []assessmentclosure.PathMember{{PathPosition: 0, AssessmentID: baseline.AssessmentID, AssessmentType: assessmentcycle.AssessmentTypeInitial, RelationshipVersion: 1, SnapshotID: current.ID}},
		References: []assessmentclosure.Reference{{Kind: "test_reference", ID: "reference", Version: 1, Metadata: json.RawMessage(`{"zz":1,"a_long_key":9007199254740993}`)}},
		Reason:     "round trip", AsOfAt: now, CreatedAt: now, CreatedBy: "reviewer",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Seal(now, "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := cycle.CompleteWithManifest(manifest.ID, version, "reviewer", now); err != nil {
		t.Fatal(err)
	}
	commit := ports.AssessmentClosureCommit{Cycle: cycle, Manifest: manifest, ExpectedCycleVersion: version}
	if err := cycles.CommitClosure(ctx, commit); err != nil {
		t.Fatalf("commit empty lists: %v", err)
	}
	loaded, err := cycles.GetClosureManifest(ctx, tenantID, cycleID, manifest.ID)
	if err != nil || loaded.ContentHash != manifest.ContentHash || !bytes.Equal(loaded.References[0].Metadata, manifest.References[0].Metadata) {
		t.Fatalf("JSONB round trip: %+v err=%v", loaded, err)
	}
	if err := cycles.CommitClosure(ctx, commit); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale commit: %v", err)
	}
	if _, err := cycles.GetClosureManifest(ctx, "other-tenant", cycleID, manifest.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	reports, err := cycleuc.NewClosureReportService(cycles, cycles, NewAssessmentSnapshotRepository(pool), comparisons, closureRoundTripReferences{}, assessmentCycleNoopAudit{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := reports.Render(ctx, tenantID, cycleID, manifest.ID)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	version = cycle.Version
	if err := cycle.ReopenFromManifest(version, "reviewer", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Supersede(now.Add(time.Minute), ""); err != nil {
		t.Fatal(err)
	}
	if err := cycles.ReopenClosure(ctx, ports.AssessmentClosureReopen{Cycle: cycle, Manifest: loaded, ExpectedCycleVersion: version}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	history, err := cycles.ListClosureManifests(ctx, tenantID, cycleID)
	if err != nil || len(history) != 1 || history[0].Lifecycle != assessmentclosure.LifecycleSuperseded || history[0].ContentHash != manifest.ContentHash {
		t.Fatalf("history: %+v err=%v", history, err)
	}
	retained, err := reports.Render(ctx, tenantID, cycleID, manifest.ID)
	if err != nil || retained.ContentHash != report.ContentHash || !bytes.Equal(retained.Content, report.Content) {
		t.Fatalf("report changed after reopen: err=%v", err)
	}
}

func TestPostgresClosureReportNotificationCaptureIsAtomicAndDeduplicated(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := fmt.Sprintf("closure-notify-%d", time.Now().UnixNano())
	tenantID := shared.ID("tenant-" + suffix)
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)
	comparisons, cycles := NewAssessmentComparisonRepository(pool), NewAssessmentCycleRepository(pool)
	comparison := postgresQueuedComparison(t, tenantID, cycleID, shared.ID("comparison-"+suffix), baseline, current, 1, now)
	if _, created, err := comparisons.CreateQueued(ctx, comparison); err != nil || !created {
		t.Fatalf("create comparison created=%v err=%v", created, err)
	}
	if err := comparison.Start(1, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 1); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Complete(nil, 2, now); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 2); err != nil {
		t.Fatal(err)
	}
	cycle, err := cycles.GetCycle(ctx, tenantID, cycleID)
	if err != nil {
		t.Fatal(err)
	}
	expectedVersion := cycle.Version
	manifest, err := assessmentclosure.NewManifest(shared.ID("manifest-"+suffix), assessmentclosure.ManifestInput{
		TenantID: tenantID, CycleID: cycleID, ManifestVersion: 1, CycleVersion: expectedVersion + 1,
		RootAssessmentID: baseline.AssessmentID, FinalAssessmentID: current.AssessmentID,
		InitialSnapshot: baseline, FinalSnapshot: current, Comparison: &comparison,
		Path:   []assessmentclosure.PathMember{{PathPosition: 0, AssessmentID: baseline.AssessmentID, AssessmentType: assessmentcycle.AssessmentTypeInitial, RelationshipVersion: 1, SnapshotID: current.ID}},
		Reason: "notification capture", AsOfAt: now, CreatedAt: now, CreatedBy: "reviewer",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Seal(now, "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := cycle.CompleteWithManifest(manifest.ID, expectedVersion, "reviewer", now); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CommitClosure(ctx, ports.AssessmentClosureCommit{Cycle: cycle, Manifest: manifest, ExpectedCycleVersion: expectedVersion}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','v1',true,$2)`, tenantID, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	reporter, err := cycleuc.NewClosureReportService(cycles, cycles, NewAssessmentSnapshotRepository(pool), comparisons, closureRoundTripReferences{}, NewAuditLog(pool))
	if err != nil {
		t.Fatal(err)
	}
	runner, outbox := NewTenantTransactionRunner(pool), NewNotificationOutbox(pool)
	injected := errors.New("capture unavailable")
	if err := reporter.SetNotifications(runner, closureReportFailAfterAppend{next: outbox, err: injected}); err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.Render(ctx, tenantID, cycleID, manifest.ID); !errors.Is(err, injected) {
		t.Fatalf("first render error=%v, want injected capture error", err)
	}
	if _, err := cycles.GetClosureReport(ctx, tenantID, cycleID, manifest.ID, manifest.RendererContractVersion); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("report escaped rollback: %v", err)
	}
	var sourceCount, auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1`, tenantID).Scan(&sourceCount); err != nil || sourceCount != 0 {
		t.Fatalf("rolled-back source count=%d err=%v", sourceCount, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='assessment_cycle.report_generated' AND target=$1`, manifest.ID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("rolled-back audit count=%d err=%v", auditCount, err)
	}
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	concurrentReporter, err := cycleuc.NewClosureReportService(cycles, closureReportSaveBarrier{next: cycles, arrived: arrived, release: release}, NewAssessmentSnapshotRepository(pool), comparisons, closureRoundTripReferences{}, NewAuditLog(pool))
	if err != nil {
		t.Fatal(err)
	}
	if err := concurrentReporter.SetNotifications(runner, outbox); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := concurrentReporter.Render(ctx, tenantID, cycleID, manifest.ID)
			errs <- err
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-t.Context().Done():
			t.Fatal("concurrent fresh render did not reach SaveClosureReport")
		}
	}
	close(release)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent fresh render: %v", err)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='assessment_cycle.report_generated' AND target=$1`, manifest.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("concurrent retry audit count=%d err=%v", auditCount, err)
	}
	for _, check := range []struct {
		query string
		args  []any
	}{
		{`SELECT count(*) FROM assessment_cycle_closure_reports WHERE tenant_id=$1 AND cycle_id=$2 AND manifest_id=$3`, []any{tenantID, cycleID, manifest.ID}},
		{`SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type='report.generated'`, []any{tenantID}},
	} {
		var count int
		if err := pool.QueryRow(ctx, check.query, check.args...).Scan(&count); err != nil || count != 1 {
			t.Fatalf("committed count=%d err=%v query=%s", count, err, check.query)
		}
	}
}
