package assessmentcycle_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestClosureReportGoldenDeterminismAndWorker(t *testing.T) {
	harness := newClosureHarness(t)
	manifest := commitClosureForReport(t, harness)
	report, err := harness.api.GetClosureReport(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID))
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := harness.api.GetClosureReport(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID))
	if err != nil {
		t.Fatal(err)
	}
	if report.ContentHash != repeated.ContentHash || !bytes.Equal(report.Content, repeated.Content) {
		t.Fatal("same manifest and renderer version produced different report bytes")
	}
	goldenPath := filepath.Join("testdata", "assessment_closure_report.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(report.Content, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(golden), report.Content) {
		t.Fatalf("closure report differs from golden fixture\n got: %s\nwant: %s", report.Content, bytes.TrimSpace(golden))
	}
	job, err := harness.queue.Claim(context.Background(), time.Minute, cycleuc.AssessmentClosureReportJobKind)
	if err != nil || job == nil {
		t.Fatalf("claim report job=%+v err=%v", job, err)
	}
	reporter, err := cycleuc.NewClosureReportService(harness.cycles, harness.cycles, harness.snapshots, harness.comparisons, closureDecisionReader{}, &recordAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.HandleJob(context.Background(), *job); err != nil {
		t.Fatal(err)
	}
}

func TestClosureReportFailsClosedForMissingTamperedAndCrossTenantReferences(t *testing.T) {
	harness := newClosureHarness(t)
	manifest := commitClosureForReport(t, harness)

	tests := []struct {
		name string
		repo ports.AssessmentSnapshotRepository
		code string
	}{
		{
			name: "missing",
			repo: snapshotGetOverride{AssessmentSnapshotRepository: harness.snapshots, get: func(context.Context, shared.ID, shared.ID) (*assessmentsnapshot.Snapshot, error) {
				return nil, shared.ErrNotFound
			}},
			code: cycleuc.CodeClosureReferenceMissing,
		},
		{
			name: "tampered",
			repo: snapshotGetOverride{AssessmentSnapshotRepository: harness.snapshots, get: func(ctx context.Context, tenantID, snapshotID shared.ID) (*assessmentsnapshot.Snapshot, error) {
				snapshot, err := harness.snapshots.Get(ctx, tenantID, snapshotID)
				if err == nil && snapshotID == shared.ID(manifest.FinalSnapshotID) {
					copy := *snapshot
					copy.ContentHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
					snapshot = &copy
				}
				return snapshot, err
			}},
			code: cycleuc.CodeClosureReferenceTampered,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			audit := &recordAudit{}
			reporter, err := cycleuc.NewClosureReportService(harness.cycles, harness.cycles, test.repo, harness.comparisons, closureDecisionReader{}, audit)
			if err != nil {
				t.Fatal(err)
			}
			_, err = reporter.Render(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID))
			if cycleuc.ErrorCode(err) != test.code {
				t.Fatalf("error=%v code=%q want=%q", err, cycleuc.ErrorCode(err), test.code)
			}
			if len(audit.entries) != 1 || audit.entries[0].Action != "assessment_cycle.report_reference_failed" || audit.entries[0].Metadata["reason_code"] != test.code {
				t.Fatalf("audit=%+v", audit.entries)
			}
		})
	}
	reporter, err := cycleuc.NewClosureReportService(harness.cycles, harness.cycles, harness.snapshots, harness.comparisons, closureDecisionReader{}, &recordAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.Render(context.Background(), "other-tenant", harness.cycleID, shared.ID(manifest.ID)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant report error=%v", err)
	}
}

func TestClosureReportAuditRecoversAfterArtifactWasCached(t *testing.T) {
	harness := newClosureHarness(t)
	manifest := commitClosureForReport(t, harness)
	audit := &retryReportAudit{fail: true}
	reporter, err := cycleuc.NewClosureReportService(harness.cycles, harness.cycles, harness.snapshots, harness.comparisons, closureDecisionReader{}, audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.Render(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID)); err == nil {
		t.Fatal("expected injected audit failure")
	}
	if _, err := reporter.Render(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID)); err != nil {
		t.Fatalf("cached artifact retry: %v", err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "assessment_cycle.report_generated" {
		t.Fatalf("audit=%+v", audit.entries)
	}
}

func commitClosureForReport(t *testing.T, harness closureHarness) cycleuc.ClosureManifestView {
	t.Helper()
	preview, err := harness.api.PreviewClosure(context.Background(), cycleuc.ClosurePreviewInput{
		TenantID: harness.tenantID, Actor: "reviewer", CycleID: harness.cycleID, Reason: "release accepted",
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := harness.api.CommitClosure(context.Background(), cycleuc.ClosureCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: harness.tenantID, Actor: "reviewer", Route: "/closure-commits", IdempotencyKey: "report-close"},
		CycleID: harness.cycleID, ExpectedVersion: preview.CycleVersion, PreviewToken: preview.PreviewToken, Reason: "release accepted",
	})
	if err != nil {
		t.Fatal(err)
	}
	var result cycleuc.ClosureCommitResult
	if err := json.Unmarshal(response.Body, &result); err != nil {
		t.Fatal(err)
	}
	return result.Manifest
}

type snapshotGetOverride struct {
	ports.AssessmentSnapshotRepository
	get func(context.Context, shared.ID, shared.ID) (*assessmentsnapshot.Snapshot, error)
}

func (repo snapshotGetOverride) Get(ctx context.Context, tenantID, snapshotID shared.ID) (*assessmentsnapshot.Snapshot, error) {
	return repo.get(ctx, tenantID, snapshotID)
}

type retryReportAudit struct {
	fail    bool
	entries []ports.AuditEntry
}

func (audit *retryReportAudit) Record(ctx context.Context, entry ports.AuditEntry) error {
	return audit.RecordOnce(ctx, entry)
}

func (audit *retryReportAudit) RecordOnce(_ context.Context, entry ports.AuditEntry) error {
	if audit.fail {
		audit.fail = false
		return errors.New("injected audit failure")
	}
	if len(audit.entries) == 0 {
		audit.entries = append(audit.entries, entry)
	}
	return nil
}

var _ ports.AssessmentSnapshotRepository = snapshotGetOverride{}
var _ ports.IdempotentAuditLogger = (*retryReportAudit)(nil)

type closureOutbox struct{ records []notification.SourceRecord }

func (o *closureOutbox) Append(_ context.Context, record notification.SourceRecord) error {
	o.records = append(o.records, record)
	return nil
}

type failingClosureOutbox struct {
	next ports.NotificationOutbox
	err  error
}

func (o failingClosureOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return o.err
}

// TestClosureReportAnnouncesOnlyTheFirstSeal pins the assessment-cycle half of
// report.generated: the record is appended when the store accepts a new
// artifact, and a cached read of the same report announces nothing again.
func TestClosureReportAnnouncesOnlyTheFirstSeal(t *testing.T) {
	harness := newClosureHarness(t)
	manifest := commitClosureForReport(t, harness)
	outbox := &closureOutbox{}
	reporter, err := cycleuc.NewClosureReportService(harness.cycles, harness.cycles, harness.snapshots, harness.comparisons, closureDecisionReader{}, &recordAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.SetNotifications(memory.NewTenantTransactionRunner(), outbox); err != nil {
		t.Fatal(err)
	}
	report, err := reporter.Render(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reporter.Render(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID)); err != nil {
		t.Fatal(err)
	}
	if len(outbox.records) != 1 {
		t.Fatalf("a cached report must not be announced again, got %d records", len(outbox.records))
	}
	record := outbox.records[0]
	if record.EventType != notification.EventReportGenerated || record.SourceKind != "report" {
		t.Fatalf("record = %+v", record)
	}
	if record.SourceID != "assessment_closure_report:"+report.ContentHash || record.SubjectID != report.ContentHash {
		t.Fatalf("source key = %q, subject = %q, report hash = %q", record.SourceID, record.SubjectID, report.ContentHash)
	}
	if record.OccurredAt != report.GeneratedAt.UTC() {
		t.Fatalf("occurred_at = %v, want the seal time %v", record.OccurredAt, report.GeneratedAt.UTC())
	}
	if !record.EngagementID.IsZero() {
		t.Fatalf("a closure report belongs to a cycle, not an engagement: %q", record.EngagementID)
	}
}

func TestClosureReportNotificationFailureRollsBackAPISealAndRetryCapturesOnce(t *testing.T) {
	harness := newClosureHarness(t)
	manifest := commitClosureForReport(t, harness)
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(harness.tenantID, harness.clock.t.Add(-time.Minute))
	injected := errors.New("capture unavailable")
	if err := harness.reporter.SetNotifications(memory.NewTenantTransactionRunner(), failingClosureOutbox{next: outbox, err: injected}); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.api.GetClosureReport(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID)); !errors.Is(err, injected) {
		t.Fatalf("render error = %v, want injected capture error", err)
	}
	if _, err := harness.cycles.GetClosureReport(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID), manifest.RendererContractVersion); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("report persisted after rolled-back capture: %v", err)
	}
	if records := outbox.Records(harness.tenantID); len(records) != 0 {
		t.Fatalf("source records persisted after rollback: %+v", records)
	}
	if err := harness.reporter.SetNotifications(memory.NewTenantTransactionRunner(), outbox); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.api.GetClosureReport(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID)); err != nil {
		t.Fatalf("retry render: %v", err)
	}
	if records := outbox.Records(harness.tenantID); len(records) != 1 || records[0].EventType != notification.EventReportGenerated {
		t.Fatalf("retry source records = %+v, want one report.generated", records)
	}
}

func TestClosureReportNotificationFailureDoesNotRecordAudit(t *testing.T) {
	harness := newClosureHarness(t)
	manifest := commitClosureForReport(t, harness)
	audit := &recordAudit{}
	reporter, err := cycleuc.NewClosureReportService(harness.cycles, harness.cycles, harness.snapshots, harness.comparisons, closureDecisionReader{}, audit)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("capture unavailable")
	if err := reporter.SetNotifications(memory.NewTenantTransactionRunner(), failingClosureOutbox{next: &closureOutbox{}, err: injected}); err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.Render(context.Background(), harness.tenantID, harness.cycleID, shared.ID(manifest.ID)); !errors.Is(err, injected) {
		t.Fatalf("render error = %v, want injected capture error", err)
	}
	if len(audit.entries) != 0 {
		t.Fatalf("audit entries=%+v, want none after outbox failure", audit.entries)
	}
}
