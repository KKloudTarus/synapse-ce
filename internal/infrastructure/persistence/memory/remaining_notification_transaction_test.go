package memory

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"testing"
)

func TestIndependentAlertSurvivesCallerRollback(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	runner, outbox := NewTenantTransactionRunner(), NewNotificationOutbox()
	outbox.Activate(notificationTestTenant, notificationTestNow)
	failure := errors.New("report failed")
	appendAlert := func(ctx context.Context, id string) error {
		return outbox.Append(ctx, notification.SourceRecord{TenantID: notificationTestTenant, SourceKind: "evidence_chain", SourceID: id, EventType: notification.EventEvidenceChainBroken, OccurredAt: notificationTestNow, Data: json.RawMessage(`{"engagement_id":"eng","evidence_chain_id":"eng","reason_code":"hash_mismatch"}`)})
	}
	err := runner.Run(ctx, notificationTestTenant, func(outer context.Context) error {
		if err := appendAlert(outer, "outer"); err != nil {
			return err
		}
		if err := runner.RunIndependent(outer, notificationTestTenant, func(inner context.Context) error { return appendAlert(inner, "independent") }); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	records := outbox.Records(notificationTestTenant)
	if len(records) != 1 || records[0].SourceID != "independent" {
		t.Fatalf("independent alert lost: %+v", records)
	}
	if err := runner.RunIndependent(ctx, "foreign", func(context.Context) error { t.Fatal("foreign callback ran"); return nil }); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("foreign transaction=%v", err)
	}
}

func TestMemoryProjectionRetainsCaptureTimeContextAndSubject(t *testing.T) {
	ctx := context.Background()
	repo, outbox := newTestNotificationRepository(), NewNotificationOutbox()
	source := NewNotificationSource(repo, outbox)
	source.AddTenant(notificationTestTenant)
	if _, err := source.Poll(ctx, notificationTestNow, 10); err != nil {
		t.Fatal(err)
	}
	record, err := notification.SnapshotSourceRecord(notification.SourceRecord{TenantID: notificationTestTenant, SourceKind: "engagement_created", SourceID: "eng", EventType: notification.EventEngagementCreated, EngagementID: "eng", SubjectKind: "engagement", SubjectID: "eng", OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"Engagement created","summary":"Created","engagement_id":"eng","lead_user_id":""}`)}, map[string]string{"engagement_name": "Immutable name"})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewTenantTransactionRunner().Run(ctx, notificationTestTenant, func(ctx context.Context) error { return outbox.Append(ctx, record) }); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, notificationTestNow, 10); err != nil {
		t.Fatal(err)
	}
	events, err := repo.ListRecentNotificationEvents(ctx, notificationTestTenant, notification.EventEngagementCreated, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if events[0].SubjectID != "eng" || events[0].SubjectKind != "engagement" || string(events[0].Context) != string(record.Context) {
		t.Fatalf("capture changed at projection: %+v", events[0])
	}
}

func TestNotificationOutboxDefersOrdinarySourceUntilProducerCommit(t *testing.T) {
	runner, outbox := NewTenantTransactionRunner(), NewNotificationOutbox()
	repo := newTestNotificationRepository()
	source := NewNotificationSource(repo, outbox)
	outbox.Activate(notificationTestTenant, notificationTestNow)
	record := notification.SourceRecord{
		TenantID: notificationTestTenant, SourceKind: "scan_job", SourceID: "rolled-back-source", EventType: notification.EventScanCompleted,
		OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"Scan completed"}`),
	}
	appended := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	rollback := errors.New("business audit failed")
	go func() {
		done <- runner.Run(context.Background(), notificationTestTenant, func(tx context.Context) error {
			if err := outbox.Append(tx, record); err != nil {
				return err
			}
			close(appended)
			<-release
			return rollback
		})
	}()
	<-appended

	if count, err := source.Poll(context.Background(), notificationTestNow, 10); err != nil || count != 0 {
		t.Fatalf("poll saw uncommitted ordinary source: count=%d err=%v", count, err)
	}
	close(release)
	if err := <-done; !errors.Is(err, rollback) {
		t.Fatalf("producer result=%v, want rollback", err)
	}
	if records := outbox.Records(notificationTestTenant); len(records) != 0 {
		t.Fatalf("rolled-back ordinary source became visible: %+v", records)
	}
	if events, err := repo.ListRecentNotificationEvents(context.Background(), notificationTestTenant, notification.EventScanCompleted, 10); err != nil || len(events) != 0 {
		t.Fatalf("poll published rolled-back ordinary source: events=%+v err=%v", events, err)
	}
}

func TestNotificationOutboxDefersApprovalRosterUntilProducerCommit(t *testing.T) {
	runner, outbox := NewTenantTransactionRunner(), NewNotificationOutbox()
	repo := newTestNotificationRepository()
	source := NewNotificationSource(repo, outbox)
	outbox.Activate(notificationTestTenant, notificationTestNow)
	record := memoryApprovalSourceRecord("rolled-back-approval")
	appended := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	rollback := errors.New("approval audit failed")
	go func() {
		done <- runner.Run(context.Background(), notificationTestTenant, func(tx context.Context) error {
			if err := outbox.AppendApprovalSource(tx, record, []shared.ID{"reviewer-a", "reviewer-b"}); err != nil {
				return err
			}
			close(appended)
			<-release
			return rollback
		})
	}()
	<-appended

	readCtx := shared.WithTenant(context.Background(), notificationTestTenant)
	if recipients, err := outbox.ApprovalNotificationRecipients(readCtx, notificationTestTenant, record.SourceKind, record.SourceID); err != nil || len(recipients) != 0 {
		t.Fatalf("uncommitted approval roster was readable: recipients=%v err=%v", recipients, err)
	}
	if count, err := source.Poll(context.Background(), notificationTestNow, 10); err != nil || count != 0 {
		t.Fatalf("poll saw uncommitted approval source: count=%d err=%v", count, err)
	}
	close(release)
	if err := <-done; !errors.Is(err, rollback) {
		t.Fatalf("producer result=%v, want rollback", err)
	}
	if recipients, err := outbox.ApprovalNotificationRecipients(readCtx, notificationTestTenant, record.SourceKind, record.SourceID); err != nil || len(recipients) != 0 {
		t.Fatalf("rolled-back approval roster remained readable: recipients=%v err=%v", recipients, err)
	}
	if events, err := repo.ListRecentNotificationEvents(context.Background(), notificationTestTenant, notification.EventApprovalRequested, 10); err != nil || len(events) != 0 {
		t.Fatalf("poll published rolled-back approval source: events=%+v err=%v", events, err)
	}
}

func TestNotificationOutboxCommitsApprovalSourceOnceWithFirstPrivateRoster(t *testing.T) {
	runner, outbox := NewTenantTransactionRunner(), NewNotificationOutbox()
	repo := newTestNotificationRepository()
	source := NewNotificationSource(repo, outbox)
	outbox.Activate(notificationTestTenant, notificationTestNow)
	record := memoryApprovalSourceRecord("committed-approval")
	first := []shared.ID{"reviewer-b", "reviewer-a", "reviewer-a", ""}
	if err := runner.Run(context.Background(), notificationTestTenant, func(tx context.Context) error {
		if err := outbox.AppendApprovalSource(tx, record, first); err != nil {
			return err
		}
		return outbox.AppendApprovalSource(tx, record, []shared.ID{"reviewer-new"})
	}); err != nil {
		t.Fatal(err)
	}
	if records := outbox.Records(notificationTestTenant); len(records) != 1 || records[0].SourceID != record.SourceID {
		t.Fatalf("committed approval source=%+v, want one first source", records)
	}
	readCtx := shared.WithTenant(context.Background(), notificationTestTenant)
	recipients, err := outbox.ApprovalNotificationRecipients(readCtx, notificationTestTenant, record.SourceKind, record.SourceID)
	if err != nil || len(recipients) != 2 || recipients[0] != "reviewer-a" || recipients[1] != "reviewer-b" {
		t.Fatalf("committed immutable roster=%v err=%v", recipients, err)
	}
	if count, err := source.Poll(context.Background(), notificationTestNow, 10); err != nil || count != 1 {
		t.Fatalf("first committed poll=%d err=%v", count, err)
	}
	if count, err := source.Poll(context.Background(), notificationTestNow, 10); err != nil || count != 0 {
		t.Fatalf("committed source was published more than once: count=%d err=%v", count, err)
	}
	if events, err := repo.ListRecentNotificationEvents(context.Background(), notificationTestTenant, notification.EventApprovalRequested, 10); err != nil || len(events) != 1 {
		t.Fatalf("committed approval events=%+v err=%v", events, err)
	}
}

func TestNotificationOutboxCommitsFirstOrdinarySourceOnce(t *testing.T) {
	runner, outbox := NewTenantTransactionRunner(), NewNotificationOutbox()
	repo := newTestNotificationRepository()
	source := NewNotificationSource(repo, outbox)
	outbox.Activate(notificationTestTenant, notificationTestNow)
	first := notification.SourceRecord{
		TenantID: notificationTestTenant, SourceKind: "scan_job", SourceID: "committed-ordinary", EventType: notification.EventScanCompleted,
		OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"first capture"}`),
	}
	second := first
	second.Data = json.RawMessage(`{"title":"replayed capture"}`)
	if err := runner.Run(context.Background(), notificationTestTenant, func(tx context.Context) error {
		if err := outbox.Append(tx, first); err != nil {
			return err
		}
		return outbox.Append(tx, second)
	}); err != nil {
		t.Fatal(err)
	}
	records := outbox.Records(notificationTestTenant)
	if len(records) != 1 || string(records[0].Data) != string(first.Data) {
		t.Fatalf("first ordinary source was not retained: %+v", records)
	}
	if count, err := source.Poll(context.Background(), notificationTestNow, 10); err != nil || count != 1 {
		t.Fatalf("first committed poll=%d err=%v", count, err)
	}
	if count, err := source.Poll(context.Background(), notificationTestNow, 10); err != nil || count != 0 {
		t.Fatalf("ordinary source was published more than once: count=%d err=%v", count, err)
	}
}

func memoryApprovalSourceRecord(sourceID string) notification.SourceRecord {
	return notification.SourceRecord{
		TenantID: notificationTestTenant, SourceKind: "approval_requested", SourceID: sourceID, EventType: notification.EventApprovalRequested,
		EngagementID: "eng", SubjectKind: "approval", SubjectID: sourceID, OccurredAt: notificationTestNow,
		Data: json.RawMessage(`{"approval_id":"` + sourceID + `","engagement_id":"eng","kind":"agent","status":"pending","approver_count":2}`),
	}
}
