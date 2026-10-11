package memory

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func appendScanRecord(t *testing.T, transactions *TenantTransactionRunner, outbox *NotificationOutbox, sourceID string, at time.Time, fail error) error {
	t.Helper()
	return transactions.Run(context.Background(), notificationTestTenant, func(ctx context.Context) error {
		if err := outbox.Append(ctx, notification.SourceRecord{
			TenantID: notificationTestTenant, SourceKind: "scan_job", SourceID: sourceID, EventType: notification.EventScanCompleted,
			OccurredAt: at, Data: json.RawMessage(`{"title":"Scan completed"}`),
		}); err != nil {
			return err
		}
		return fail
	})
}

// TestSourceDrainsTheOutboxThroughTheRepository is the producer path end to end: append in a
// business transaction, poll, and find the delivery the matching rule asked for.
func TestSourceDrainsTheOutboxThroughTheRepository(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	outbox := NewNotificationOutbox()
	source := NewNotificationSource(repo, outbox)
	transactions := NewTenantTransactionRunner()
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelWebhook))
	mustCreateRule(t, repo, testRule("rule-1", notification.EventScanCompleted, "ch-1"))

	// Before the first poll the tenant is not active, so this record is dropped.
	if err := appendScanRecord(t, transactions, outbox, "scan-before", notificationTestNow.Add(-time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if n, err := source.Poll(ctx, notificationTestNow, 0); err != nil || n != 0 || !outbox.isActivated(notificationTestTenant) {
		t.Fatalf("activation poll = %d err=%v", n, err)
	}

	rolledBack := errors.New("business write failed")
	if err := appendScanRecord(t, transactions, outbox, "scan-rolled-back", notificationTestNow.Add(time.Minute), rolledBack); !errors.Is(err, rolledBack) {
		t.Fatalf("rolled-back append err = %v", err)
	}
	if err := appendScanRecord(t, transactions, outbox, "scan-1", notificationTestNow.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if n, err := source.Poll(ctx, notificationTestNow.Add(2*time.Minute), 0); err != nil || n != 1 {
		t.Fatalf("drain poll = %d err=%v, want only the committed record", n, err)
	}
	if n, _ := source.Poll(ctx, notificationTestNow.Add(3*time.Minute), 0); n != 0 {
		t.Fatalf("second drain published %d records again", n)
	}

	eventID := notificationStableID(notificationTestTenant.String(), "scan_job", "scan-1")
	delivery := notificationStableID(notificationTestTenant.String(), eventID.String(), "ch-1", "")
	if d, err := repo.GetDelivery(ctx, notificationTestTenant, delivery); err != nil || d.EventID != eventID {
		t.Fatalf("delivery = %+v err=%v", d, err)
	}
}

// TestSourceQuarantinesARecordItCannotProject is #1343 on the memory source: a record whose event
// the domain refuses is marked processed with a reason, and the record after it still publishes in
// the same tick.
func TestSourceQuarantinesARecordItCannotProject(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	outbox := NewNotificationOutbox()
	source := NewNotificationSource(repo, outbox)
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelWebhook))
	mustCreateRule(t, repo, testRule("rule-1", notification.EventScanCompleted, "ch-1"))
	outbox.Activate(notificationTestTenant, notificationTestNow)
	putSourceRecord(outbox, "bad", notificationTestNow, json.RawMessage(`[]`))
	putSourceRecord(outbox, "too-large", notificationTestNow.Add(time.Second), json.RawMessage(`{"title":"`+strings.Repeat("x", 17<<10)+`"}`))
	putSourceRecord(outbox, "good", notificationTestNow.Add(2*time.Second), json.RawMessage(`{"title":"Scan completed"}`))

	polled := notificationTestNow.Add(time.Minute)
	if n, err := source.Poll(ctx, polled, 0); err != nil || n != 3 {
		t.Fatalf("poll = %d err=%v, want all three records processed", n, err)
	}
	if n, _ := source.Poll(ctx, polled.Add(time.Minute), 0); n != 0 {
		t.Fatalf("quarantined records were polled again: %d", n)
	}
	eventID := notificationStableID(notificationTestTenant.String(), "scan_job", "good")
	if _, err := repo.GetDelivery(ctx, notificationTestTenant, notificationStableID(notificationTestTenant.String(), eventID.String(), "ch-1", "")); err != nil {
		t.Fatalf("the valid record after the bad ones was not delivered: %v", err)
	}
	page, err := repo.ListSourceFailures(ctx, ports.NotificationSourceFailureFilter{TenantID: notificationTestTenant})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range page.Items {
		if !f.ProcessedAt.Equal(polled) || f.EventType != notification.EventScanCompleted {
			t.Fatalf("failure = %+v", f)
		}
		got[f.SourceID] = f.FailedReason
	}
	if want := map[string]string{"bad": "invalid_event", "too-large": "event_data_too_large"}; !maps.Equal(got, want) {
		t.Fatalf("failures = %v, want %v", got, want)
	}
	if other, _ := repo.ListSourceFailures(ctx, ports.NotificationSourceFailureFilter{TenantID: "tenant-other"}); len(other.Items) != 0 {
		t.Fatalf("another tenant sees %d failures", len(other.Items))
	}
}

// TestSourceSpendsOneBudgetPerTick checks that limit bounds the whole tick, not each tenant.
func TestSourceSpendsOneBudgetPerTick(t *testing.T) {
	repo := newTestNotificationRepository()
	outbox := NewNotificationOutbox()
	source := NewNotificationSource(repo, outbox)
	for _, tenant := range []shared.ID{"tenant-a", "tenant-b"} {
		outbox.Activate(tenant, notificationTestNow)
		for _, id := range []string{"scan-1", "scan-2"} {
			outbox.records[sourceRecordKey{tenant: tenant, kind: "scan_job", id: id}] = outboxEntry{record: notification.SourceRecord{
				TenantID: tenant, SourceKind: "scan_job", SourceID: id, EventType: notification.EventScanCompleted,
				OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"Scan completed"}`), SchemaVersion: 1,
			}}
		}
	}
	if n, err := source.Poll(context.Background(), notificationTestNow, 3); err != nil || n != 3 {
		t.Fatalf("poll = %d err=%v, want the budget of 3 across both tenants", n, err)
	}
	if n, _ := source.Poll(context.Background(), notificationTestNow, 3); n != 1 {
		t.Fatalf("second poll = %d, want the one record left", n)
	}
}

// putSourceRecord stores a record as the capture triggers would, bypassing Append's checks.
func putSourceRecord(outbox *NotificationOutbox, sourceID string, at time.Time, data json.RawMessage) {
	outbox.records[sourceRecordKey{tenant: notificationTestTenant, kind: "scan_job", id: sourceID}] = outboxEntry{record: notification.SourceRecord{
		TenantID: notificationTestTenant, SourceKind: "scan_job", SourceID: sourceID, EventType: notification.EventScanCompleted,
		OccurredAt: at, Data: data, SchemaVersion: 1,
	}}
}
