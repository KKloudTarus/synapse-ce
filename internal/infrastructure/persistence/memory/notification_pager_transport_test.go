package memory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPagerLifecycleSurvivesOutboxAndDelivery(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	outbox := NewNotificationOutbox()
	source := NewNotificationSource(repo, outbox)
	transactions := NewTenantTransactionRunner()
	mustCreateChannel(t, repo, testChannel("pager-test", notification.ChannelWebhook))
	mustCreateRule(t, repo, testRule("pager-rule", notification.EventFindingStatusChanged, "pager-test"))
	outbox.Activate(notificationTestTenant, notificationTestNow)
	lifecycle := notification.PagerLifecycle{Episode: 2, Revision: 7, Terminal: true}
	record := notification.SourceRecord{TenantID: notificationTestTenant, SourceKind: "finding_status", SourceID: "finding:7", EventType: notification.EventFindingStatusChanged, SubjectKind: "finding", SubjectID: "finding", PagerLifecycle: lifecycle, OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"Finding status changed"}`)}
	if err := transactions.Run(ctx, notificationTestTenant, func(ctx context.Context) error { return outbox.Append(ctx, record) }); err != nil {
		t.Fatal(err)
	}
	if n, err := source.Poll(ctx, notificationTestNow.Add(time.Minute), 0); err != nil || n != 1 {
		t.Fatalf("poll = %d, %v", n, err)
	}
	id := notificationStableID(notificationTestTenant.String(), record.SourceKind, record.SourceID)
	event, err := repo.GetNotificationEvent(ctx, notificationTestTenant, id)
	if err != nil || event.PagerLifecycle != lifecycle {
		t.Fatalf("event lifecycle = %+v, %v", event.PagerLifecycle, err)
	}
	delivery := notificationStableID(notificationTestTenant.String(), id.String(), "pager-test", "")
	work, err := repo.LoadWork(ctx, notificationTestTenant, delivery)
	if err != nil || work.Event.PagerLifecycle != lifecycle {
		t.Fatalf("work lifecycle = %+v, %v", work.Event.PagerLifecycle, err)
	}
}

func TestPagerLifecycleRejectsIncompleteClassification(t *testing.T) {
	outbox := NewNotificationOutbox()
	transactions := NewTenantTransactionRunner()
	record := notification.SourceRecord{TenantID: notificationTestTenant, SourceKind: "finding_status", SourceID: "bad", EventType: notification.EventFindingStatusChanged, SubjectKind: "finding", SubjectID: "finding", PagerLifecycle: notification.PagerLifecycle{Episode: 1}, OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"Changed"}`)}
	err := transactions.Run(context.Background(), notificationTestTenant, func(ctx context.Context) error { return outbox.Append(ctx, record) })
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid lifecycle: %v", err)
	}
}
