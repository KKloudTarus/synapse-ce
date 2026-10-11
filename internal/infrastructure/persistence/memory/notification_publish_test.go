package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
)

func testEvent(sourceID string, event notification.EventType) notification.Event {
	return notification.Event{
		TenantID: notificationTestTenant, ID: shared.ID("event-" + sourceID), Type: event, SourceKind: "scan_job", SourceID: sourceID,
		SchemaVersion: 1, OccurredAt: notificationTestNow, Data: json.RawMessage(`{"title":"Scan completed"}`),
	}
}

func TestPublishFansOutOncePerChannelAndRecipient(t *testing.T) {
	ctx := context.Background()
	jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return notificationTestNow })
	repo := NewNotificationRepository(jobs, func() time.Time { return notificationTestNow })
	mustCreateChannel(t, repo, testChannel("ch-hook", notification.ChannelWebhook))
	mustCreateChannel(t, repo, testChannel("ch-mail", notification.ChannelEmail, "a@example.com", "b@example.com"))
	disabled := testChannel("ch-off", notification.ChannelSlack)
	disabled.Enabled = false
	mustCreateChannel(t, repo, disabled)
	mustCreateRule(t, repo, testRule("rule-1", notification.EventScanCompleted, "ch-hook", "ch-mail"))
	mustCreateRule(t, repo, testRule("rule-2", notification.EventScanCompleted, "ch-hook", "ch-off"))
	mustCreateRule(t, repo, testRule("rule-other", notification.EventQualityGateFailed, "ch-hook"))

	event := testEvent("scan-1", notification.EventScanCompleted)
	ids, err := repo.Publish(ctx, event)
	if err != nil || len(ids) != 3 {
		t.Fatalf("deliveries = %v err=%v, want one webhook and two email deliveries", ids, err)
	}
	hook := notificationStableID(notificationTestTenant.String(), event.ID.String(), "ch-hook", "")
	delivery, err := repo.GetDelivery(ctx, notificationTestTenant, hook)
	if err != nil || len(delivery.MatchedRuleIDs) != 2 || delivery.State != notification.DeliveryPending {
		t.Fatalf("webhook delivery = %+v err=%v, want both rules and pending", delivery, err)
	}
	if depth, _ := jobs.Depth(ctx, notificationDeliverJobKey); depth != 3 {
		t.Fatalf("queued jobs = %d, want 3", depth)
	}
	matched, revisions := repo.MatchedRules(notificationTestTenant, event.ID)
	if len(matched) != 3 || revisions["rule-1"] != 1 || revisions["rule-2"] != 1 || len(revisions) != 2 {
		t.Fatalf("matched rules = %v revisions = %v", matched, revisions)
	}

	replayed, err := repo.Publish(ctx, event)
	if err != nil || len(replayed) != 3 {
		t.Fatalf("replay = %v err=%v, want the original deliveries", replayed, err)
	}
	if depth, _ := jobs.Depth(ctx, notificationDeliverJobKey); depth != 3 {
		t.Fatalf("replay queued more jobs: %d", depth)
	}
}

func TestPublishWithoutMatchingRulesRecordsTheEvent(t *testing.T) {
	repo := newTestNotificationRepository()
	ids, err := repo.Publish(context.Background(), testEvent("scan-1", notification.EventScanCompleted))
	if err != nil || len(ids) != 0 {
		t.Fatalf("deliveries = %v err=%v", ids, err)
	}
	if _, err := repo.Publish(context.Background(), notification.Event{TenantID: notificationTestTenant}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid event err = %v", err)
	}
}

func TestPublishToChannelLimitsChannelTests(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelWebhook))
	for i := range maxChannelTestsPerMinute {
		if _, err := repo.PublishToChannel(ctx, testEvent(fmt.Sprintf("test-%d", i), notification.EventTest), "ch-1"); err != nil {
			t.Fatalf("test %d: %v", i, err)
		}
	}
	if _, err := repo.PublishToChannel(ctx, testEvent("test-over", notification.EventTest), "ch-1"); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("eleventh test err = %v", err)
	}
	if _, err := repo.PublishToChannel(ctx, testEvent("test-x", notification.EventTest), "ch-missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("test to a missing channel err = %v", err)
	}
}
