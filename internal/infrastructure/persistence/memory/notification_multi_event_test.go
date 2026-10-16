package memory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPublishMultiEventRuleMatchesSelectedTypesAndKeepsSelectionPrivate(t *testing.T) {
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("ch-multi", notification.ChannelWebhook))
	rule := testRule("multi", notification.EventFindingCreated, "ch-multi")
	rule.EventTypes = []notification.EventType{notification.EventFindingCreated, notification.EventFindingStatusChanged}
	mustCreateRule(t, repo, rule)

	for _, eventType := range []notification.EventType{notification.EventFindingCreated, notification.EventFindingStatusChanged} {
		event := testEvent("multi-"+string(eventType), eventType)
		if ids, err := repo.Publish(context.Background(), event); err != nil || len(ids) != 1 {
			t.Fatalf("publish %s = %v, %v; want one delivery", eventType, ids, err)
		}
	}
	stored, err := repo.GetRule(context.Background(), notificationTestTenant, "multi")
	if err != nil {
		t.Fatal(err)
	}
	stored.EventTypes[0] = notification.EventScanCompleted
	fresh, err := repo.GetRule(context.Background(), notificationTestTenant, "multi")
	if err != nil || fresh.EventTypes[0] != notification.EventFindingCreated {
		t.Fatalf("mutating returned event selection altered storage: %+v, %v", fresh.EventTypes, err)
	}
}

func TestMultiEventRuleMaterializesOneMixedDigestWindowIdempotently(t *testing.T) {
	ctx := context.Background()
	now := notificationTestNow
	repo := NewNotificationRepository(nil, func() time.Time { return now })
	channel := mustCreateChannel(t, repo, testChannel("ch-mixed-digest", notification.ChannelWebhook))
	types := []notification.EventType{
		notification.EventEngagementCreated,
		notification.EventEngagementStatusChanged,
		notification.EventFindingCreated,
		notification.EventFindingStatusChanged,
		notification.EventFindingCommented,
	}
	rule := testRule("mixed-digest", types[0], channel.ID)
	rule.EventTypes = types
	rule.Cadence = notification.CadenceHourly
	mustCreateRule(t, repo, rule)

	for index, eventType := range types {
		event := testEvent("mixed-digest-"+string(rune('a'+index)), eventType)
		event.Context = json.RawMessage(`{"vars":{"event_type":"` + string(eventType) + `","occurred_at":"2026-09-28T09:00:00Z","title":"event"}}`)
		if ids, err := repo.Publish(ctx, event); err != nil || len(ids) != 0 {
			t.Fatalf("publish %s = %v, %v; want queued digest membership", eventType, ids, err)
		}
	}
	if count, err := repo.materializeDigests(ctx, notificationTestTenant, now.Add(time.Hour), 10); err != nil || count != 1 {
		t.Fatalf("materialize = %d, %v; want one digest", count, err)
	}
	if count, err := repo.materializeDigests(ctx, notificationTestTenant, now.Add(2*time.Hour), 10); err != nil || count != 0 {
		t.Fatalf("rerun materialize = %d, %v; want idempotent no-op", count, err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: notificationTestTenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("digest deliveries = %+v, %v", page, err)
	}
	work, err := repo.LoadWork(ctx, notificationTestTenant, page.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[notification.EventType]bool{}
	for _, item := range work.Event.DigestItems {
		seen[item.Event.Type] = true
	}
	if work.Event.Type != notification.EventDigest || len(work.Event.DigestItems) != len(types) || len(seen) != len(types) {
		t.Fatalf("mixed digest = type %s, %d members, %d types; want digest with %d distinct types", work.Event.Type, len(work.Event.DigestItems), len(seen), len(types))
	}
}
