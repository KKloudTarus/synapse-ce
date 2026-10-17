package memory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestDigestMaterializationIsBoundedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	now := notificationTestNow
	repo := NewNotificationRepository(nil, func() time.Time { return now })
	channel := testChannel("digest-channel", notification.ChannelWebhook)
	mustCreateChannel(t, repo, channel)
	rule := testRule("digest-rule", notification.EventScanCompleted, channel.ID)
	rule.Cadence = notification.CadenceHourly
	mustCreateRule(t, repo, rule)

	event := testEvent("digest-source", notification.EventScanCompleted)
	event.Context = json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-01-01T00:00:00Z","title":"scan"}}`)
	if ids, err := repo.Publish(ctx, event); err != nil || len(ids) != 0 {
		t.Fatalf("digest source deliveries=%v err=%v, want none before close", ids, err)
	}
	if count, err := repo.materializeDigests(ctx, notificationTestTenant, now.Add(time.Hour), 10); err != nil || count != 1 {
		t.Fatalf("materialize=%d err=%v", count, err)
	}
	if count, err := repo.materializeDigests(ctx, notificationTestTenant, now.Add(2*time.Hour), 10); err != nil || count != 0 {
		t.Fatalf("rerun materialize=%d err=%v, want idempotent no-op", count, err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: notificationTestTenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("digest deliveries=%+v err=%v", page, err)
	}
	work, err := repo.LoadWork(ctx, notificationTestTenant, page.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if work.Event.Type != notification.EventDigest || len(work.Event.DigestItems) != 1 || work.DigestPolicy == "" {
		t.Fatalf("digest work=%+v", work)
	}
	if err := repo.admitDigestPolicy(notificationTestTenant, page.Items[0], ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing digest witness=%v, want validation refusal", err)
	}
}

func TestDigestCriticalEventBypassesCadence(t *testing.T) {
	repo := newTestNotificationRepository()
	channel := testChannel("critical-channel", notification.ChannelWebhook)
	mustCreateChannel(t, repo, channel)
	rule := testRule("critical-rule", notification.EventFindingCreated, channel.ID)
	rule.Cadence = notification.CadenceDaily
	mustCreateRule(t, repo, rule)
	event := notification.Event{TenantID: notificationTestTenant, ID: "critical-event", Type: notification.EventFindingCreated, SourceKind: "finding", SourceID: "critical-event", Severity: shared.SeverityCritical, SchemaVersion: 1, OccurredAt: notificationTestNow, Data: json.RawMessage(`{"finding_id":"f"}`)}
	if ids, err := repo.Publish(context.Background(), event); err != nil || len(ids) != 1 {
		t.Fatalf("critical delivery=%v err=%v, want immediate delivery", ids, err)
	}
}

func TestDigestLoadWorkRemovesSuppressedRawReferences(t *testing.T) {
	ctx := context.Background()
	now := notificationTestNow
	repo := NewNotificationRepository(nil, func() time.Time { return now })
	repo.AddEngagement(notificationTestTenant, "digest-engagement")
	channel := testChannel("digest-raw-channel", notification.ChannelWebhook)
	mustCreateChannel(t, repo, channel)
	rule := testRule("digest-raw-rule", notification.EventScanCompleted, channel.ID)
	rule.Cadence = notification.CadenceHourly
	mustCreateRule(t, repo, rule)
	event := testEvent("digest-raw-source", notification.EventScanCompleted)
	event.EngagementID = "digest-engagement"
	event.Context = json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-01-01T00:00:00Z","title":"scan"}}`)
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if count, err := repo.materializeDigests(ctx, notificationTestTenant, now.Add(time.Hour), 10); err != nil || count != 1 {
		t.Fatalf("materialize=%d err=%v", count, err)
	}
	updatedAt := now.Add(time.Minute)
	if _, err := repo.PutEngagementNotificationSetting(ctx, notification.EngagementNotificationSetting{
		TenantID: notificationTestTenant, EngagementID: event.EngagementID,
		ExternalNotifications: notification.EngagementNotificationsNone, Revision: 1,
		UpdatedAt: &updatedAt, UpdatedBy: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: notificationTestTenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("deliveries=%+v err=%v", page, err)
	}
	work, err := repo.LoadWork(ctx, notificationTestTenant, page.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var data notification.DigestData
	if err := json.Unmarshal(work.Event.Data, &data); err != nil {
		t.Fatal(err)
	}
	if work.Engagement != notification.EngagementNotificationsNone || data.TotalCount != 0 || len(data.EventIDs) != 0 {
		t.Fatalf("suppressed digest work leaks references: engagement=%s data=%+v", work.Engagement, data)
	}
}

func TestDigestChannelTransitionsSuppressBacklogAndResumeInFreshChunk(t *testing.T) {
	ctx := context.Background()
	now := notificationTestNow
	repo := NewNotificationRepository(nil, func() time.Time { return now })
	channel := mustCreateChannel(t, repo, testChannel("digest-transition-channel", notification.ChannelWebhook))
	rule := testRule("digest-transition-rule", notification.EventScanCompleted, channel.ID)
	rule.Cadence = notification.CadenceHourly
	mustCreateRule(t, repo, rule)
	publish := func(source string) {
		event := testEvent(source, notification.EventScanCompleted)
		event.Context = json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-01-01T00:00:00Z","title":"scan"}}`)
		if ids, err := repo.Publish(ctx, event); err != nil || len(ids) != 0 {
			t.Fatalf("publish %s ids=%v err=%v", source, ids, err)
		}
	}
	publish("digest-transition-before-disable")

	channel.Enabled, channel.Revision, channel.UpdatedAt = false, 2, now.Add(time.Minute)
	if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
		t.Fatal(err)
	}
	publish("digest-transition-while-disabled")
	channel.Enabled, channel.Revision, channel.UpdatedAt = true, 3, now.Add(2*time.Minute)
	if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
		t.Fatal(err)
	}
	publish("digest-transition-after-enable")

	channel.Revision, channel.UpdatedAt = 4, now.Add(3*time.Minute)
	if _, err := repo.UpdateChannel(ctx, channel, "replacement-secret", true); err != nil {
		t.Fatal(err)
	}
	publish("digest-transition-after-replacement")
	if _, err := repo.RecordChannelOutcome(ctx, notificationTestTenant, ports.NotificationChannelOutcome{
		ChannelID: channel.ID, DeliveryID: "transition-delivery", AttemptID: "transition-attempt",
		Class: notification.AttemptPermanent, Code: "destination_blocked", At: now.Add(4 * time.Minute), Threshold: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ResumeChannel(ctx, notificationTestTenant, channel.ID, 4, "admin", now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	publish("digest-transition-after-resume")

	var pending []memoryDigestKey
	for key := range repo.digestMembers {
		if key.channel == channel.ID {
			if window, finalized := repo.digestWindows[key]; !finalized || window.outcome == "pending" {
				pending = append(pending, key)
			}
		}
	}
	if len(pending) != 1 || pending[0].chunk != 3 {
		t.Fatalf("pending digest chunks=%+v, want only fresh chunk 3", pending)
	}
	if count, err := repo.materializeDigests(ctx, notificationTestTenant, now.Add(time.Hour), 10); err != nil || count != 1 {
		t.Fatalf("materialize count=%d err=%v", count, err)
	}
}

func TestDigestHistorySurvivesRuleDeletion(t *testing.T) {
	ctx := context.Background()
	now := notificationTestNow
	repo := NewNotificationRepository(nil, func() time.Time { return now })
	channel := mustCreateChannel(t, repo, testChannel("digest-history-channel", notification.ChannelWebhook))
	rule := testRule("digest-history-rule", notification.EventScanCompleted, channel.ID)
	rule.Cadence = notification.CadenceHourly
	mustCreateRule(t, repo, rule)
	event := testEvent("digest-history-source", notification.EventScanCompleted)
	event.Context = json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-01-01T00:00:00Z","title":"scan"}}`)
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if count, err := repo.materializeDigests(ctx, notificationTestTenant, now.Add(time.Hour), 10); err != nil || count != 1 {
		t.Fatalf("materialize count=%d err=%v", count, err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: notificationTestTenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("deliveries=%+v err=%v", page, err)
	}
	if err := repo.DeleteRule(ctx, notificationTestTenant, rule.ID, rule.Revision); err != nil {
		t.Fatal(err)
	}
	if work, err := repo.LoadWork(ctx, notificationTestTenant, page.Items[0].ID); err != nil || len(work.Event.DigestItems) != 1 {
		t.Fatalf("work=%+v err=%v", work, err)
	}
	if got, err := repo.GetNotificationEvent(ctx, notificationTestTenant, page.Items[0].EventID); err != nil || len(got.DigestItems) != 1 {
		t.Fatalf("event=%+v err=%v", got, err)
	}
	if recent, err := repo.ListRecentNotificationEvents(ctx, notificationTestTenant, notification.EventDigest, 1); err != nil || len(recent) != 1 || len(recent[0].DigestItems) != 0 {
		t.Fatalf("recent=%+v err=%v", recent, err)
	}
}
