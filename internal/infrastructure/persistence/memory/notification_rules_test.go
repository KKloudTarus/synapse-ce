package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func testRule(id shared.ID, event notification.EventType, channels ...shared.ID) notification.Rule {
	return notification.Rule{
		TenantID: notificationTestTenant, ID: id, Name: "rule " + id.String(), Enabled: true, EventType: event,
		ChannelIDs: channels, Revision: 1, CreatedAt: notificationTestNow, UpdatedAt: notificationTestNow,
	}
}

func mustCreateRule(t *testing.T, repo *NotificationRepository, rule notification.Rule) notification.Rule {
	t.Helper()
	created, err := repo.CreateRule(context.Background(), rule)
	if err != nil {
		t.Fatalf("create rule %s: %v", rule.ID, err)
	}
	return created
}

func TestNotificationRuleLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("ch-2", notification.ChannelWebhook))
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelSlack))

	if _, err := repo.CreateRule(ctx, testRule("rule-x", notification.EventScanCompleted, "ch-missing")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rule to a missing channel err = %v", err)
	}
	created := mustCreateRule(t, repo, testRule("rule-1", notification.EventScanCompleted, "ch-2", "ch-1"))
	if len(created.ChannelIDs) != 2 || created.ChannelIDs[0] != "ch-1" || created.TeamIDs == nil {
		t.Fatalf("created rule = %+v, want sorted channel IDs and empty team IDs", created)
	}

	stale := created
	stale.Revision = 7
	if _, err := repo.UpdateRule(ctx, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale rule update err = %v", err)
	}
	next := created
	next.Revision, next.Name = 2, "renamed"
	if updated, err := repo.UpdateRule(ctx, next); err != nil || updated.Name != "renamed" {
		t.Fatalf("rule update = %+v err=%v", updated, err)
	}
	if err := repo.DeleteRule(ctx, notificationTestTenant, "rule-1", 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale delete err = %v", err)
	}
	if err := repo.DeleteRule(ctx, notificationTestTenant, "rule-1", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetRule(ctx, notificationTestTenant, "rule-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted rule err = %v", err)
	}
}

func TestNotificationRuleAdmissionCap(t *testing.T) {
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelWebhook))
	for i := range maxNotificationRules {
		mustCreateRule(t, repo, testRule(shared.ID(fmt.Sprintf("rule-%03d", i)), notification.EventScanCompleted, "ch-1"))
	}
	if _, err := repo.CreateRule(context.Background(), testRule("rule-over", notification.EventScanCompleted, "ch-1")); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("rule over the cap err = %v", err)
	}
}
