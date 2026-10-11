package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var notificationTestNow = time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)

const notificationTestTenant shared.ID = "tenant-notify"

func newTestNotificationRepository() *NotificationRepository {
	return NewNotificationRepository(nil, func() time.Time { return notificationTestNow })
}

func testChannel(id shared.ID, kind notification.ChannelType, recipients ...string) notification.Channel {
	return notification.Channel{
		TenantID: notificationTestTenant, ID: id, Name: "channel " + id.String(), Type: kind, Enabled: true,
		Destination: "https://hooks.example/…", Recipients: recipients, Revision: 1, SecretVersion: 1,
		CreatedAt: notificationTestNow, UpdatedAt: notificationTestNow,
	}
}

func mustCreateChannel(t *testing.T, repo *NotificationRepository, c notification.Channel) notification.Channel {
	t.Helper()
	created, err := repo.CreateChannel(context.Background(), c, "sealed-"+c.ID.String()+"-1")
	if err != nil {
		t.Fatalf("create channel %s: %v", c.ID, err)
	}
	return created
}

func TestNotificationChannelLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	created := mustCreateChannel(t, repo, testChannel("ch-b", notification.ChannelSlack))
	mustCreateChannel(t, repo, testChannel("ch-a", notification.ChannelWebhook))
	if created.Recipients == nil {
		t.Fatal("created channel has nil recipients")
	}
	if list, _ := repo.ListChannels(ctx, notificationTestTenant); len(list) != 2 || list[0].ID != "ch-a" {
		t.Fatalf("channels = %+v, want ordered by name", list)
	}

	stale := created
	stale.Revision = 5
	if _, err := repo.UpdateChannel(ctx, stale, "", false); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update err = %v", err)
	}
	next := created
	next.Revision = 2
	updated, err := repo.UpdateChannel(ctx, next, "sealed-ch-b-2", true)
	if err != nil || updated.SecretVersion != 2 {
		t.Fatalf("replace secret: %+v err=%v", updated, err)
	}
	next.Revision = 3
	if kept, _ := repo.UpdateChannel(ctx, next, "", false); kept.SecretVersion != 2 {
		t.Fatalf("update without replace changed secret version to %d", kept.SecretVersion)
	}

	if err := repo.DeleteChannel(ctx, notificationTestTenant, "ch-b", 3, notificationTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetChannel(ctx, notificationTestTenant, "ch-b"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted channel err = %v", err)
	}
	if err := repo.DeleteChannel(ctx, notificationTestTenant, "ch-b", 4, notificationTestNow); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second delete err = %v", err)
	}
	if _, err := repo.GetChannel(ctx, "other-tenant", "ch-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read err = %v", err)
	}
}

func TestNotificationChannelAdmissionCap(t *testing.T) {
	repo := newTestNotificationRepository()
	for i := range maxNotificationChannels {
		mustCreateChannel(t, repo, testChannel(shared.ID(fmt.Sprintf("ch-%02d", i)), notification.ChannelWebhook))
	}
	if _, err := repo.CreateChannel(context.Background(), testChannel("ch-over", notification.ChannelWebhook), "sealed"); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("channel over the cap err = %v", err)
	}
	if err := repo.DeleteChannel(context.Background(), notificationTestTenant, "ch-00", 1, notificationTestNow); err != nil {
		t.Fatal(err)
	}
	mustCreateChannel(t, repo, testChannel("ch-over", notification.ChannelWebhook))
}
