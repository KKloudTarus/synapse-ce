package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
)

func createThreadTestChannel(t *testing.T, repo *NotificationRepository, tenant, id shared.ID, kind notification.ChannelType) notification.Channel {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	channel := notification.Channel{TenantID: tenant, ID: id, Name: "thread test " + id.String(), Type: kind, Enabled: true,
		Destination: "https://example.test/…", Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if kind == notification.ChannelEmail {
		channel.Recipients = []string{"one@example.test", "two@example.test"}
	}
	if _, err := repo.CreateChannel(shared.WithTenant(context.Background(), tenant), channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	return channel
}

func threadTestEvent(tenant shared.ID, source string) notification.Event {
	return notification.Event{TenantID: tenant, ID: shared.ID("event-" + source), Type: notification.EventTest,
		SourceKind: "thread_test", SourceID: source, SchemaVersion: 1, OccurredAt: time.Now().UTC(), Data: json.RawMessage(`{"title":"test"}`), SubjectKind: "finding", SubjectID: "finding-1"}
}

func TestNotificationSubjectAnchorPostgresUsesEarliestDeliveredReference(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("thread-anchor")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	channel := createThreadTestChannel(t, repo, tenant, "thread-channel", notification.ChannelTelegram)
	first, err := repo.PublishToChannel(ctx, threadTestEvent(tenant, "late"), channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.PublishToChannel(ctx, threadTestEvent(tenant, "early"), channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	earliest := time.Now().UTC().Add(-time.Second)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='delivered',delivered_at=$3,remote_ref=$4 WHERE tenant_id=$1 AND id=$2`, tenant, first, earliest.Add(time.Second), "later"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='delivered',delivered_at=$3,remote_ref=$4 WHERE tenant_id=$1 AND id=$2`, tenant, second, earliest, "earliest")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	anchor, err := repo.SubjectAnchor(ctx, tenant, channel.ID, 1, "finding", "finding-1")
	if err != nil || anchor != "earliest" {
		t.Fatalf("anchor=%q err=%v", anchor, err)
	}
	if anchor, err := repo.SubjectAnchor(ctx, tenant, channel.ID, 2, "finding", "finding-1"); err != nil || anchor != "" {
		t.Fatalf("rotated configuration anchor=%q err=%v", anchor, err)
	}
}

func TestPublishToChannelPostgresAdmitsExactlyFiveTestsPerTenantChannelHour(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("test-quota")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	firstRepo, secondRepo := NewNotificationRepository(pool), NewNotificationRepository(pool)
	channel := createThreadTestChannel(t, firstRepo, tenant, "quota-channel", notification.ChannelEmail)

	var accepted int
	var saturated int
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			repo := firstRepo
			if i%2 == 1 {
				repo = secondRepo
			}
			_, err := repo.PublishToChannel(ctx, threadTestEvent(tenant, fmt.Sprintf("quota-%d", i)), channel.ID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				accepted++
			} else if errors.Is(err, shared.ErrSaturated) {
				saturated++
			} else {
				t.Errorf("publish %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if accepted != 5 || saturated != 5 {
		t.Fatalf("accepted=%d saturated=%d, want 5 each", accepted, saturated)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET created_at=now()-interval '1 hour'-interval '1 second' WHERE tenant_id=$1 AND channel_id=$2`, tenant, channel.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := firstRepo.PublishToChannel(ctx, threadTestEvent(tenant, "after-window"), channel.ID); err != nil {
		t.Fatalf("publish after window: %v", err)
	}
	other := createThreadTestChannel(t, firstRepo, tenant, "quota-other", notification.ChannelWebhook)
	if _, err := firstRepo.PublishToChannel(ctx, threadTestEvent(tenant, "other-channel"), other.ID); err != nil {
		t.Fatalf("same tenant other channel: %v", err)
	}
}
