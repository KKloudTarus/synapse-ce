package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	engagementdomain "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	engagementuc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

type failingEngagementProducerOutbox struct {
	next *NotificationOutbox
	err  error
}

func (o failingEngagementProducerOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return o.err
}

func TestEngagementProducerPostgresTransactionAndImmutableSnapshot(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("engagement-events")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$1),('engagement-events-foreign','Other')", tenant); err != nil {
		t.Fatal(err)
	}

	eventRepo := NewNotificationRepository(pool)
	eventRepo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, eventRepo, time.Minute)
	if _, err := source.Poll(ctx, at.Add(-time.Second), 200); err != nil {
		t.Fatal(err)
	}
	repo, outbox, runner := NewEngagementRepository(pool), NewNotificationOutbox(pool), NewTenantTransactionRunner(pool)
	service := engagementuc.NewService(repo, &notificationTestClock{at}, &notificationTestIDs{}, NewAuditLog(pool))
	facts := NewNotificationLifecycleFactsReader(pool)
	injected := errors.New("capture unavailable")
	if err := service.SetNotifications(runner, failingEngagementProducerOutbox{next: outbox, err: injected}, facts); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, engagementuc.CreateInput{TenantID: tenant, Name: "Original engagement", CreatedBy: "opaque actor", Timezone: "UTC"}); !errors.Is(err, injected) {
		t.Fatalf("create rollback = %v", err)
	}
	if engagements, err := repo.List(ctx, tenant); err != nil || len(engagements) != 0 {
		t.Fatalf("rolled back engagements=%+v err=%v", engagements, err)
	}

	if err := service.SetNotifications(runner, outbox, facts); err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(ctx, engagementuc.CreateInput{TenantID: tenant, Name: "Original engagement", CreatedBy: "opaque actor", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetNotifications(runner, failingEngagementProducerOutbox{next: outbox, err: injected}, facts); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transition(ctx, "opaque actor", tenant, created.ID, engagementdomain.StatusActive); !errors.Is(err, injected) {
		t.Fatalf("transition rollback = %v", err)
	}
	stored, err := repo.GetByIDInTenant(ctx, tenant, created.ID)
	if err != nil || stored.Status != engagementdomain.StatusDraft {
		t.Fatalf("status escaped rollback: %+v %v", stored, err)
	}
	if err := service.SetNotifications(runner, outbox, facts); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transition(ctx, "opaque actor", tenant, created.ID, engagementdomain.StatusActive); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE engagements SET name='Changed engagement' WHERE tenant_id=$1 AND id=$2", tenant, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, at.Add(time.Minute), 200); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []notification.EventType{notification.EventEngagementCreated, notification.EventEngagementStatusChanged} {
		events, err := eventRepo.ListRecentNotificationEvents(ctx, tenant, typ, 10)
		if err != nil || len(events) != 1 {
			t.Fatalf("%s events=%d err=%v", typ, len(events), err)
		}
		assertPublishedEventSchema(t, events[0])
		context, err := notification.DecodeTemplateContext(events[0].Context)
		if err != nil || context.Vars["engagement_name"] != "Original engagement" || context.Vars["event_type"] != string(typ) {
			t.Fatalf("%s immutable context=%+v err=%v", typ, context, err)
		}
	}
}
