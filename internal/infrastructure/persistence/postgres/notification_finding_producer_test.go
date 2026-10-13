package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/jackc/pgx/v5"
)

type failingFindingOutbox struct {
	next *NotificationOutbox
	err  error
}

func (o failingFindingOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return o.err
}

func TestFindingProducerPostgresTransactionAndRecovery(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("finding-events")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),('finding-foreign','Other')`, tenant); err != nil {
		t.Fatal(err)
	}
	eng, err := engagement.New("finding-engagement", "", "Original engagement", "", at)
	if err != nil {
		t.Fatal(err)
	}
	eng.TenantID = tenant
	engagements := NewEngagementRepository(pool)
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	eventRepo := NewNotificationRepository(pool)
	eventRepo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, eventRepo, time.Minute)
	if _, err := source.Poll(ctx, at.Add(-time.Second), 200); err != nil {
		t.Fatal(err)
	}
	repo, retests := NewFindingRepository(pool), NewRetestRepository(pool)
	outbox, runner := NewNotificationOutbox(pool), NewTenantTransactionRunner(pool)
	clock, ids := &notificationTestClock{at}, &notificationTestIDs{}
	service := findingsuc.NewService(repo, nil, retests, NewAuditLog(pool), clock, ids)
	service.SetEngagementTenantResolver(engagements)
	facts := NewNotificationFindingFactsReader(pool)
	injected := errors.New("capture unavailable")
	if err := service.SetNotifications(runner, failingFindingOutbox{outbox, injected}, facts); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, "opaque actor", eng.ID, finding.ManualInput{Title: "Original finding", Severity: shared.SeverityHigh}); !errors.Is(err, injected) {
		t.Fatalf("create rollback: %v", err)
	}
	if got, err := repo.ListByEngagement(ctx, eng.ID); err != nil || len(got) != 0 {
		t.Fatalf("rolled back findings=%v err=%v", got, err)
	}
	if err := service.SetNotifications(runner, outbox, facts); err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(ctx, "opaque actor", eng.ID, finding.ManualInput{Title: "Original finding", Severity: shared.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetNotifications(runner, failingFindingOutbox{outbox, injected}, facts); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.RecordRetest(ctx, eng.ID, created.ID, finding.RetestRemediated, "Fixed", "tester", created.Version); !errors.Is(err, injected) {
		t.Fatalf("retest rollback: %v", err)
	}
	stored, err := repo.GetByEngagementAndID(ctx, eng.ID, created.ID)
	if err != nil || stored.Version != created.Version || stored.Status != finding.StatusOpen {
		t.Fatalf("status escaped rollback: %+v %v", stored, err)
	}
	if got, err := retests.ListByEngagementFinding(ctx, eng.ID, created.ID); err != nil || len(got) != 0 {
		t.Fatalf("retest escaped rollback: %+v %v", got, err)
	}
	if err := service.SetNotifications(runner, outbox, facts); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.RecordRetest(ctx, eng.ID, created.ID, finding.RetestRemediated, "Fixed", "tester", created.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateStatus(shared.WithTenant(ctx, "finding-foreign"), eng.ID, created.ID, finding.StatusOpen, "", "other", created.Version+1); err == nil {
		t.Fatal("foreign tenant mutation succeeded")
	}
	// Change presentation after commit but before projection. The source snapshot wins.
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE findings SET title='Changed finding' WHERE tenant_id=$1 AND id=$2`, tenant, created.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE engagements SET name='Changed engagement' WHERE tenant_id=$1 AND id=$2`, tenant, eng.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, at.Add(time.Minute), 200); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []notification.EventType{notification.EventFindingCreated, notification.EventFindingStatusChanged, notification.EventFindingRetestCompleted} {
		events, err := eventRepo.ListRecentNotificationEvents(ctx, tenant, typ, 10)
		if err != nil || len(events) != 1 {
			t.Fatalf("%s events=%d err=%v", typ, len(events), err)
		}
		assertPublishedEventSchema(t, events[0])
		facts, err := notification.DecodeTemplateContext(events[0].Context)
		if err != nil || facts.Vars["finding_title"] != "Original finding" || facts.Vars["engagement_name"] != "Original engagement" {
			t.Fatalf("mutable context %+v %v", facts, err)
		}
	}
}
