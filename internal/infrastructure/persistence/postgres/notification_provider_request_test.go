package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestProviderRequestReferencePostgresSurvivesRestartAndFencesWrites(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("provider-request")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$2),($3,$4)`, tenant, "Provider request", "provider-request-other", "Other"); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	channel := notification.Channel{TenantID: tenant, ID: "provider-request-channel", Name: "JSM", Type: notification.ChannelJSM, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed-provider-request"); err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "provider-request-event", Type: notification.EventTest, SourceKind: "test", SourceID: "provider-request", SubjectKind: "finding", SubjectID: "finding-1", SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{"title":"test"}`)}
	delivery, err := repo.PublishToChannel(ctx, event, channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	queue := NewJobQueue(pool, &notificationTestIDs{})
	job, err := queue.Claim(ctx, time.Minute, "notification.deliver")
	if err != nil || job == nil {
		t.Fatalf("claim=%+v err=%v", job, err)
	}
	firstAttempt := shared.ID("provider-request-first")
	if _, err = repo.BeginAttempt(ctx, tenant, delivery, job.ID, job.Fence, firstAttempt, now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	next := now.Add(time.Minute)
	if err = repo.FinishAttemptWithProviderRefs(ctx, tenant, delivery, job.ID, job.Fence, firstAttempt, now, "retrying", 404, "jsm_request_unconfirmed", &next, "", "request-create"); err != nil {
		t.Fatal(err)
	}
	work, err := repo.LoadWork(ctx, tenant, delivery)
	if err != nil || work.Delivery.ProviderRequestRef != "request-create" || work.Delivery.RemoteRef != "" || work.Delivery.State != notification.DeliveryRetrying {
		t.Fatalf("work=%+v err=%v", work.Delivery, err)
	}
	encoded, err := json.Marshal(work.Delivery)
	if err != nil || strings.Contains(string(encoded), "provider_request_ref") || strings.Contains(string(encoded), "request-create") {
		t.Fatalf("delivery JSON exposed provider request reference: %s err=%v", encoded, err)
	}
	if anchor, err := repo.SubjectAnchor(ctx, tenant, channel.ID, 1, "finding", "finding-1"); err != nil || anchor != "" {
		t.Fatalf("pending provider request became an anchor: %q err=%v", anchor, err)
	}
	if err = repo.FinishAttemptWithProviderRefs(ctx, tenant, delivery, job.ID, job.Fence+1, firstAttempt, now, "retrying", 404, "late", &next, "", "overwritten"); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale fence=%v", err)
	}
	otherCtx := shared.WithTenant(context.Background(), "provider-request-other")
	if err = repo.FinishAttemptWithProviderRefs(otherCtx, "provider-request-other", delivery, job.ID, job.Fence, firstAttempt, now, "retrying", 404, "cross", &next, "", "overwritten"); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("cross-tenant write=%v", err)
	}
	if got, err := repo.GetDelivery(ctx, tenant, delivery); err != nil || got.ProviderRequestRef != "request-create" {
		t.Fatalf("fenced reference changed: %+v err=%v", got, err)
	}
	if err = queue.Fail(ctx, job.ID, job.Fence, 0); err != nil {
		t.Fatal(err)
	}
	secondJob, err := queue.Claim(ctx, time.Minute, "notification.deliver")
	if err != nil || secondJob == nil {
		t.Fatalf("retry claim=%+v err=%v", secondJob, err)
	}
	secondAttempt := shared.ID("provider-request-second")
	if _, err = repo.BeginAttempt(ctx, tenant, delivery, secondJob.ID, secondJob.Fence, secondAttempt, now.Add(time.Second), ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	if err = repo.FinishAttemptWithProviderRefs(ctx, tenant, delivery, secondJob.ID, secondJob.Fence, secondAttempt, now.Add(time.Second), "delivered", 202, "", nil, "alert-alias", ""); err != nil {
		t.Fatal(err)
	}
	confirmed, err := repo.GetDelivery(ctx, tenant, delivery)
	if err != nil || confirmed.ProviderRequestRef != "" || confirmed.RemoteRef != "alert-alias" || confirmed.State != notification.DeliverySucceeded {
		t.Fatalf("confirmed=%+v err=%v", confirmed, err)
	}
	if anchor, err := repo.SubjectAnchor(ctx, tenant, channel.ID, 1, "finding", "finding-1"); err != nil || anchor != "alert-alias" {
		t.Fatalf("confirmed anchor=%q err=%v", anchor, err)
	}
}
