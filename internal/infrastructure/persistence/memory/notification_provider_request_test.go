package memory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestProviderRequestReferenceMemoryIsFencedPrivateAndNeverAnAnchor(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	now := notificationTestNow
	jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
	repo := NewNotificationRepository(jobs, func() time.Time { return now })
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelJSM))
	event := testEvent("provider-request", notification.EventTest)
	event.SubjectKind, event.SubjectID = "finding", "finding-1"
	delivery, err := repo.PublishToChannel(ctx, event, "ch-1")
	if err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim=%+v err=%v", job, err)
	}
	firstAttempt := shared.ID("provider-request-first")
	if _, err = repo.BeginAttempt(ctx, notificationTestTenant, delivery, job.ID, job.Fence, firstAttempt, now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	next := now.Add(time.Minute)
	if err = repo.FinishAttemptWithProviderRefs(ctx, notificationTestTenant, delivery, job.ID, job.Fence, firstAttempt, now, "retrying", 404, "jsm_request_unconfirmed", &next, "", "request-create"); err != nil {
		t.Fatal(err)
	}
	work, err := repo.LoadWork(ctx, notificationTestTenant, delivery)
	if err != nil || work.Delivery.ProviderRequestRef != "request-create" || work.Delivery.RemoteRef != "" || work.Delivery.State != notification.DeliveryRetrying {
		t.Fatalf("work=%+v err=%v", work.Delivery, err)
	}
	encoded, err := json.Marshal(work.Delivery)
	if err != nil || strings.Contains(string(encoded), "provider_request_ref") || strings.Contains(string(encoded), "request-create") {
		t.Fatalf("delivery JSON exposed provider request reference: %s err=%v", encoded, err)
	}
	if anchor, err := repo.SubjectAnchor(ctx, notificationTestTenant, "ch-1", 1, "finding", "finding-1"); err != nil || anchor != "" {
		t.Fatalf("pending provider request became an anchor: %q err=%v", anchor, err)
	}
	if err = repo.FinishAttemptWithProviderRefs(ctx, notificationTestTenant, delivery, job.ID, job.Fence+1, firstAttempt, now, "retrying", 404, "late", &next, "", "overwritten"); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale fence=%v", err)
	}
	if err = repo.FinishAttemptWithProviderRefs(ctx, "other-tenant", delivery, job.ID, job.Fence, firstAttempt, now, "retrying", 404, "cross", &next, "", "overwritten"); err == nil {
		t.Fatal("cross-tenant write succeeded")
	}
	if got, err := repo.GetDelivery(ctx, notificationTestTenant, delivery); err != nil || got.ProviderRequestRef != "request-create" {
		t.Fatalf("fenced reference changed: %+v err=%v", got, err)
	}
	if err = jobs.Fail(ctx, job.ID, job.Fence, 0); err != nil {
		t.Fatal(err)
	}
	secondJob, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || secondJob == nil {
		t.Fatalf("retry claim=%+v err=%v", secondJob, err)
	}
	secondAttempt := shared.ID("provider-request-second")
	if _, err = repo.BeginAttempt(ctx, notificationTestTenant, delivery, secondJob.ID, secondJob.Fence, secondAttempt, now.Add(time.Second), ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	if err = repo.FinishAttemptWithProviderRefs(ctx, notificationTestTenant, delivery, secondJob.ID, secondJob.Fence, secondAttempt, now.Add(time.Second), "delivered", 202, "", nil, "alert-alias", ""); err != nil {
		t.Fatal(err)
	}
	confirmed, err := repo.GetDelivery(ctx, notificationTestTenant, delivery)
	if err != nil || confirmed.ProviderRequestRef != "" || confirmed.RemoteRef != "alert-alias" || confirmed.State != notification.DeliverySucceeded {
		t.Fatalf("confirmed=%+v err=%v", confirmed, err)
	}
	if anchor, err := repo.SubjectAnchor(ctx, notificationTestTenant, "ch-1", 1, "finding", "finding-1"); err != nil || anchor != "alert-alias" {
		t.Fatalf("confirmed anchor=%q err=%v", anchor, err)
	}
}

func TestProviderRequestReferenceMemorySurvivesTerminalFailureAndRedrive(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	now := notificationTestNow
	jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return now })
	repo := NewNotificationRepository(jobs, func() time.Time { return now })
	mustCreateChannel(t, repo, testChannel("ch-redrive", notification.ChannelJSM))
	delivery, err := repo.PublishToChannel(ctx, testEvent("provider-request-redrive", notification.EventTest), "ch-redrive")
	if err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim=%+v err=%v", job, err)
	}
	if _, err = repo.BeginAttempt(ctx, notificationTestTenant, delivery, job.ID, job.Fence, "provider-request-terminal", now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}
	if err = repo.FinishAttemptWithProviderRefs(ctx, notificationTestTenant, delivery, job.ID, job.Fence, "provider-request-terminal", now, "failed", 401, "http_401", nil, "", "request-create"); err != nil {
		t.Fatal(err)
	}
	if err = jobs.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	dead, err := repo.GetDelivery(ctx, notificationTestTenant, delivery)
	if err != nil || dead.State != notification.DeliveryDead || dead.ProviderRequestRef != "request-create" {
		t.Fatalf("dead=%+v err=%v", dead, err)
	}
	redriven, _, err := repo.RedriveDelivery(ctx, notificationTestTenant, delivery, dead.RedriveFence)
	if err != nil || redriven.State != notification.DeliveryPending || redriven.ProviderRequestRef != "request-create" {
		t.Fatalf("redrive=%+v err=%v", redriven, err)
	}
	work, err := repo.LoadWork(ctx, notificationTestTenant, delivery)
	if err != nil || work.Delivery.ProviderRequestRef != "request-create" {
		t.Fatalf("work=%+v err=%v", work.Delivery, err)
	}
}
