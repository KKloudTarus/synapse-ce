package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func publishedDelivery(t *testing.T, repo *NotificationRepository) shared.ID {
	t.Helper()
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelWebhook))
	mustCreateRule(t, repo, testRule("rule-1", notification.EventScanCompleted, "ch-1"))
	ids, err := repo.Publish(context.Background(), testEvent("scan-1", notification.EventScanCompleted))
	if err != nil || len(ids) != 1 {
		t.Fatalf("publish: %v %v", ids, err)
	}
	return ids[0]
}

func TestDeliveryAttemptStateMachine(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	delivery := publishedDelivery(t, repo)
	retryAt := notificationTestNow.Add(time.Minute)

	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-1", notificationTestNow, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.FinishAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-1", notificationTestNow, "retrying", 503, "http_503", &retryAt); err != nil {
		t.Fatal(err)
	}
	if err := repo.FinishAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-1", notificationTestNow, "delivered", 200, "", nil); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("finishing a finished attempt err = %v", err)
	}
	second, err := repo.BeginAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-2", retryAt, "")
	if err != nil || second.Number != 2 {
		t.Fatalf("second attempt = %+v err=%v", second, err)
	}
	if err := repo.FinishAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-2", retryAt, "delivered", 200, "", nil); err != nil {
		t.Fatal(err)
	}
	d, _ := repo.GetDelivery(ctx, notificationTestTenant, delivery)
	if d.State != notification.DeliverySucceeded || d.Attempts != 2 || d.LastError != "" || d.DeliveredAt == nil || d.NextAttemptAt != nil {
		t.Fatalf("delivered state = %+v", d)
	}
	attempts, err := repo.ListAttempts(ctx, notificationTestTenant, delivery)
	if err != nil || len(attempts) != 2 || attempts[0].Outcome != "retrying" || attempts[0].ErrorCode != "http_503" || attempts[1].Outcome != "delivered" {
		t.Fatalf("attempts = %+v err=%v", attempts, err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-3", retryAt.Add(time.Minute), ""); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("attempt on a delivered delivery err = %v", err)
	}
	if err := repo.FinishAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-2", retryAt, "bogus", 0, "", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid outcome err = %v", err)
	}
}

func TestDeadLetterReportsOnlyTheFirstTransition(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	delivery := publishedDelivery(t, repo)
	if changed, err := repo.DeadLetterDelivery(ctx, notificationTestTenant, delivery, 1, "worker_dead_letter"); err != nil || !changed {
		t.Fatalf("first dead letter = %v err=%v", changed, err)
	}
	if changed, _ := repo.DeadLetterDelivery(ctx, notificationTestTenant, delivery, 1, "worker_dead_letter"); changed {
		t.Fatal("second dead letter reported a transition")
	}
	if err := repo.CancelDelivery(ctx, notificationTestTenant, delivery, "job", 1, "late_cancel"); err != nil {
		t.Fatal(err)
	}
	if d, _ := repo.GetDelivery(ctx, notificationTestTenant, delivery); d.State != notification.DeliveryDead || d.LastError != "worker_dead_letter" {
		t.Fatalf("terminal delivery changed: %+v", d)
	}
}

func TestRedrivePreservesHistoryAndFencesOldCallbacks(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	jobs := NewJobQueue(idgen.RandomID{}, func() time.Time { return notificationTestNow })
	repo := NewNotificationRepository(jobs, func() time.Time { return notificationTestNow })
	id := publishedDelivery(t, repo)
	job, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim: %v %v", job, err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, id, job.ID, job.Fence, "attempt", notificationTestNow, "tenant:tpl@1"); err != nil {
		t.Fatal(err)
	}
	if err := repo.FinishAttempt(ctx, notificationTestTenant, id, job.ID, job.Fence, "attempt", notificationTestNow, "failed", 503, "http_503", nil); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	d, err := repo.GetDelivery(ctx, notificationTestTenant, id)
	if err != nil || d.RedriveFence != job.Fence {
		t.Fatalf("delivery fence: %+v %v", d, err)
	}
	if _, _, err := repo.RedriveDelivery(ctx, "other-tenant", id, job.Fence); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	d, _, err = repo.RedriveDelivery(ctx, notificationTestTenant, id, job.Fence)
	// Redrive releases the template pin so the next attempt resolves again (#1365).
	if err != nil || d.State != notification.DeliveryPending || d.Attempts != 1 || d.RedriveFence != job.Fence+1 || d.TemplateRef != "" {
		t.Fatalf("redrive: %+v %v", d, err)
	}
	if _, _, err := repo.RedriveDelivery(ctx, notificationTestTenant, id, job.Fence); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale redrive: %v", err)
	}
	if changed, err := repo.DeadLetterDelivery(ctx, notificationTestTenant, id, job.Fence, "late"); err != nil || changed {
		t.Fatalf("old callback: %v %v", changed, err)
	}
	next, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || next == nil || next.Attempts != 1 || next.Fence <= job.Fence {
		t.Fatalf("fresh retry budget: %+v %v", next, err)
	}
	if err := jobs.Deadletter(ctx, next.ID, next.Fence); err != nil {
		t.Fatal(err)
	}
	if changed, err := repo.DeadLetterDelivery(ctx, notificationTestTenant, id, job.Fence, "late"); err != nil || changed {
		t.Fatalf("old callback after new failure: %v %v", changed, err)
	}
	if changed, err := repo.DeadLetterDelivery(ctx, notificationTestTenant, id, next.Fence, "current"); err != nil || !changed {
		t.Fatalf("current callback: %v %v", changed, err)
	}
	attempts, err := repo.ListAttempts(ctx, notificationTestTenant, id)
	if err != nil || len(attempts) != 1 || attempts[0].ErrorCode != "http_503" || attempts[0].TemplateRef != "tenant:tpl@1" {
		t.Fatalf("history: %+v %v", attempts, err)
	}
}

func TestDisablingAChannelCancelsIdleDeliveries(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	delivery := publishedDelivery(t, repo)
	channel, _ := repo.GetChannel(ctx, notificationTestTenant, "ch-1")
	channel.Enabled, channel.Revision = false, 2
	if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
		t.Fatal(err)
	}
	if d, _ := repo.GetDelivery(ctx, notificationTestTenant, delivery); d.State != notification.DeliveryCancelled || d.LastError != "channel_disabled" {
		t.Fatalf("delivery after disabling its channel = %+v", d)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, delivery, "job", 1, "att-1", notificationTestNow, ""); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("attempt on a disabled channel err = %v", err)
	}
}

func TestAttemptTransitionsAreFencedByTheJobClaim(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), notificationTestTenant)
	now := notificationTestNow
	clock := func() time.Time { return now }
	jobs := NewJobQueue(idgen.RandomID{}, clock)
	repo := NewNotificationRepository(jobs, clock)
	delivery := publishedDelivery(t, repo)
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, delivery, "unclaimed", 1, "att-0", now, ""); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("attempt without a claim err = %v", err)
	}
	job, err := jobs.Claim(ctx, time.Minute, notificationDeliverJobKey)
	if err != nil || job == nil {
		t.Fatalf("claim = %v err=%v", job, err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, delivery, job.ID, job.Fence+1, "att-0", now, ""); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("attempt with a stale fence err = %v", err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, delivery, job.ID, job.Fence, "att-1", now, ""); err != nil {
		t.Fatalf("attempt with the live claim: %v", err)
	}
	now = now.Add(2 * time.Minute) // the lease expired
	if err := repo.FinishAttempt(ctx, notificationTestTenant, delivery, job.ID, job.Fence, "att-1", now, "delivered", 200, "", nil); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("finish after the lease expired err = %v", err)
	}
	if changed, _ := repo.DeadLetterDelivery(ctx, notificationTestTenant, delivery, 1, "worker_dead_letter"); changed {
		t.Fatal("dead-lettered a delivery whose job has not failed")
	}
}

func TestBeginAttemptAppliesTheDeliveryRateLimits(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelWebhook))
	mustCreateChannel(t, repo, testChannel("ch-2", notification.ChannelWebhook))
	mustCreateRule(t, repo, testRule("rule-1", notification.EventScanCompleted, "ch-1", "ch-2"))
	ids, err := repo.Publish(ctx, testEvent("scan-1", notification.EventScanCompleted))
	if err != nil || len(ids) != 2 {
		t.Fatalf("publish = %v err=%v", ids, err)
	}
	first, second := ids[0], ids[1]
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, first, "job", 1, "att-1", notificationTestNow, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, second, "job", 1, "att-2", notificationTestNow.Add(50*time.Millisecond), ""); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("attempt inside the tenant interval err = %v", err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, second, "job", 1, "att-2", notificationTestNow.Add(200*time.Millisecond), ""); err != nil {
		t.Fatalf("attempt on another channel after the tenant interval: %v", err)
	}
	if err := repo.FinishAttempt(ctx, notificationTestTenant, first, "job", 1, "att-1", notificationTestNow, "retrying", 503, "http_503", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BeginAttempt(ctx, notificationTestTenant, first, "job", 1, "att-3", notificationTestNow.Add(500*time.Millisecond), ""); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("attempt inside the channel interval err = %v", err)
	}
}

func TestLoadWorkUsesTheChannelVersionPinnedAtProjection(t *testing.T) {
	ctx := context.Background()
	repo := newTestNotificationRepository()
	delivery := publishedDelivery(t, repo)
	channel, _ := repo.GetChannel(ctx, notificationTestTenant, "ch-1")
	channel.Revision = 2
	if _, err := repo.UpdateChannel(ctx, channel, "sealed-ch-1-2", true); err != nil {
		t.Fatal(err)
	}
	work, err := repo.LoadWork(ctx, notificationTestTenant, delivery)
	if err != nil || work.Sealed != "sealed-ch-1-1" || work.Channel.SecretVersion != 1 || work.Event.SourceID != "scan-1" {
		t.Fatalf("work = %+v err=%v, want the version sealed when the delivery was created", work, err)
	}
	if _, err := repo.LoadWork(ctx, notificationTestTenant, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing delivery err = %v", err)
	}
}

func TestListDeliveriesPagesNewestFirst(t *testing.T) {
	ctx := context.Background()
	now := notificationTestNow
	repo := NewNotificationRepository(nil, func() time.Time { return now })
	mustCreateChannel(t, repo, testChannel("ch-1", notification.ChannelWebhook))
	mustCreateRule(t, repo, testRule("rule-1", notification.EventScanCompleted, "ch-1"))
	for i := range 5 {
		now = notificationTestNow.Add(time.Duration(i) * time.Second)
		if _, err := repo.Publish(ctx, testEvent(fmt.Sprintf("scan-%d", i), notification.EventScanCompleted)); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: notificationTestTenant, Limit: 2})
	if len(first.Items) != 2 || first.Next == "" || !first.Items[0].CreatedAt.After(first.Items[1].CreatedAt) {
		t.Fatalf("first page = %+v", first)
	}
	last := first.Items[1]
	rest, _ := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: notificationTestTenant, Limit: 10, Before: last.CreatedAt, BeforeID: last.ID})
	if len(rest.Items) != 3 || rest.Next != "" {
		t.Fatalf("second page = %+v", rest)
	}
	filtered, _ := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: notificationTestTenant, EventType: notification.EventQualityGateFailed})
	if len(filtered.Items) != 0 {
		t.Fatalf("event type filter kept %d deliveries", len(filtered.Items))
	}
}
