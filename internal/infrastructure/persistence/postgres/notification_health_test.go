package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestNotificationChannelAutoPauseEndToEnd drives the real worker path (service, Postgres
// repository, job queue and one tenant transaction per finished attempt) through the channel
// health state machine of #1464.
func TestNotificationChannelAutoPauseEndToEnd(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("health")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('health','Health'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('ada','Ada','admin','hash-ada','health',false),
		('bob','Bob','member','hash-bob','health',false)`)
	personalExec(t, ctx, pool, "other", `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('eve','Eve','admin','hash-eve','other',false)`)

	repo := NewNotificationRepository(pool)
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	clock := &notificationTestClock{now}
	ids := &notificationTestIDs{}
	sender := &notificationTestSender{result: ports.NotificationSendResult{ErrorCode: "destination_blocked"}}
	svc, err := notificationuc.NewService(repo, cipher, sender, NewAuditLog(pool), clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
	if err := svc.SetPauseThreshold(3); err != nil {
		t.Fatal(err)
	}
	channel, err := svc.CreateChannel(ctx, "ada", notificationuc.ChannelInput{Name: "Ops hook", Type: notification.ChannelWebhook, Enabled: true, URL: "https://hooks.example.com/secret-path?token=hidden", Secret: "1234567890abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if channel.Health.State != notification.ChannelActive || channel.Health.ConsecutiveFailures != 0 {
		t.Fatalf("new channel health = %+v", channel.Health)
	}
	queue := NewJobQueue(pool, ids)
	seq := 0
	publish := func() shared.ID {
		t.Helper()
		seq++
		source := fmt.Sprintf("health-%d", seq)
		id, err := repo.PublishToChannel(ctx, notification.Event{TenantID: tenant, ID: shared.ID(source), Type: notification.EventTest, SourceKind: "test", SourceID: source, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{"title":"test"}`)}, channel.ID)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	claim := func() *ports.QueuedJob {
		t.Helper()
		job, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
		if err != nil || job == nil {
			t.Fatalf("claim: %v %v", job, err)
		}
		return job
	}
	attempt := func(job *ports.QueuedJob) error {
		t.Helper()
		clock.at = clock.at.Add(2 * time.Second) // clear the per-channel rate limit without sleeping
		err := svc.HandleJob(ctx, *job)
		var directive *notificationuc.DeliveryError
		if errors.As(err, &directive) {
			// Retries are not replayed here: each step of the test is one attempt on a new delivery.
			if dlErr := queue.Deadletter(ctx, job.ID, job.Fence); dlErr != nil {
				t.Fatal(dlErr)
			}
		} else if err == nil {
			if cErr := queue.Complete(ctx, job.ID, job.Fence); cErr != nil {
				t.Fatal(cErr)
			}
		} else if fErr := queue.Fail(ctx, job.ID, job.Fence, 0); fErr != nil {
			t.Fatal(fErr)
		}
		return err
	}
	health := func() notification.ChannelHealth {
		t.Helper()
		c, err := repo.GetChannel(ctx, tenant, channel.ID)
		if err != nil {
			t.Fatal(err)
		}
		return c.Health
	}

	// Two permanent failures, then a retryable one that neither counts nor resets.
	publish()
	_ = attempt(claim())
	publish()
	_ = attempt(claim())
	if h := health(); h.ConsecutiveFailures != 2 || h.LastFailureCode != "destination_blocked" || h.Paused() {
		t.Fatalf("after two permanent failures: %+v", h)
	}
	sender.result = ports.NotificationSendResult{StatusCode: 503, ErrorCode: "http_503", Retryable: true}
	publish()
	_ = attempt(claim())
	if h := health(); h.ConsecutiveFailures != 2 || h.Paused() {
		t.Fatalf("a retryable 503 changed the count: %+v", h)
	}

	// The third permanent failure pauses. A delivery queued behind it is cancelled, not held.
	sender.result = ports.NotificationSendResult{ErrorCode: "destination_blocked"}
	tripDelivery := publish()
	var tripJob *ports.QueuedJob
	for tripJob == nil {
		job := claim()
		if job.Payload != nil && strings.Contains(string(job.Payload), tripDelivery.String()) {
			tripJob = job
		} else {
			_ = attempt(job) // the earlier 503 retry, still transient
		}
	}
	queued := publish()
	_ = attempt(tripJob)
	h := health()
	if !h.Paused() || h.ConsecutiveFailures != 3 || h.PausedReason != notification.PauseReasonPermanentFailures || h.PausedAt == nil {
		t.Fatalf("after the third permanent failure: %+v", h)
	}
	if d, err := repo.GetDelivery(ctx, tenant, queued); err != nil || d.State != notification.DeliveryCancelled || d.LastError != "channel_paused" {
		t.Fatalf("queued delivery after pause = %+v, %v", d, err)
	}
	calls := sender.calls
	// Its job still runs: it is a no-op and never reaches the sender.
	for {
		job, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			break
		}
		if err := attempt(job); err != nil {
			t.Fatal(err)
		}
	}
	if sender.calls != calls {
		t.Fatalf("a paused channel was sent to %d more times", sender.calls-calls)
	}
	// A test send is refused with a clear conflict, and rule fan-out skips the channel.
	if _, err := svc.TestChannel(ctx, "ada", channel.ID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("test on a paused channel: %v", err)
	}

	// History names the tripping delivery and attempt; the notice reached admins only.
	history, err := svc.ListChannelHealthEvents(ctx, channel.ID)
	if err != nil || len(history) != 1 || history[0].Action != notification.HealthActionPaused || history[0].DeliveryID != tripDelivery || history[0].AttemptID.IsZero() || history[0].Failures != 3 || history[0].Actor != "system" {
		t.Fatalf("pause history = %+v, %v", history, err)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE user_id='ada' AND event_type='notification.channel_paused'`); n != 1 {
		t.Fatalf("admin notices = %d", n)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE user_id='bob'`); n != 0 {
		t.Fatalf("member notices = %d", n)
	}
	if n := personalCount(t, ctx, pool, "other", `SELECT count(*) FROM user_notifications`); n != 0 {
		t.Fatalf("other tenant notices = %d", n)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_events WHERE event_type='notification.channel_paused' AND (data::text LIKE '%hooks.example%' OR data::text LIKE '%token%' OR data::text LIKE '%secret%')`); n != 0 {
		t.Fatal("the pause notice stored the destination")
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE summary LIKE '%hooks.example%' OR summary LIKE '%token%'`); n != 0 {
		t.Fatal("the inbox notice shows the destination")
	}
	var stored notification.Event
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		stored.TenantID = tenant
		return tx.QueryRow(ctx, `SELECT id,event_type,source_kind,source_id,engagement_id,severity,schema_version,occurred_at,data FROM notification_events WHERE event_type='notification.channel_paused'`).
			Scan(&stored.ID, &stored.Type, &stored.SourceKind, &stored.SourceID, &stored.EngagementID, &stored.Severity, &stored.SchemaVersion, &stored.OccurredAt, &stored.Data)
	}); err != nil {
		t.Fatal(err)
	}
	assertPublishedEventSchema(t, stored)
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_deliveries WHERE event_id=$1`, stored.ID); n != 0 {
		t.Fatalf("the pause notice was fanned out to %d channels", n)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM audit_log WHERE action='notification.channel.paused' AND actor='system' AND target=$1`, channel.ID); n != 1 {
		t.Fatalf("pause audit entries = %d", n)
	}

	// Recording the same tripping attempt again is a no-op: one pause, one notice.
	again, err := repo.RecordChannelOutcome(ctx, tenant, ports.NotificationChannelOutcome{ChannelID: channel.ID, DeliveryID: tripDelivery, AttemptID: history[0].AttemptID, Class: notification.AttemptPermanent, Code: "destination_blocked", At: clock.at, Threshold: 3})
	if err != nil || again.Paused {
		t.Fatalf("replayed outcome = %+v, %v", again, err)
	}

	// An administrator's edit that started before the pause still saves and keeps the pause.
	edited, err := svc.UpdateChannel(ctx, "ada", channel.ID, notificationuc.ChannelInput{Name: "Ops hook (renamed)", Enabled: true, Revision: channel.Revision})
	if err != nil || !edited.Health.Paused() || edited.Revision != channel.Revision+1 {
		t.Fatalf("edit while paused = %+v, %v", edited, err)
	}
	if _, err := svc.ResumeChannel(ctx, "ada", channel.ID, notificationuc.ResumeInput{Revision: channel.Revision}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale resume: %v", err)
	}
	resumed, err := svc.ResumeChannel(ctx, "ada", channel.ID, notificationuc.ResumeInput{Revision: edited.Revision})
	if err != nil || resumed.Health.Paused() || resumed.Health.ConsecutiveFailures != 0 || resumed.Revision != edited.Revision+1 {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
	if _, err := svc.ResumeChannel(ctx, "ada", channel.ID, notificationuc.ResumeInput{Revision: resumed.Revision}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second resume: %v", err)
	}
	history, err = svc.ListChannelHealthEvents(ctx, channel.ID)
	if err != nil || len(history) != 2 || history[0].Action != notification.HealthActionResumed || history[0].Actor != "ada" || history[0].Failures != 3 || history[0].FailureCode != "destination_blocked" {
		t.Fatalf("history after resume = %+v, %v", history, err)
	}

	// A success after resuming resets a fresh count; a later run of failures pauses again and
	// notifies again, because the notice is idempotent per pause, not per channel.
	sender.result = ports.NotificationSendResult{ErrorCode: "destination_blocked"}
	publish()
	_ = attempt(claim())
	sender.result = ports.NotificationSendResult{StatusCode: 204}
	publish()
	if err := attempt(claim()); err != nil {
		t.Fatal(err)
	}
	if h := health(); h.ConsecutiveFailures != 0 || h.Paused() {
		t.Fatalf("success after resume: %+v", h)
	}
	sender.result = ports.NotificationSendResult{StatusCode: 404, ErrorCode: "http_404"}
	for i := 0; i < 3; i++ {
		publish()
		_ = attempt(claim())
	}
	if h := health(); !h.Paused() || h.LastFailureCode != "http_404" {
		t.Fatalf("second pause: %+v", h)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE user_id='ada' AND event_type='notification.channel_paused'`); n != 2 {
		t.Fatalf("admin notices after two pauses = %d", n)
	}
}
