package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type notificationTestClock struct{ at time.Time }

func (c *notificationTestClock) Now() time.Time { return c.at }

type notificationTestIDs struct{ n int }

func (i *notificationTestIDs) NewID() shared.ID {
	i.n++
	return shared.ID(fmt.Sprintf("notification-test-%d", i.n))
}

type notificationTestSender struct {
	calls  int
	result ports.NotificationSendResult
}

func (s *notificationTestSender) Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.calls++
	return s.result
}

func notificationTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	isolated := newIsolatedMigrationDB(t, 163, 163)
	var database, role string
	if err := isolated.db.QueryRow("SELECT current_database(),current_user").Scan(&database, &role); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("SYNAPSE_TEST_DB_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + database
	u.User = url.UserPassword(role, "migration-test-password")
	if err := Migrate(context.Background(), u.String()); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestNotificationPostgresDurability(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "notify-a")
	tenant := shared.ID("notify-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('notify-a','A'),('notify-b','B')"); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	clock := &notificationTestClock{now}
	ids := &notificationTestIDs{}
	sender := &notificationTestSender{result: ports.NotificationSendResult{StatusCode: 503, ErrorCode: "http_503", Retryable: true}}
	svc, err := notificationuc.NewService(repo, cipher, sender, NewAuditLog(pool), clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
	channel, err := svc.CreateChannel(ctx, "admin", notificationuc.ChannelInput{Name: "Signed", Type: notification.ChannelWebhook, Enabled: true, URL: "https://example.com/secret-path?token=hidden", Secret: "1234567890abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(channel)
	if strings.Contains(string(encoded), "hidden") || strings.Contains(string(encoded), "abcdef") {
		t.Fatal("secret in API result")
	}
	for n := 0; n < 2; n++ {
		_, err = svc.CreateRule(ctx, "admin", notificationuc.RuleInput{Name: fmt.Sprint(n), Enabled: true, EventType: notification.EventVulnerabilityAction, MinSeverity: shared.SeverityHigh, ChannelIDs: []shared.ID{channel.ID}})
		if err != nil {
			t.Fatal(err)
		}
	}
	event := notification.Event{TenantID: tenant, ID: "event-1", Type: notification.EventVulnerabilityAction, SourceKind: "risk-test", SourceID: "risk-1", Severity: shared.SeverityHigh, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{"title":"High risk"}`)}
	deliveries, err := repo.Publish(ctx, event)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("fanout=%v err=%v", deliveries, err)
	}
	again, err := repo.Publish(ctx, event)
	if err != nil || len(again) != 1 || again[0] != deliveries[0] {
		t.Fatalf("replay=%v err=%v", again, err)
	}
	did := deliveries[0]
	work, err := repo.LoadWork(ctx, tenant, did)
	if err != nil || len(work.Delivery.MatchedRuleIDs) != 2 {
		t.Fatalf("work=%+v err=%v", work, err)
	}
	if _, err = svc.GetChannel(shared.WithTenant(ctx, "notify-b"), channel.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant read=%v", err)
	}
	_, err = svc.CreateRule(shared.WithTenant(ctx, "notify-b"), "other", notificationuc.RuleInput{Name: "cross", Enabled: true, EventType: event.Type, ChannelIDs: []shared.ID{channel.ID}})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant binding=%v", err)
	}
	// No-match remains no-match after new rules are added.
	low := event
	low.ID = "event-low"
	low.SourceID = "risk-low"
	low.Severity = shared.SeverityLow
	if ds, e := repo.Publish(ctx, low); e != nil || len(ds) != 0 {
		t.Fatalf("low severity fanout=%v %v", ds, e)
	}
	// Roll back all event/delivery/job writes together.
	rollback := errors.New("injected rollback")
	err = NewTenantTransactionRunner(pool).Run(ctx, tenant, func(txctx context.Context) error {
		v := event
		v.ID = "rollback"
		v.SourceID = "rollback"
		if _, e := repo.Publish(txctx, v); e != nil {
			return e
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var count int
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM notification_events WHERE id='rollback'").Scan(&count)
	})
	if err != nil || count != 0 {
		t.Fatalf("rollback left event=%d err=%v", count, err)
	}
	queue := NewJobQueue(pool, ids)
	job, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim=%v %v", job, err)
	}
	// One network attempt, persisted retry, no sleep in the handler.
	err = svc.HandleJob(ctx, *job)
	var retry *notificationuc.DeliveryError
	if !errors.As(err, &retry) || retry.Terminal() || sender.calls != 1 {
		t.Fatalf("retry err=%v calls=%d", err, sender.calls)
	}
	if err = queue.Fail(ctx, job.ID, job.Fence, 0); err != nil {
		t.Fatal(err)
	}
	// Simulate passing wall time without sleeping.
	clock.at = now.Add(2 * time.Second)
	job2, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job2 == nil {
		t.Fatalf("second claim=%v %v", job2, err)
	}
	if _, err = repo.BeginAttempt(ctx, tenant, did, job.ID, job.Fence, "stale", clock.at, ""); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale start=%v", err)
	}
	sender.result = ports.NotificationSendResult{StatusCode: 204}
	if err = svc.HandleJob(ctx, *job2); err != nil {
		t.Fatal(err)
	}
	// Crash before queue.Complete: replay sees success and does not resend.
	if err = svc.HandleJob(ctx, *job2); err != nil || sender.calls != 2 {
		t.Fatalf("ack replay=%v calls=%d", err, sender.calls)
	}
	attempts, err := repo.ListAttempts(ctx, tenant, did)
	if err != nil || len(attempts) != 2 || attempts[1].Outcome != "delivered" {
		t.Fatalf("attempts=%+v %v", attempts, err)
	}
	if err = queue.Complete(ctx, job2.ID, job2.Fence); err != nil {
		t.Fatal(err)
	}
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { return repo.reconcileTx(ctx, tx, tenant) }); err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM notification_audit_intents WHERE recorded_at IS NULL").Scan(&count)
	})
	if err != nil || count != 0 {
		t.Fatalf("undrained audits=%d %v", count, err)
	}
	// Rotating the channel after did is delivered must not retarget its pinned configuration: a
	// historical delivery keeps the channel_version it was sent under. #1352 covers the opposite
	// case, a delivery still pending or retrying when the channel rotates.
	channel, err = svc.UpdateChannel(ctx, "admin", channel.ID, notificationuc.ChannelInput{Name: channel.Name, Type: channel.Type, Enabled: true, URL: "https://example.net/replacement", Secret: "replacement-secret", Revision: channel.Revision, AllowDestinationChange: true})
	if err != nil {
		t.Fatal(err)
	}
	work, err = repo.LoadWork(ctx, tenant, did)
	if err != nil || work.Channel.SecretVersion != 1 || work.Delivery.State != notification.DeliverySucceeded {
		t.Fatalf("snapshot version=%d state=%s err=%v", work.Channel.SecretVersion, work.Delivery.State, err)
	}
	// Rate-limited synthetic tests share the production fanout.
	for n := 0; n < 10; n++ {
		if _, err = svc.TestChannel(ctx, "admin", channel.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = svc.TestChannel(ctx, "admin", channel.ID); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("test rate limit=%v", err)
	}
	// Cover the operator-only notification.test event from its real service
	// producer as well as the fixture and Event JSON-tag tests.
	var testEvents []notification.Event
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT id,event_type,source_kind,source_id,engagement_id,severity,schema_version,occurred_at,data FROM notification_events WHERE tenant_id=$1 AND event_type=$2", tenant, notification.EventTest)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e := notification.Event{TenantID: tenant}
			if err := rows.Scan(&e.ID, &e.Type, &e.SourceKind, &e.SourceID, &e.EngagementID, &e.Severity, &e.SchemaVersion, &e.OccurredAt, &e.Data); err != nil {
				return err
			}
			testEvents = append(testEvents, e)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(testEvents) != 10 {
		t.Fatalf("operator test events = %d; want 10", len(testEvents))
	}
	for _, e := range testEvents {
		assertPublishedEventSchema(t, e)
	}
}

func TestNotificationPostgresRedriveIsFencedAndPreservesHistory(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "notify-redrive")
	tenant := shared.ID("notify-redrive")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Redrive')", tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	clock := &notificationTestClock{at: now}
	ids := &notificationTestIDs{}
	sender := &notificationTestSender{result: ports.NotificationSendResult{StatusCode: 204}}
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("r", 32)))
	svc, err := notificationuc.NewService(repo, cipher, sender, NewAuditLog(pool), clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
	channel, err := svc.CreateChannel(ctx, "admin", notificationuc.ChannelInput{
		Name: "Stable hook", Type: notification.ChannelWebhook, Enabled: true,
		URL: "https://hooks.example.test/services/T1/B2", Secret: "0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	did, err := svc.TestChannel(ctx, "admin", channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	queue := NewJobQueue(pool, ids)
	job, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job == nil || job.ID != "notification-"+did.String() {
		t.Fatalf("first claim=%+v err=%v", job, err)
	}
	firstAttempt, err := repo.BeginAttempt(ctx, tenant, did, job.ID, job.Fence, "redrive-attempt-1", now, "tenant:tpl@1")
	if err != nil {
		t.Fatal(err)
	}
	next := now.Add(time.Second)
	if err := repo.FinishAttempt(ctx, tenant, did, job.ID, job.Fence, firstAttempt.ID, now, "retrying", 503, "http_503", &next); err != nil {
		t.Fatal(err)
	}
	if err := queue.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnDeadLetter(ctx, *job, errors.New("retry budget exhausted")); err != nil {
		t.Fatal(err)
	}
	dead, err := repo.GetDelivery(ctx, tenant, did)
	if err != nil || dead.State != notification.DeliveryDead || dead.RedriveFence != job.Fence || dead.Attempts != 1 {
		t.Fatalf("dead delivery=%+v err=%v", dead, err)
	}
	channel, err = svc.UpdateChannel(ctx, "admin", channel.ID, notificationuc.ChannelInput{
		Name: "Renamed hook", Type: channel.Type, Enabled: true, Revision: channel.Revision,
	})
	if err != nil {
		t.Fatalf("metadata-only rename: %v", err)
	}

	// Two confirmations with the same observation race at the database boundary;
	// exactly one can advance the existing job and the winner must audit atomically.
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.RedriveDelivery(ctx, "admin", did, notificationuc.RedriveInput{Reason: "Receiver recovered", ExpectedFence: dead.RedriveFence})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for callErr := range results {
		switch {
		case callErr == nil:
			successes++
		case errors.Is(callErr, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("redrive race error=%v", callErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("redrive race successes=%d conflicts=%d", successes, conflicts)
	}
	pending, err := repo.GetDelivery(ctx, tenant, did)
	if err != nil || pending.State != notification.DeliveryPending || pending.Attempts != 1 || pending.RedriveFence != dead.RedriveFence+1 || pending.LastError != "" || pending.NextAttemptAt != nil || pending.DeliveredAt != nil {
		t.Fatalf("redriven delivery=%+v err=%v", pending, err)
	}
	// Redrive releases the pin so the next attempt resolves again (#1365); the history keeps it.
	if pending.TemplateRef != "" {
		t.Fatalf("redriven delivery still pins %q", pending.TemplateRef)
	}
	if attempts, err := repo.ListAttempts(ctx, tenant, did); err != nil || len(attempts) != 1 || attempts[0].Outcome != "retrying" || attempts[0].TemplateRef != "tenant:tpl@1" {
		t.Fatalf("attempt history=%+v err=%v", attempts, err)
	}
	if err := svc.OnDeadLetter(ctx, *job, errors.New("delayed callback")); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { return repo.reconcileTx(ctx, tx, tenant) }); err != nil {
		t.Fatal(err)
	}
	pending, err = repo.GetDelivery(ctx, tenant, did)
	if err != nil || pending.State != notification.DeliveryPending {
		t.Fatalf("stale callback/reconcile changed delivery: %+v err=%v", pending, err)
	}
	if _, _, err := repo.RedriveDelivery(ctx, tenant, did, dead.RedriveFence); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale confirmation error=%v", err)
	}

	clock.at = now.Add(2 * time.Second)
	job2, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job2 == nil || job2.ID != job.ID || job2.Attempts != 1 || job2.Fence != dead.RedriveFence+2 {
		t.Fatalf("redrive claim=%+v err=%v", job2, err)
	}
	secondAttempt, err := repo.BeginAttempt(ctx, tenant, did, job2.ID, job2.Fence, "redrive-attempt-2", clock.at, "")
	if err != nil {
		t.Fatal(err)
	}
	next = clock.at.Add(time.Second)
	if err := repo.FinishAttempt(ctx, tenant, did, job2.ID, job2.Fence, secondAttempt.ID, clock.at, "retrying", 503, "http_503", &next); err != nil {
		t.Fatal(err)
	}
	if err := queue.Deadletter(ctx, job2.ID, job2.Fence); err != nil {
		t.Fatal(err)
	}
	// Even when a newer cycle is also failed, the old callback must not repair it.
	if err := svc.OnDeadLetter(ctx, *job, errors.New("obsolete first-cycle callback")); err != nil {
		t.Fatal(err)
	}
	stillRetrying, err := repo.GetDelivery(ctx, tenant, did)
	if err != nil || stillRetrying.State != notification.DeliveryRetrying {
		t.Fatalf("old callback applied to a later failed cycle: %+v %v", stillRetrying, err)
	}
	// Repair a second terminal cycle through reconciliation. Its audit intent key
	// must differ from the first cycle's key even though the delivery ID is stable.
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { return repo.reconcileTx(ctx, tx, tenant) }); err != nil {
		t.Fatal(err)
	}
	dead2, err := repo.GetDelivery(ctx, tenant, did)
	if err != nil || dead2.State != notification.DeliveryDead || dead2.RedriveFence != job2.Fence || dead2.Attempts != 2 {
		t.Fatalf("second dead cycle=%+v err=%v", dead2, err)
	}
	var deadIntents int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(DISTINCT id) FROM notification_audit_intents WHERE tenant_id=$1 AND delivery_id=$2 AND id LIKE 'dead:%'`, tenant, did).Scan(&deadIntents)
	}); err != nil || deadIntents != 2 {
		t.Fatalf("cycle audit intents=%d err=%v", deadIntents, err)
	}
	if _, err := svc.RedriveDelivery(ctx, "admin", did, notificationuc.RedriveInput{Reason: "Retry after receiver recovery", ExpectedFence: dead2.RedriveFence}); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnDeadLetter(ctx, *job2, errors.New("delayed second-cycle callback")); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { return repo.reconcileTx(ctx, tx, tenant) }); err != nil {
		t.Fatal(err)
	}
	pending, err = repo.GetDelivery(ctx, tenant, did)
	if err != nil || pending.State != notification.DeliveryPending {
		t.Fatalf("second stale callback/reconcile changed delivery: %+v err=%v", pending, err)
	}
	if _, _, err := repo.RedriveDelivery(ctx, tenant, did, dead.RedriveFence); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("older-cycle confirmation error=%v", err)
	}
	clock.at = now.Add(4 * time.Second)
	job3, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job3 == nil || job3.ID != job.ID || job3.Attempts != 1 || job3.Fence != dead2.RedriveFence+2 {
		t.Fatalf("second redrive claim=%+v err=%v", job3, err)
	}
	if err := svc.HandleJob(ctx, *job3); err != nil {
		t.Fatal(err)
	}
	if err := queue.Complete(ctx, job3.ID, job3.Fence); err != nil {
		t.Fatal(err)
	}
	attempts, err := repo.ListAttempts(ctx, tenant, did)
	if err != nil || len(attempts) != 3 || attempts[0].Outcome != "retrying" || attempts[1].Outcome != "retrying" || attempts[2].Outcome != "delivered" || attempts[2].Number != 3 {
		t.Fatalf("completed redrive history=%+v err=%v", attempts, err)
	}

	// A dead delivery remains bound to the channel version it was created for.
	changedChannel, err := svc.CreateChannel(ctx, "admin", notificationuc.ChannelInput{
		Name: "Rotating hook", Type: notification.ChannelWebhook, Enabled: true,
		URL: "https://old.example.test/hook", Secret: "0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	changedID, err := svc.TestChannel(ctx, "admin", changedChannel.ID)
	if err != nil {
		t.Fatal(err)
	}
	job4, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job4 == nil {
		t.Fatalf("rotating claim=%+v err=%v", job4, err)
	}
	clock.at = now.Add(6 * time.Second)
	thirdAttempt, err := repo.BeginAttempt(ctx, tenant, changedID, job4.ID, job4.Fence, "redrive-attempt-rotating", clock.at, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.FinishAttempt(ctx, tenant, changedID, job4.ID, job4.Fence, thirdAttempt.ID, clock.at, "failed", 503, "http_503", nil); err != nil {
		t.Fatal(err)
	}
	if err := queue.Deadletter(ctx, job4.ID, job4.Fence); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.UpdateChannel(ctx, "admin", changedChannel.ID, notificationuc.ChannelInput{
		Name: changedChannel.Name, Type: changedChannel.Type, Enabled: true,
		URL: "https://new.example.test/hook", Secret: "fedcba9876543210", Revision: changedChannel.Revision, AllowDestinationChange: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.RedriveDelivery(ctx, "admin", changedID, notificationuc.RedriveInput{Reason: "Destination rotated", ExpectedFence: job4.Fence}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("rotated destination redrive error=%v", err)
	}
}

func TestNotificationPostgresCapturedSources(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "notify-a")
	tenant := shared.ID("notify-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('notify-a','A')"); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO engagements(id,tenant_id,name) VALUES('eng','notify-a','E')")
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	channel := notification.Channel{TenantID: tenant, ID: "channel", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []notification.EventType{notification.EventScanCompleted, notification.EventQualityGateFailed, notification.EventIncidentCreated, notification.EventFleetAgentOffline} {
		if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: shared.ID(kind), Name: string(kind), Enabled: true, EventType: kind, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 100); err != nil {
		t.Fatal(err)
	}
	finished := now.Add(time.Second)
	if err := NewScanJobStore(pool).Save(ctx, ports.ScanJob{ID: "scan", EngagementID: "eng", Target: "ignored", Kind: "git", Status: ports.ScanSucceeded, Stage: "done", StartedAt: finished, FinishedAt: &finished}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES('project','notify-a','P','p','{}')`)
	exec(`INSERT INTO project_analyses(id,tenant_id,project_id,created_at,payload) VALUES('analysis','notify-a','project',$1,'{"gate":{"Passed":false}}')`, now.Add(time.Second))
	exec(`INSERT INTO incident_events(tenant_id,incident_id,seq,kind,occurred_at,actor,payload) VALUES('notify-a','incident',1,'created',$1,'correlator','{"Severity":"high","Title":"Detected"}')`, now.Add(time.Second))
	exec(`INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state,created_at,last_seen_at) VALUES('agent','notify-a','A','hash','active',$1,$2)`, now.Add(-time.Minute), now)
	// Inspect real INSERT-trigger output before the poller consumes the JSONB.
	var captured []notification.Event
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT source_kind,source_id,event_type,engagement_id,severity,occurred_at,data FROM notification_source_records WHERE tenant_id=$1 ORDER BY event_type", tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e := notification.Event{TenantID: tenant, ID: "captured-schema-test", SchemaVersion: 1}
			if err := rows.Scan(&e.SourceKind, &e.SourceID, &e.Type, &e.EngagementID, &e.Severity, &e.OccurredAt, &e.Data); err != nil {
				return err
			}
			captured = append(captured, e)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	seen := map[notification.EventType]bool{}
	for _, e := range captured {
		assertPublishedEventSchema(t, e)
		if seen[e.Type] {
			t.Errorf("duplicate SQL capture for %s", e.Type)
		}
		seen[e.Type] = true
		if e.Type == notification.EventIncidentCreated {
			var data map[string]any
			if err := json.Unmarshal(e.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data["asset_id"] != "" {
				t.Errorf("assetless incident must emit an empty string, got %v", data["asset_id"])
			}
		}
	}
	for _, typ := range []notification.EventType{notification.EventScanCompleted, notification.EventQualityGateFailed, notification.EventIncidentCreated} {
		if !seen[typ] {
			t.Errorf("SQL capture trigger failed to record %s", typ)
		}
	}
	if len(captured) != 3 {
		t.Fatalf("captured %d SQL events; want exactly 3", len(captured))
	}
	if _, err := source.Poll(ctx, now.Add(2*time.Second), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, now.Add(2*time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 4 {
		t.Fatalf("source fanout=%d %v", len(page.Items), err)
	}
	if _, err := source.Poll(ctx, now.Add(3*time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	replay, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(replay.Items) != 4 {
		t.Fatalf("replay duplicates=%d %v", len(replay.Items), err)
	}
	for _, d := range replay.Items {
		w, err := repo.LoadWork(ctx, tenant, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		assertPublishedEventSchema(t, w.Event)
		assertComposedFromSource(t, w.Event)
		if w.Event.Type == notification.EventFleetAgentOffline {
			exec("UPDATE fleet_agents SET last_seen_at=$1 WHERE id='agent'", now.Add(3*time.Minute))
			if relevant, e := deliveryStillRelevant(repo, ctx, w); e != nil || relevant {
				t.Fatalf("recovery not rechecked: %v %v", relevant, e)
			}
		}
	}
	// #1347: a deployment that also runs the deprecated SYNAPSE_ALERT_WEBHOOK_URL sink still projects
	// every incident.created onto the framework. The source has no legacy switch any more, so a second
	// incident is published once and a replayed poll never sends it twice.
	exec(`INSERT INTO incident_events(tenant_id,incident_id,seq,kind,occurred_at,actor,payload) VALUES('notify-a','legacy-incident',1,'created',$1,'correlator','{"Severity":"high","Title":"Legacy"}')`, now.Add(4*time.Minute))
	exec("UPDATE fleet_agents SET last_seen_at=$1 WHERE id='agent'", now.Add(4*time.Minute))
	for _, at := range []time.Time{now.Add(4 * time.Minute), now.Add(5 * time.Minute)} {
		if _, err := source.Poll(ctx, at, 100); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE source_kind='incident'`).Scan(&count)
	}); err != nil || count != 2 {
		t.Fatalf("incident events=%d, want 2 (each incident projected exactly once): %v", count, err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries d JOIN notification_events e ON e.tenant_id=d.tenant_id AND e.id=d.event_id WHERE e.source_kind='incident'`).Scan(&count)
	}); err != nil || count != 2 {
		t.Fatalf("incident deliveries=%d, want 2: %v", count, err)
	}
}

// assertComposedFromSource checks that a captured event carries the data the migration 0163
// trigger writes, whether the trigger wrote it or the builder composed it from an identity-only
// record, and that its snapshot carries the names read from the source rows.
func assertComposedFromSource(t *testing.T, e notification.Event) {
	t.Helper()
	want := map[notification.EventType]struct {
		data string
		vars map[string]string
	}{
		notification.EventScanCompleted: {
			`{"scan_id": "scan", "summary": "A scan completed successfully.", "title": "Scan completed", "scan_kind": "git"}`,
			map[string]string{"engagement_name": "E", "target": "ignored", "scan_kind": "git"},
		},
		notification.EventQualityGateFailed: {
			`{"title": "Quality gate failed", "summary": "A finalized project analysis failed its quality gate.", "project_id": "project", "analysis_id": "analysis"}`,
			map[string]string{"project_name": "P", "failed_conditions": "0"},
		},
		notification.EventIncidentCreated: {
			`{"title": "Detected", "summary": "Fleet correlation created an incident.", "asset_id": "", "incident_id": "incident"}`,
			map[string]string{"severity": "high", "title": "Detected"},
		},
	}[e.Type]
	if want.data == "" {
		return
	}
	var got, expected map[string]any
	if err := json.Unmarshal(e.Data, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want.data), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("%s data = %s, want %s", e.Type, e.Data, want.data)
	}
	snapshot, err := notification.DecodeTemplateContext(e.Context)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range want.vars {
		if snapshot.Vars[name] != value {
			t.Errorf("%s variable %s = %q, want %q", e.Type, name, snapshot.Vars[name], value)
		}
	}
}
