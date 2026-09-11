package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
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
	// Rotation must preserve the selected encrypted version for pending work.
	channel, err = svc.UpdateChannel(ctx, "admin", channel.ID, notificationuc.ChannelInput{Name: channel.Name, Type: channel.Type, Enabled: true, URL: "https://example.net/replacement", Secret: "replacement-secret", Revision: channel.Revision})
	if err != nil {
		t.Fatal(err)
	}
	work, err = repo.LoadWork(ctx, tenant, did)
	if err != nil || work.Channel.SecretVersion != 1 {
		t.Fatalf("snapshot version=%d err=%v", work.Channel.SecretVersion, err)
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
	if _, err = repo.BeginAttempt(ctx, tenant, did, job.ID, job.Fence, "stale", clock.at); !errors.Is(err, ports.ErrStaleLease) {
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
	// Rate-limited synthetic tests share the production fanout.
	for n := 0; n < 10; n++ {
		if _, err = svc.TestChannel(ctx, "admin", channel.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = svc.TestChannel(ctx, "admin", channel.ID); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("test rate limit=%v", err)
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
	channel := notification.Channel{TenantID: tenant, ID: "channel", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []notification.EventType{notification.EventScanCompleted, notification.EventQualityGateFailed, notification.EventIncidentCreated, notification.EventFleetAgentOffline} {
		if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: shared.ID(kind), Name: string(kind), Enabled: true, EventType: kind, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	source := NewNotificationSource(pool, repo, time.Minute, true)
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
		if w.Event.Type == notification.EventFleetAgentOffline {
			exec("UPDATE fleet_agents SET last_seen_at=$1 WHERE id='agent'", now.Add(3*time.Minute))
			if relevant, e := repo.DeliveryStillRelevant(ctx, w); e != nil || relevant {
				t.Fatalf("recovery not rechecked: %v %v", relevant, e)
			}
		}
	}
	// Legacy routing consumes the inbox without a second durable incident send.
	exec(`INSERT INTO incident_events(tenant_id,incident_id,seq,kind,occurred_at,actor,payload) VALUES('notify-a','legacy-incident',1,'created',$1,'correlator','{"Severity":"high","Title":"Legacy"}')`, now.Add(4*time.Minute))
	legacy := NewNotificationSource(pool, repo, time.Minute, false)
	if _, err := legacy.Poll(ctx, now.Add(4*time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	// Keep the heartbeat fresh while switching routing back to the framework.
	exec("UPDATE fleet_agents SET last_seen_at=$1 WHERE id='agent'", now.Add(5*time.Minute))
	if _, err := source.Poll(ctx, now.Add(5*time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE source_kind='incident'`).Scan(&count)
	}); err != nil || count != 1 {
		t.Fatalf("legacy incident replayed: %d %v", count, err)
	}
}
