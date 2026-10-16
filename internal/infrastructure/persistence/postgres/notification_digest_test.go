package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestNotificationPostgresDigestMaterializesOnce(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("digest-postgres")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	channel := notification.Channel{TenantID: tenant, ID: "digest-channel", Name: "Digest", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	rule := notification.Rule{TenantID: tenant, ID: "digest-rule", Name: "Digest", Enabled: true, EventType: notification.EventVulnerabilityAction, Cadence: notification.CadenceHourly, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "digest-source", Type: notification.EventVulnerabilityAction, SourceKind: "digest-test", SourceID: "digest-source", Severity: shared.SeverityHigh, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{"action_type":"escalate"}`)}
	if deliveries, err := repo.Publish(ctx, event); err != nil || len(deliveries) != 0 {
		t.Fatalf("source deliveries=%v err=%v, want none before close", deliveries, err)
	}
	materialize := func() int {
		var count int
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 78145))`, tenant.String()); err != nil {
				return err
			}
			var err error
			count, err = repo.materializeDigestsTx(ctx, tx, tenant, time.Now().UTC().Add(2*time.Hour), 10)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if got := materialize(); got != 1 {
		t.Fatalf("first materialization=%d, want 1", got)
	}
	if got := materialize(); got != 0 {
		t.Fatalf("rerun materialization=%d, want 0", got)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("digest deliveries=%+v err=%v", page, err)
	}
	work, err := repo.LoadWork(ctx, tenant, page.Items[0].ID)
	if err != nil || work.Event.Type != notification.EventDigest || len(work.Event.DigestItems) != 1 || work.DigestPolicy == "" {
		t.Fatalf("digest work=%+v err=%v", work, err)
	}
	recent, err := repo.ListRecentNotificationEvents(ctx, tenant, notification.EventDigest, 10)
	if err != nil || len(recent) != 1 || len(recent[0].DigestItems) != 0 {
		t.Fatalf("recent digest events=%+v err=%v", recent, err)
	}
}

type postgresDigestFixture struct {
	ctx     context.Context
	tenant  shared.ID
	repo    *NotificationRepository
	channel notification.Channel
	rule    notification.Rule
	at      time.Time
}

func newPostgresDigestFixture(t *testing.T, pool *pgxpool.Pool, tenant shared.ID, cadence notification.DeliveryCadence) postgresDigestFixture {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	channel := notification.Channel{TenantID: tenant, ID: "digest-channel", Name: "Digest", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: at, UpdatedAt: at}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	rule := notification.Rule{TenantID: tenant, ID: "digest-rule", Name: "Digest", Enabled: true, EventType: notification.EventScanCompleted, Cadence: cadence, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: at, UpdatedAt: at}
	if _, err := repo.CreateRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	return postgresDigestFixture{ctx: ctx, tenant: tenant, repo: repo, channel: channel, rule: rule, at: at}
}

func (f postgresDigestFixture) publish(t *testing.T, id shared.ID, engagement shared.ID, eventType notification.EventType, severity shared.Severity) []shared.ID {
	t.Helper()
	event := notification.Event{TenantID: f.tenant, ID: id, Type: eventType, SourceKind: "digest-source", SourceID: id.String(), EngagementID: engagement,
		Severity: severity, SchemaVersion: 1, OccurredAt: f.at, Data: json.RawMessage(`{"title":"digest source"}`),
		Context: json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-10-16T10:15:00Z","title":"digest source"}}`)}
	ids, err := f.repo.Publish(f.ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func (f postgresDigestFixture) materialize(ctx context.Context, now time.Time, limit int) (int, error) {
	count := 0
	err := WithTenant(ctx, f.repo.pool, f.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 78145))`, f.tenant.String()); err != nil {
			return err
		}
		var err error
		count, err = f.repo.materializeDigestsTx(ctx, tx, f.tenant, now, limit)
		return err
	})
	return count, err
}

func TestNotificationPostgresDigestDurabilityInvariants(t *testing.T) {
	pool := notificationTestPool(t)
	t.Run("concurrent materialization is idempotent", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-concurrent", notification.CadenceHourly)
		if ids := f.publish(t, "concurrent-event", "", notification.EventScanCompleted, shared.SeverityHigh); len(ids) != 0 {
			t.Fatalf("source deliveries=%v, want none", ids)
		}
		start := make(chan struct{})
		type result struct {
			count int
			err   error
		}
		results := make(chan result, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				count, err := f.materialize(f.ctx, f.at.Add(2*time.Hour), 1)
				results <- result{count, err}
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		total := 0
		for result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			total += result.count
		}
		if total != 1 {
			t.Fatalf("concurrent materialization count=%d, want 1", total)
		}
		page, err := f.repo.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("deliveries=%+v err=%v", page, err)
		}
	})

	t.Run("daily windows and tenants stay separate", func(t *testing.T) {
		a := newPostgresDigestFixture(t, pool, "digest-daily-a", notification.CadenceDaily)
		b := newPostgresDigestFixture(t, pool, "digest-daily-b", notification.CadenceDaily)
		a.publish(t, "same-event", "", notification.EventScanCompleted, shared.SeverityHigh)
		b.publish(t, "same-event", "", notification.EventScanCompleted, shared.SeverityHigh)
		if count, err := a.materialize(a.ctx, a.at.Add(25*time.Hour), 10); err != nil || count != 1 {
			t.Fatalf("tenant A daily materialize=%d err=%v", count, err)
		}
		for _, check := range []struct {
			fixture postgresDigestFixture
			want    int
		}{{a, 1}, {b, 0}} {
			page, err := check.fixture.repo.ListDeliveries(check.fixture.ctx, ports.NotificationDeliveryFilter{TenantID: check.fixture.tenant})
			if err != nil || len(page.Items) != check.want {
				t.Fatalf("tenant %s deliveries=%+v err=%v, want %d", check.fixture.tenant, page, err, check.want)
			}
		}
		page, err := a.repo.ListDeliveries(a.ctx, ports.NotificationDeliveryFilter{TenantID: a.tenant})
		if err != nil {
			t.Fatal(err)
		}
		work, err := a.repo.LoadWork(a.ctx, a.tenant, page.Items[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		var digest notification.DigestData
		if err := json.Unmarshal(work.Event.Data, &digest); err != nil || digest.Cadence != notification.CadenceDaily {
			t.Fatalf("daily digest=%+v err=%v", digest, err)
		}
		if count, err := b.materialize(b.ctx, b.at.Add(25*time.Hour), 10); err != nil || count != 1 {
			t.Fatalf("tenant B daily materialize=%d err=%v", count, err)
		}
	})

	t.Run("overflow continues in bounded chunks", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-overflow", notification.CadenceHourly)
		for i := 0; i <= maxDigestMembers; i++ {
			f.publish(t, shared.ID(fmt.Sprintf("overflow-%03d", i)), "", notification.EventScanCompleted, shared.SeverityHigh)
		}
		// Replaying a source while the CTE assigns a full tail chunk must leave
		// both chunk boundaries unchanged.
		f.publish(t, "overflow-000", "", notification.EventScanCompleted, shared.SeverityHigh)
		var members int
		if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM notification_digest_members WHERE tenant_id=$1`, f.tenant).Scan(&members)
		}); err != nil || members != maxDigestMembers+1 {
			t.Fatalf("overflow members=%d err=%v, want %d", members, err, maxDigestMembers+1)
		}
		if count, err := f.materialize(f.ctx, f.at.Add(2*time.Hour), 10); err != nil || count != 2 {
			t.Fatalf("overflow materialize=%d err=%v, want two chunks", count, err)
		}
		page, err := f.repo.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant})
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("overflow deliveries=%+v err=%v", page, err)
		}
		counts := make([]int, 0, 2)
		for _, delivery := range page.Items {
			work, err := f.repo.LoadWork(f.ctx, f.tenant, delivery.ID)
			if err != nil {
				t.Fatal(err)
			}
			var digest notification.DigestData
			if err := json.Unmarshal(work.Event.Data, &digest); err != nil {
				t.Fatal(err)
			}
			if len(digest.EventIDs) > notification.MaxDigestItems || len(work.Event.DigestItems) > maxDigestMembers {
				t.Fatalf("chunk limits ids=%d members=%d", len(digest.EventIDs), len(work.Event.DigestItems))
			}
			counts = append(counts, digest.TotalCount)
		}
		slices.Sort(counts)
		if !slices.Equal(counts, []int{1, maxDigestMembers}) {
			t.Fatalf("overflow counts=%v, want [1 %d]", counts, maxDigestMembers)
		}
	})

	t.Run("one admission batch retains every matching target", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-batch-targets", notification.CadenceHourly)
		channel := notification.Channel{TenantID: f.tenant, ID: "digest-channel-b", Name: "Digest B", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: f.at, UpdatedAt: f.at}
		if _, err := f.repo.CreateChannel(f.ctx, channel, "sealed-b"); err != nil {
			t.Fatal(err)
		}
		rule := f.rule
		rule.ID, rule.Name, rule.ChannelIDs = "digest-rule-b", "Digest B", []shared.ID{channel.ID}
		if _, err := f.repo.CreateRule(f.ctx, rule); err != nil {
			t.Fatal(err)
		}
		f.publish(t, "batch-source", "", notification.EventScanCompleted, shared.SeverityHigh)
		var members, windows int
		if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM notification_digest_members WHERE tenant_id=$1`, f.tenant).Scan(&members); err != nil {
				return err
			}
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM notification_digest_windows WHERE tenant_id=$1 AND outcome='pending'`, f.tenant).Scan(&windows)
		}); err != nil || members != 2 || windows != 2 {
			t.Fatalf("batched memberships=%d windows=%d err=%v, want 2 each", members, windows, err)
		}
	})

	t.Run("critical and mandatory events bypass cadence", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-bypass", notification.CadenceHourly)
		for _, tc := range []struct {
			id       shared.ID
			event    notification.EventType
			severity shared.Severity
		}{{"critical", notification.EventScanCompleted, shared.SeverityCritical}, {"mandatory", notification.EventEvidenceChainBroken, shared.SeverityHigh}} {
			rule := f.rule
			rule.ID, rule.Name, rule.EventType = shared.ID("rule-"+tc.id.String()), "Bypass "+tc.id.String(), tc.event
			if _, err := f.repo.CreateRule(f.ctx, rule); err != nil {
				t.Fatal(err)
			}
			if ids := f.publish(t, tc.id, "", tc.event, tc.severity); len(ids) != 1 {
				t.Fatalf("%s deliveries=%v, want immediate one", tc.id, ids)
			}
		}
		var members int
		if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM notification_digest_members WHERE tenant_id=$1`, f.tenant).Scan(&members)
		}); err != nil {
			t.Fatal(err)
		}
		if members != 0 {
			t.Fatalf("bypass members=%d, want 0", members)
		}
	})

	t.Run("suppressed members finalize empty and policy changes refuse attempt", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-policy", notification.CadenceHourly)
		engagement := shared.ID("digest-engagement")
		if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(f.ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Digest')`, engagement, f.tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		f.publish(t, "policy-event", engagement, notification.EventScanCompleted, shared.SeverityHigh)
		if count, err := f.materialize(f.ctx, f.at.Add(2*time.Hour), 10); err != nil || count != 1 {
			t.Fatalf("materialize=%d err=%v", count, err)
		}
		page, err := f.repo.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("deliveries=%+v err=%v", page, err)
		}
		work, err := f.repo.LoadWork(f.ctx, f.tenant, page.Items[0].ID)
		if err != nil || work.DigestPolicy == "" {
			t.Fatalf("work=%+v err=%v", work, err)
		}
		updatedAt := f.at.Add(time.Minute)
		if _, err := f.repo.PutEngagementNotificationSetting(f.ctx, notification.EngagementNotificationSetting{TenantID: f.tenant, EngagementID: engagement,
			ExternalNotifications: notification.EngagementNotificationsNone, Revision: 1, UpdatedAt: &updatedAt, UpdatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		var job ports.QueuedJob
		err = WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `UPDATE jobs SET status='claimed',attempts=attempts+1,claim_fence=claim_fence+1,claimed_until=now()+interval '1 minute',updated_at=now()
				WHERE tenant_id=$1 AND id=$2 AND kind='notification.deliver'
				RETURNING id,tenant_id,kind,payload,attempts,claim_fence`, f.tenant, "notification-"+page.Items[0].ID.String()).Scan(&job.ID, &job.TenantID, &job.Kind, &job.Payload, &job.Attempts, &job.Fence)
		})
		if err != nil {
			t.Fatalf("claim digest job: %v", err)
		}
		_, err = f.repo.BeginAttempt(f.ctx, f.tenant, page.Items[0].ID, job.ID, job.Fence, "policy-attempt", time.Now().UTC(), ports.AttemptAdmission{DataClass: work.Channel.Class(), DigestPolicy: work.DigestPolicy})
		if !errors.Is(err, ports.ErrRetryable) {
			t.Fatalf("stale digest policy attempt=%v, want retryable refusal", err)
		}
		if attempts, err := f.repo.ListAttempts(f.ctx, f.tenant, page.Items[0].ID); err != nil || len(attempts) != 0 {
			t.Fatalf("attempts=%+v err=%v", attempts, err)
		}

		empty := newPostgresDigestFixture(t, pool, "digest-empty", notification.CadenceHourly)
		if err := WithTenant(empty.ctx, pool, empty.tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(empty.ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES('empty-engagement',$1,'Empty')`, empty.tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		empty.publish(t, "empty-event", "empty-engagement", notification.EventScanCompleted, shared.SeverityHigh)
		emptyAt := empty.at.Add(time.Minute)
		if _, err := empty.repo.PutEngagementNotificationSetting(empty.ctx, notification.EngagementNotificationSetting{TenantID: empty.tenant, EngagementID: "empty-engagement", ExternalNotifications: notification.EngagementNotificationsNone, Revision: 1, UpdatedAt: &emptyAt, UpdatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		if count, err := empty.materialize(empty.ctx, empty.at.Add(2*time.Hour), 10); err != nil || count != 1 {
			t.Fatalf("empty materialize=%d err=%v", count, err)
		}
		page, err = empty.repo.ListDeliveries(empty.ctx, ports.NotificationDeliveryFilter{TenantID: empty.tenant})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("empty digest deliveries=%+v err=%v", page, err)
		}
		var outcome string
		if err := WithTenant(empty.ctx, pool, empty.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(empty.ctx, `SELECT outcome FROM notification_digest_windows WHERE tenant_id=$1`, empty.tenant).Scan(&outcome)
		}); err != nil || outcome != "empty" {
			t.Fatalf("empty outcome=%q err=%v", outcome, err)
		}
	})
}

func TestNotificationPostgresDigestChannelTransitionsAndRuleHistory(t *testing.T) {
	pool := notificationTestPool(t)
	t.Run("channel transitions discard backlog and resume in a fresh chunk", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-transition", notification.CadenceHourly)
		f.publish(t, "before-disable", "", notification.EventScanCompleted, shared.SeverityHigh)

		channel := f.channel
		channel.Enabled, channel.Revision, channel.UpdatedAt = false, 2, f.at.Add(time.Minute)
		if _, err := f.repo.UpdateChannel(f.ctx, channel, "", false); err != nil {
			t.Fatal(err)
		}
		f.publish(t, "while-disabled", "", notification.EventScanCompleted, shared.SeverityHigh)
		channel.Enabled, channel.Revision, channel.UpdatedAt = true, 3, f.at.Add(2*time.Minute)
		if _, err := f.repo.UpdateChannel(f.ctx, channel, "", false); err != nil {
			t.Fatal(err)
		}
		f.publish(t, "after-enable", "", notification.EventScanCompleted, shared.SeverityHigh)

		channel.Revision, channel.UpdatedAt = 4, f.at.Add(3*time.Minute)
		if _, err := f.repo.UpdateChannel(f.ctx, channel, "replacement-secret", true); err != nil {
			t.Fatal(err)
		}
		f.publish(t, "after-replacement", "", notification.EventScanCompleted, shared.SeverityHigh)
		if _, err := f.repo.RecordChannelOutcome(f.ctx, f.tenant, ports.NotificationChannelOutcome{
			ChannelID: f.channel.ID, DeliveryID: "transition-delivery", AttemptID: "transition-attempt",
			Class: notification.AttemptPermanent, Code: "destination_blocked", At: f.at.Add(4 * time.Minute), Threshold: 1,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.ResumeChannel(f.ctx, f.tenant, f.channel.ID, 4, "admin", f.at.Add(5*time.Minute)); err != nil {
			t.Fatal(err)
		}
		f.publish(t, "after-resume", "", notification.EventScanCompleted, shared.SeverityHigh)

		var chunks []struct {
			chunk   int
			outcome string
		}
		if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(f.ctx, `SELECT chunk,outcome FROM notification_digest_windows WHERE tenant_id=$1 ORDER BY chunk`, f.tenant)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var row struct {
					chunk   int
					outcome string
				}
				if err := rows.Scan(&row.chunk, &row.outcome); err != nil {
					return err
				}
				chunks = append(chunks, row)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		if len(chunks) != 4 || chunks[0].outcome != "suppressed" || chunks[1].outcome != "suppressed" || chunks[2].outcome != "suppressed" || chunks[3].chunk != 3 || chunks[3].outcome != "pending" {
			t.Fatalf("digest chunks=%+v, want three suppressed then pending chunk 3", chunks)
		}
		if count, err := f.materialize(f.ctx, f.at.Add(2*time.Hour), 10); err != nil || count != 1 {
			t.Fatalf("materialize count=%d err=%v", count, err)
		}
	})

	t.Run("published history remains readable after rule deletion", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-rule-history", notification.CadenceHourly)
		f.publish(t, "history-source", "", notification.EventScanCompleted, shared.SeverityHigh)
		if count, err := f.materialize(f.ctx, f.at.Add(2*time.Hour), 10); err != nil || count != 1 {
			t.Fatalf("materialize count=%d err=%v", count, err)
		}
		page, err := f.repo.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("deliveries=%+v err=%v", page, err)
		}
		if err := f.repo.DeleteRule(f.ctx, f.tenant, f.rule.ID, f.rule.Revision); err != nil {
			t.Fatal(err)
		}
		if work, err := f.repo.LoadWork(f.ctx, f.tenant, page.Items[0].ID); err != nil || len(work.Event.DigestItems) != 1 {
			t.Fatalf("work=%+v err=%v", work, err)
		}
		if event, err := f.repo.GetNotificationEvent(f.ctx, f.tenant, page.Items[0].EventID); err != nil || len(event.DigestItems) != 1 {
			t.Fatalf("event=%+v err=%v", event, err)
		}
		if recent, err := f.repo.ListRecentNotificationEvents(f.ctx, f.tenant, notification.EventDigest, 1); err != nil || len(recent) != 1 || len(recent[0].DigestItems) != 0 {
			t.Fatalf("recent=%+v err=%v", recent, err)
		}
	})

	t.Run("deleted rule suppresses pending work", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-rule-pending", notification.CadenceHourly)
		f.publish(t, "pending-source", "", notification.EventScanCompleted, shared.SeverityHigh)
		if err := f.repo.DeleteRule(f.ctx, f.tenant, f.rule.ID, f.rule.Revision); err != nil {
			t.Fatal(err)
		}
		if count, err := f.materialize(f.ctx, f.at.Add(2*time.Hour), 10); err != nil || count != 1 {
			t.Fatalf("materialize count=%d err=%v", count, err)
		}
		var outcome string
		if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT outcome FROM notification_digest_windows WHERE tenant_id=$1`, f.tenant).Scan(&outcome)
		}); err != nil || outcome != "suppressed" {
			t.Fatalf("pending deleted rule outcome=%q err=%v", outcome, err)
		}
	})

	t.Run("publication materialization and channel transition do not deadlock", func(t *testing.T) {
		f := newPostgresDigestFixture(t, pool, "digest-contention", notification.CadenceHourly)
		f.publish(t, "contention-before", "", notification.EventScanCompleted, shared.SeverityHigh)
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		start := make(chan struct{})
		errs := make(chan error, 3)
		go func() {
			<-start
			event := notification.Event{TenantID: f.tenant, ID: "contention-source", Type: notification.EventScanCompleted, SourceKind: "digest-source", SourceID: "contention-source", Severity: shared.SeverityHigh, SchemaVersion: 1, OccurredAt: f.at, Data: json.RawMessage(`{"title":"contention"}`)}
			_, err := f.repo.Publish(ctx, event)
			errs <- err
		}()
		go func() {
			<-start
			channel := f.channel
			channel.Enabled, channel.Revision, channel.UpdatedAt = false, 2, f.at.Add(time.Minute)
			_, err := f.repo.UpdateChannel(ctx, channel, "", false)
			errs <- err
		}()
		go func() {
			<-start
			_, err := f.materialize(ctx, f.at.Add(2*time.Hour), 10)
			errs <- err
		}()
		close(start)
		for range 3 {
			if err := <-errs; err != nil {
				t.Fatalf("contention operation: %v", err)
			}
		}
		var pending int
		if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT count(*) FROM notification_digest_windows WHERE tenant_id=$1 AND outcome='pending'`, f.tenant).Scan(&pending)
		}); err != nil || pending != 0 {
			t.Fatalf("contention pending=%d err=%v, want none after disable", pending, err)
		}
	})
}

func TestNotificationPostgresDigestIndexesBoundAdmissionAndHydration(t *testing.T) {
	pool := notificationTestPool(t)
	f := newPostgresDigestFixture(t, pool, "digest-indexes", notification.CadenceHourly)
	f.publish(t, "index-source", "", notification.EventScanCompleted, shared.SeverityHigh)
	if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `SET LOCAL enable_seqscan=off`); err != nil {
			return err
		}
		assertPlanUses := func(query, index string, args ...any) error {
			rows, err := tx.Query(f.ctx, "EXPLAIN (COSTS OFF) "+query, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			var lines []string
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					return err
				}
				lines = append(lines, line)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if !strings.Contains(strings.Join(lines, "\n"), index) {
				return fmt.Errorf("plan does not use %s: %s", index, strings.Join(lines, "\n"))
			}
			return nil
		}
		if err := assertPlanUses(`SELECT chunk FROM notification_digest_members WHERE tenant_id=$1 AND rule_id=$2 AND channel_id=$3 AND cadence=$4 AND window_start=$5 ORDER BY chunk DESC LIMIT 1`, "notification_digest_members_tail", f.tenant, f.rule.ID, f.channel.ID, f.rule.Cadence, f.at.Truncate(time.Hour)); err != nil {
			return err
		}
		return assertPlanUses(`SELECT rule_id FROM notification_digest_windows WHERE tenant_id=$1 AND outcome='pending' AND window_end<=$2 ORDER BY window_end,window_start,rule_id,channel_id,cadence,chunk LIMIT 1`, "notification_digest_windows_pending_due", f.tenant, f.at.Add(2*time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	if count, err := f.materialize(f.ctx, f.at.Add(2*time.Hour), 1); err != nil || count != 1 {
		t.Fatalf("materialize count=%d err=%v", count, err)
	}
	page, err := f.repo.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("deliveries=%+v err=%v", page, err)
	}
	if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `SET LOCAL enable_seqscan=off`); err != nil {
			return err
		}
		rows, err := tx.Query(f.ctx, `EXPLAIN (COSTS OFF) SELECT rule_id FROM notification_digest_windows WHERE tenant_id=$1 AND event_id=$2`, f.tenant, page.Items[0].EventID)
		if err != nil {
			return err
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			lines = append(lines, line)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if !strings.Contains(strings.Join(lines, "\n"), "notification_digest_windows_event") {
			return fmt.Errorf("plan does not use event lookup index: %s", strings.Join(lines, "\n"))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationPostgresDigestTablesEnforceTenantRLS(t *testing.T) {
	pool := notificationTestPool(t)
	a := newPostgresDigestFixture(t, pool, "digest-rls-a", notification.CadenceHourly)
	b := newPostgresDigestFixture(t, pool, "digest-rls-b", notification.CadenceHourly)
	a.publish(t, "rls-event-a", "", notification.EventScanCompleted, shared.SeverityHigh)
	b.publish(t, "rls-event-b", "", notification.EventScanCompleted, shared.SeverityHigh)

	var window digestWindow
	if err := WithTenant(b.ctx, pool, b.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(b.ctx, `SELECT rule_id,channel_id,cadence,window_start,window_end,chunk
			FROM notification_digest_windows WHERE tenant_id=$1 AND outcome='pending'`, b.tenant).
			Scan(&window.ruleID, &window.channelID, &window.cadence, &window.start, &window.end, &window.chunk)
	}); err != nil {
		t.Fatal(err)
	}
	var superuser, bypass bool
	if err := pool.QueryRow(context.Background(), `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&superuser, &bypass); err != nil {
		t.Fatal(err)
	}
	role := ""
	if superuser {
		role = fmt.Sprintf("digest_rls_%d", time.Now().UnixNano())
		if _, err := pool.Exec(context.Background(), `CREATE ROLE `+role+` NOSUPERUSER NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role+`; DROP ROLE `+role) })
		for _, grant := range []string{
			`GRANT USAGE ON SCHEMA public TO ` + role,
			`GRANT SELECT,INSERT ON notification_digest_members,notification_digest_windows TO ` + role,
		} {
			if _, err := pool.Exec(context.Background(), grant); err != nil {
				t.Fatal(err)
			}
		}
	} else if bypass {
		t.Fatal("test database runtime role bypasses RLS")
	}
	underRole := func(tenant *shared.ID, fn func(pgx.Tx) error) error {
		tx, err := pool.Begin(context.Background())
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if tenant != nil {
			if _, err := tx.Exec(context.Background(), `SELECT set_config('app.current_tenant',$1,true)`, tenant.String()); err != nil {
				return err
			}
		}
		if role != "" {
			if _, err := tx.Exec(context.Background(), `SET LOCAL ROLE `+role); err != nil {
				return err
			}
		}
		return fn(tx)
	}
	for _, table := range []string{"notification_digest_members", "notification_digest_windows"} {
		for _, tenant := range []*shared.ID{&a.tenant, &b.tenant, nil} {
			var count int
			if err := underRole(tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, a.tenant).Scan(&count)
			}); err != nil {
				t.Fatal(err)
			}
			want := 0
			if tenant != nil && *tenant == a.tenant {
				want = 1
			}
			if count != want {
				t.Fatalf("%s tenant=%v count=%d, want %d", table, tenant, count, want)
			}
		}
	}
	if err := underRole(&a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO notification_digest_members(tenant_id,rule_id,channel_id,cadence,window_start,window_end,chunk,event_id)
			VALUES($1,$2,$3,$4,$5,$6,99,'rls-event-b')`, b.tenant, window.ruleID, window.channelID, window.cadence, window.start, window.end)
		return err
	}); err == nil {
		t.Fatal("tenant A runtime role inserted tenant B digest member")
	}
	if err := underRole(&a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO notification_digest_windows(tenant_id,rule_id,channel_id,cadence,window_start,window_end,chunk,outcome)
			VALUES($1,$2,$3,$4,$5,$6,99,'pending')`, b.tenant, window.ruleID, window.channelID, window.cadence, window.start, window.end)
		return err
	}); err == nil {
		t.Fatal("tenant A runtime role inserted tenant B digest window")
	}
}
