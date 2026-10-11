package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNotificationLifecycleRiskAcceptanceThresholdsAndBaseline(t *testing.T) {
	pool := notificationTestPool(t)
	base := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	ctx := shared.WithTenant(context.Background(), "lifecycle-a")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('lifecycle-a','A'),('lifecycle-b','B')`); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	// The first poll establishes the tenant baseline before the live acceptance is written.
	if _, err := source.Poll(ctx, base, 100); err != nil {
		t.Fatal(err)
	}
	seedLifecycleAcceptance(t, pool, ctx, "lifecycle-a", "live", base.Add(time.Minute), base.Add(3*time.Hour))
	insertLifecycleRule(t, pool, ctx, "lifecycle-a", "live-expiring", notification.EventRiskAcceptanceExpiring, 3600)
	if _, err := source.Poll(ctx, base.Add(2*time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, base.Add(2*time.Hour).Add(time.Microsecond), 100); err != nil {
		t.Fatal(err)
	}
	assertLifecycleEvent(t, pool, "lifecycle-a", notification.EventRiskAcceptanceExpiring, base.Add(2*time.Hour))
	if _, err := source.Poll(ctx, base.Add(3*time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, base.Add(3*time.Hour).Add(time.Microsecond), 100); err != nil {
		t.Fatal(err)
	}
	assertLifecycleEvent(t, pool, "lifecycle-a", notification.EventRiskAcceptanceExpired, base.Add(3*time.Hour))
	if _, err := source.Poll(ctx, base.Add(3*time.Hour).Add(time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	var expired int
	if err := WithTenant(ctx, pool, "lifecycle-a", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE tenant_id='lifecycle-a' AND event_type='risk_acceptance.expired'`).Scan(&expired)
	}); err != nil || expired != 1 {
		t.Fatalf("expired event count=%d err=%v", expired, err)
	}

	// A threshold that already held strictly before activation is state-baselined and never
	// produces a historical expiry page.
	other := shared.WithTenant(context.Background(), "lifecycle-b")
	seedLifecycleAcceptance(t, pool, other, "lifecycle-b", "historic", base.Add(-2*time.Hour), base.Add(30*time.Minute))
	insertLifecycleRule(t, pool, other, "lifecycle-b", "historic-expiring", notification.EventRiskAcceptanceExpiring, 3600)
	if _, err := source.Poll(other, base, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(other, base.Add(time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	var historic int
	if err := WithTenant(other, pool, "lifecycle-b", func(tx pgx.Tx) error {
		return tx.QueryRow(other, `SELECT count(*) FROM notification_events WHERE tenant_id='lifecycle-b' AND event_type IN ('risk_acceptance.expiring','risk_acceptance.expired')`).Scan(&historic)
	}); err != nil || historic != 0 {
		t.Fatalf("historic lifecycle events=%d err=%v", historic, err)
	}

	// A threshold equal to activation is a live boundary, rather than history.
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('lifecycle-c','C')`); err != nil {
		t.Fatal(err)
	}
	equal := shared.WithTenant(context.Background(), "lifecycle-c")
	seedLifecycleAcceptance(t, pool, equal, "lifecycle-c", "equal", base.Add(-time.Hour), base.Add(30*time.Minute))
	insertLifecycleRule(t, pool, equal, "lifecycle-c", "equal-expiring", notification.EventRiskAcceptanceExpiring, 1800)
	if _, err := source.Poll(equal, base, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(equal, base.Add(time.Microsecond), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(equal, base.Add(2*time.Microsecond), 100); err != nil {
		t.Fatal(err)
	}
	assertLifecycleEvent(t, pool, "lifecycle-c", notification.EventRiskAcceptanceExpiring, base)
	if err := WithTenant(equal, pool, "lifecycle-c", func(tx pgx.Tx) error {
		var leadHours string
		if err := tx.QueryRow(equal, `SELECT context->'vars'->>'lead_time_hours' FROM notification_source_records WHERE tenant_id='lifecycle-c' AND source_kind='risk_acceptance_expiring' AND source_id='acceptance-equal:1800'`).Scan(&leadHours); err != nil {
			return err
		}
		if leadHours != "0.5" {
			t.Fatalf("lead_time_hours=%q, want 0.5", leadHours)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSLAStoreAcceptedRiskCapturesSnapshotAndUsesCAS(t *testing.T) {
	pool := notificationTestPool(t)
	base := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	tenant := shared.ID("lifecycle-transition")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'transition')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, base, 100); err != nil {
		t.Fatal(err)
	}
	seedOpenLifecycle(t, pool, ctx, tenant.String(), "transition", base)

	current := sla.Lifecycle{
		TenantID: tenant, EngagementID: "eng-transition", FindingID: "finding-transition", AssessmentID: "assessment-transition",
		Status: sla.RemediationOpen, Version: 1, UpdatedBy: "operator", UpdatedAt: base,
	}
	expires := base.Add(24 * time.Hour)
	next, event, err := sla.ApplyTransition(current, "acceptance-transition", sla.TransitionCommand{
		To: sla.RemediationAcceptedRisk, Reason: "approved", CompensatingControl: "documented control",
		AcceptanceExpiresAt: &expires, Actor: "operator", ExpectedVersion: 1,
	}, base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	store := NewSLAStore(pool)
	if err := store.SaveTransition(ctx, next, event); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, base.Add(2*time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTransition(ctx, next, event); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale transition error=%v, want conflict", err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var version int
		var subject string
		if err := tx.QueryRow(ctx, `SELECT capture_version,subject_id FROM notification_source_records WHERE tenant_id=$1 AND source_kind='risk_acceptance_created' AND source_id=$2`, tenant, event.ID).Scan(&version, &subject); err != nil {
			return err
		}
		if version != 3 || subject != current.FindingID.String() {
			t.Fatalf("snapshot capture_version=%d subject=%q", version, subject)
		}
		var events int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sla_lifecycle_events WHERE tenant_id=$1 AND id=$2`, tenant, event.ID).Scan(&events); err != nil {
			return err
		}
		if events != 1 {
			t.Fatalf("lifecycle event count=%d", events)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	events, err := repo.ListRecentNotificationEvents(ctx, tenant, notification.EventRiskAcceptanceCreated, 1)
	if err != nil || len(events) != 1 {
		t.Fatalf("published risk acceptance events=%d err=%v", len(events), err)
	}
	assertPublishedEventSchema(t, events[0])
}

func TestNotificationLifecycleRiskThresholdSkipsObservedRowsBeforeLimit(t *testing.T) {
	pool := notificationTestPool(t)
	base := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	tenant := "lifecycle-fairness"
	ctx := shared.WithTenant(context.Background(), shared.ID(tenant))
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'fairness')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, base, 100); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 65; i++ {
		key := fmt.Sprintf("old-%03d", i)
		seedLifecycleAcceptance(t, pool, ctx, tenant, key, base.Add(time.Minute), base.Add(2*time.Hour))
	}
	seedLifecycleAcceptance(t, pool, ctx, tenant, "zz-fresh", base.Add(time.Minute), base.Add(2*time.Hour))
	insertLifecycleRule(t, pool, ctx, tenant, "fair-expiring", notification.EventRiskAcceptanceExpiring, 3600)
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		for i := 0; i < 65; i++ {
			key := fmt.Sprintf("acceptance-old-%03d:3600", i)
			if err := upsertLifecycleState(ctx, tx, shared.ID(tenant), riskExpiringStateKind, key, "observed", true, base); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, base.Add(time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	var captured int
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind='risk_acceptance_expiring' AND source_id='acceptance-zz-fresh:3600'`, tenant).Scan(&captured)
	}); err != nil || captured != 1 {
		t.Fatalf("fresh threshold captures=%d err=%v", captured, err)
	}
}

func TestNotificationLifecycleSLABreachCatchupAndExpiryReentry(t *testing.T) {
	pool := notificationTestPool(t)
	base := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	tenant := shared.ID("lifecycle-breach")
	ctx := shared.WithTenant(context.Background(), tenant)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'breach')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if err := source.SetSLABreachMaxReminders(2); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, base, 100); err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	service, err := notificationuc.NewService(repo, cipher, nil, NewAuditLog(pool), &notificationTestClock{base}, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	service.SetTransactionRunner(NewTenantTransactionRunner(pool))
	channel, err := service.CreateChannel(ctx, "operator", notificationuc.ChannelInput{Name: "Breach receiver", Type: notification.ChannelWebhook, Enabled: true, URL: "https://example.com/events", Secret: "1234567890abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateRule(ctx, "operator", notificationuc.RuleInput{Name: "All breached findings", EventType: notification.EventSLABreached, Enabled: true, AllTeams: true, ChannelIDs: []shared.ID{channel.ID}}); err != nil {
		t.Fatal(err)
	}
	deadline := base.Add(time.Hour)
	seedOpenLifecycleWithDeadline(t, pool, ctx, tenant.String(), "breach", base.Add(time.Minute), deadline)
	if _, err := source.Poll(ctx, deadline, 100); err != nil {
		t.Fatal(err)
	}
	key := "finding-breach:" + strconv.FormatInt(deadline.UnixMicro(), 10)
	assertSourceRecord(t, pool, ctx, tenant.String(), "sla_breach_episode", key+":1:0", deadline)
	if _, err := source.Poll(ctx, deadline.Add(3*24*time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	// Downtime emits the latest due ordinal once, capped by configuration.
	assertSourceRecord(t, pool, ctx, tenant.String(), "sla_breach_episode", key+":1:2", deadline.Add(2*24*time.Hour))

	current := sla.Lifecycle{TenantID: tenant, EngagementID: "eng-breach", FindingID: "finding-breach", AssessmentID: "assessment-breach", Status: sla.RemediationOpen, Version: 1, UpdatedBy: "operator", UpdatedAt: base.Add(time.Minute)}
	acceptedAt := deadline.Add(3 * 24 * time.Hour)
	expires := acceptedAt.Add(time.Hour)
	next, event, err := sla.ApplyTransition(current, "acceptance-breach", sla.TransitionCommand{To: sla.RemediationAcceptedRisk, Reason: "approved", CompensatingControl: "control", AcceptanceExpiresAt: &expires, Actor: "operator", ExpectedVersion: 1}, acceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewSLAStore(pool).SaveTransition(ctx, next, event); err != nil {
		t.Fatal(err)
	}
	var active bool
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT active FROM notification_source_state WHERE tenant_id=$1 AND source_kind='sla_breach' AND source_id=$2`, tenant, key).Scan(&active)
	}); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("accepted risk did not close the active SLA breach episode")
	}
	if _, err := source.Poll(ctx, expires, 100); err != nil {
		t.Fatal(err)
	}
	assertSourceRecord(t, pool, ctx, tenant.String(), "sla_breach_episode", key+":2:0", expires)
	if _, err := source.Poll(ctx, expires.Add(time.Microsecond), 100); err != nil {
		t.Fatal(err)
	}
	events, err := repo.ListRecentNotificationEvents(ctx, tenant, notification.EventSLABreached, 10)
	if err != nil || len(events) != 3 {
		t.Fatalf("breach events=%d err=%v", len(events), err)
	}
	for _, event := range events {
		assertPublishedEventSchema(t, event)
	}
	var deliveries int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE tenant_id=$1 AND channel_id=$2`, tenant, channel.ID).Scan(&deliveries)
	}); err != nil || deliveries != 3 {
		t.Fatalf("unassigned lifecycle deliveries=%d err=%v", deliveries, err)
	}
}

func seedLifecycleAcceptance(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tenant, key string, accepted, expiry time.Time) {
	t.Helper()
	eng, finding, assessment, acceptance := "eng-"+key, "finding-"+key, "assessment-"+key, "acceptance-"+key
	err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		exec := func(query string, args ...any) error { _, err := tx.Exec(ctx, query, args...); return err }
		for _, call := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$3)`, []any{eng, tenant, "Engagement " + key}},
			{`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,$2,$3,$4)`, []any{finding, tenant, eng, "Finding " + key}},
			{`INSERT INTO sla_policies(tenant_id,config_version,config,sha256,created_by,created_at) VALUES($1,'v1','{}',repeat('b',64),'operator',$2) ON CONFLICT (tenant_id,config_version) DO NOTHING`, []any{tenant, accepted}},
			{`INSERT INTO sla_assessments(tenant_id,id,engagement_id,finding_id,inputs,result,input_hash,config_hash,config_version,tier,score,mitigate_by,remediate_by,deadline_anchor_at,assessed_at,created_at) VALUES($1,$2,$3,$4,'{}','{}',repeat('a',64),repeat('b',64),'v1','high',1,$5,$6,$5,$5,$5)`, []any{tenant, assessment, eng, finding, accepted, accepted.Add(7 * 24 * time.Hour)}},
			{`INSERT INTO sla_current_assessments(tenant_id,engagement_id,finding_id,assessment_id,updated_at) VALUES($1,$2,$3,$4,$5)`, []any{tenant, eng, finding, assessment, accepted}},
			{`INSERT INTO sla_lifecycles(tenant_id,engagement_id,finding_id,assessment_id,status,version,reason,compensating_control,accepted_by,accepted_at,acceptance_expires_at,updated_by,updated_at) VALUES($1,$2,$3,$4,'accepted_risk',2,'approved','control','operator',$5,$6,'operator',$5)`, []any{tenant, eng, finding, assessment, accepted, expiry}},
			{`INSERT INTO sla_lifecycle_events(tenant_id,id,engagement_id,finding_id,assessment_id,from_status,to_status,reason,compensating_control,acceptance_expires_at,actor,before_version,after_version,occurred_at) VALUES($1,$2,$3,$4,$5,'open','accepted_risk','approved','control',$6,'operator',1,2,$7)`, []any{tenant, acceptance, eng, finding, assessment, expiry, accepted}},
		} {
			if err := exec(call.query, call.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func seedOpenLifecycle(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tenant, key string, at time.Time) {
	seedOpenLifecycleWithDeadline(t, pool, ctx, tenant, key, at, at.Add(7*24*time.Hour))
}

func seedOpenLifecycleWithDeadline(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tenant, key string, at, deadline time.Time) {
	t.Helper()
	eng, finding, assessment := "eng-"+key, "finding-"+key, "assessment-"+key
	err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		exec := func(query string, args ...any) error { _, err := tx.Exec(ctx, query, args...); return err }
		for _, call := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$3)`, []any{eng, tenant, "Engagement " + key}},
			{`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,$2,$3,$4)`, []any{finding, tenant, eng, "Finding " + key}},
			{`INSERT INTO sla_policies(tenant_id,config_version,config,sha256,created_by,created_at) VALUES($1,'v1','{}',repeat('b',64),'operator',$2) ON CONFLICT DO NOTHING`, []any{tenant, at}},
			{`INSERT INTO sla_assessments(tenant_id,id,engagement_id,finding_id,inputs,result,input_hash,config_hash,config_version,tier,score,mitigate_by,remediate_by,deadline_anchor_at,assessed_at,created_at) VALUES($1,$2,$3,$4,'{}','{}',repeat('a',64),repeat('b',64),'v1','high',1,$5,$6,$5,$5,$5)`, []any{tenant, assessment, eng, finding, at, deadline}},
			{`INSERT INTO sla_current_assessments(tenant_id,engagement_id,finding_id,assessment_id,updated_at) VALUES($1,$2,$3,$4,$5)`, []any{tenant, eng, finding, assessment, at}},
			{`INSERT INTO sla_lifecycles(tenant_id,engagement_id,finding_id,assessment_id,status,version,updated_by,updated_at) VALUES($1,$2,$3,$4,'open',1,'operator',$5)`, []any{tenant, eng, finding, assessment, at}},
		} {
			if err := exec(call.query, call.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertSourceRecord(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tenant, kind, source string, want time.Time) {
	t.Helper()
	var got time.Time
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT occurred_at FROM notification_source_records WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, kind, source).Scan(&got)
	}); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("%s/%s occurred_at=%s want %s", kind, source, got, want)
	}
}

func insertLifecycleRule(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tenant, id string, event notification.EventType, lead int64) {
	t.Helper()
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,lead_time_secs,created_at,updated_at) VALUES($1,$2,$2,true,$3,$4,now(),now())`, tenant, id, event, lead)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func assertLifecycleEvent(t *testing.T, pool *pgxpool.Pool, tenant string, event notification.EventType, want time.Time) {
	t.Helper()
	var got time.Time
	ctx := shared.WithTenant(context.Background(), shared.ID(tenant))
	if err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT occurred_at FROM notification_events WHERE tenant_id=$1 AND event_type=$2`, tenant, event).Scan(&got)
	}); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("%s occurred_at=%s want %s", event, got, want)
	}
}
