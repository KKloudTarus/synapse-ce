package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

func TestNotificationEngagementWindowPollsInclusiveLeadAndNullableOppositeBound(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("window-source")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$1)", tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 100); err != nil { // activation baseline
		t.Fatal(err)
	}
	windowExec(t, ctx, pool, tenant, "INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,lead_time_secs,created_at,updated_at) VALUES($1,'start-window','start',true,$2,3600,$3,$3)", tenant, notification.EventEngagementWindowStarting, now)
	from := now.Add(time.Hour) // inclusive threshold: from - lead == now
	e, err := engagement.New("window-null-end", tenant, "DST-safe UTC", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetAuthorizationWindow(&from, nil, "America/New_York", now); err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, now, 100); err != nil {
		t.Fatal(err)
	}
	count := windowCount(t, ctx, pool, tenant, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2", tenant, notification.EventEngagementWindowStarting)
	if count != 1 {
		t.Fatalf("inclusive window records=%d", count)
	}
	if _, err := source.Poll(ctx, now.Add(time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	count = windowCount(t, ctx, pool, tenant, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2", tenant, notification.EventEngagementWindowStarting)
	if count != 1 {
		t.Fatalf("restart dedupe records=%d", count)
	}
	windowExec(t, ctx, pool, tenant, "UPDATE engagements SET authorized_from=$3 WHERE tenant_id=$1 AND id=$2", tenant, e.ID, now)
	if _, err := source.Poll(ctx, now, 100); err != nil {
		t.Fatal(err)
	}
	count = windowCount(t, ctx, pool, tenant, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2", tenant, notification.EventEngagementWindowStarting)
	if count != 1 {
		t.Fatalf("actual-boundary exclusion records=%d", count)
	}
}

func TestNotificationEngagementWindowFreshRescheduleRelevanceAndHiddenContexts(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("window-fresh")
	ctx := shared.WithTenant(context.Background(), tenant)
	activated := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$1)", tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, activated, 100); err != nil {
		t.Fatal(err)
	}
	windowExec(t, ctx, pool, tenant, "INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,lead_time_secs,created_at,updated_at) VALUES($1,'fresh-start','fresh',true,$2,3600,$3,$3)", tenant, notification.EventEngagementWindowStarting, activated)
	created := activated.Add(5 * time.Minute)
	oldBoundary := activated.Add(30 * time.Minute) // threshold was before activation.
	e, err := engagement.New("fresh-window", tenant, "Fresh", "", created)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetAuthorizationWindow(&oldBoundary, nil, "Asia/Ho_Chi_Minh", created); err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(ctx, created, 100); err != nil {
		t.Fatal(err)
	}
	count := windowCount(t, ctx, pool, tenant, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2", tenant, notification.EventEngagementWindowStarting)
	if count != 1 {
		t.Fatalf("fresh post-activation warning count=%d", count)
	}
	newBoundary := activated.Add(35 * time.Minute)
	rescheduled := created.Add(time.Minute)
	windowExec(t, ctx, pool, tenant, "UPDATE engagements SET authorized_from=$3,updated_at=$4 WHERE tenant_id=$1 AND id=$2", tenant, e.ID, newBoundary, rescheduled)
	if _, err := source.Poll(ctx, rescheduled, 100); err != nil {
		t.Fatal(err)
	}
	count = windowCount(t, ctx, pool, tenant, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2", tenant, notification.EventEngagementWindowStarting)
	if count != 2 {
		t.Fatalf("rescheduled warning count=%d", count)
	}
	if current, err := repo.WindowStillCurrent(ctx, tenant, e.ID, notification.EventEngagementWindowStarting, oldBoundary); err != nil || current {
		t.Fatalf("obsolete boundary relevance=%v err=%v", current, err)
	}
	if current, err := repo.WindowStillCurrent(ctx, tenant, e.ID, notification.EventEngagementWindowStarting, newBoundary); err != nil || !current {
		t.Fatalf("current boundary relevance=%v err=%v", current, err)
	}
	// Internal Project contexts must not be observable by the window query.
	windowExec(t, ctx, pool, tenant, `INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES('hidden-project',$1,'Internal','hidden','{}')`, tenant)
	windowExec(t, ctx, pool, tenant, `UPDATE engagements SET project_id='hidden-project',authorized_from=$3,updated_at=$4 WHERE tenant_id=$1 AND id=$2`, tenant, e.ID, newBoundary.Add(time.Minute), rescheduled.Add(time.Minute))
	if _, err := source.Poll(ctx, rescheduled.Add(time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	count = windowCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventEngagementWindowStarting)
	if count != 2 {
		t.Fatalf("hidden context emitted warning=%d", count)
	}
}

func TestEngagementWindowSourceIdentityUsesUTCThroughRepeatedWallClockHour(t *testing.T) {
	beforeFallBack := time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("EDT", -4*3600))
	afterFallBack := time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("EST", -5*3600))
	first := engagementWindowStateID("engagement", beforeFallBack, 3600)
	if first != engagementWindowStateID("engagement", beforeFallBack.UTC(), 3600) {
		t.Fatal("same UTC instant has different source identity")
	}
	if first == engagementWindowStateID("engagement", afterFallBack, 3600) {
		t.Fatal("repeated wall clock hours collapsed distinct boundaries")
	}
	if afterFallBack.Sub(beforeFallBack) != time.Hour {
		t.Fatal("DST boundary fixture is not an elapsed hour")
	}
}

func TestNotificationEngagementWindowsShareSmallPollQuotaFairly(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("window-quota")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$1)", tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 1); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []struct {
		id    string
		event notification.EventType
	}{
		{"quota-start", notification.EventEngagementWindowStarting},
		{"quota-end", notification.EventEngagementWindowEnding},
	} {
		windowExec(t, ctx, pool, tenant, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,lead_time_secs,created_at,updated_at)
			VALUES($1,$2,$2,true,$3,3600,$4,$4)`, tenant, rule.id, rule.event, now)
	}
	start := now.Add(time.Hour)
	starting, err := engagement.New("quota-starting", tenant, "Starting", "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := starting.SetAuthorizationWindow(&start, nil, "UTC", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ending, err := engagement.New("quota-ending", tenant, "Ending", "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := ending.SetAuthorizationWindow(nil, &start, "UTC", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	engagements := NewEngagementRepository(pool)
	for _, item := range []*engagement.Engagement{starting, ending} {
		if err := engagements.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
	}

	if count, err := source.Poll(ctx, now.Add(time.Minute), 1); err != nil || count != 1 {
		t.Fatalf("first quota poll count=%d err=%v", count, err)
	}
	if count, err := source.Poll(ctx, now.Add(2*time.Minute), 1); err != nil || count != 1 {
		t.Fatalf("second quota poll count=%d err=%v", count, err)
	}
	if count := windowCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventEngagementWindowStarting); count != 1 {
		t.Fatalf("starting notifications=%d", count)
	}
	if count := windowCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventEngagementWindowEnding); count != 1 {
		t.Fatalf("ending notifications=%d", count)
	}
}

func TestNotificationEngagementWindowConcurrentPollsReplayOnce(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("window-concurrent")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$1)", tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	windowExec(t, ctx, pool, tenant, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,lead_time_secs,created_at,updated_at)
		VALUES($1,'concurrent-start','Concurrent',true,$2,3600,$3,$3)`, tenant, notification.EventEngagementWindowStarting, now)
	boundary := now.Add(time.Hour)
	item, err := engagement.New("concurrent-window", tenant, "Concurrent", "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetAuthorizationWindow(&boundary, nil, "UTC", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, item); err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := source.Poll(ctx, now.Add(time.Minute), 10)
			errs <- err
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent poll: %v", err)
		}
	}
	if count := windowCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventEngagementWindowStarting); count != 1 {
		t.Fatalf("concurrent source records=%d", count)
	}
	if _, err := source.Poll(ctx, now.Add(2*time.Minute), 10); err != nil {
		t.Fatal(err)
	}
	if count := windowCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventEngagementWindowStarting); count != 1 {
		t.Fatalf("restart replay source records=%d", count)
	}
}

func TestNotificationEngagementWindowDSTBoundariesKeepActualUTCInstants(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("window-dst")
	ctx := shared.WithTenant(context.Background(), tenant)
	activated := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$1)", tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, activated, 10); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []struct {
		id    string
		event notification.EventType
	}{
		{"dst-start", notification.EventEngagementWindowStarting},
		{"dst-end", notification.EventEngagementWindowEnding},
	} {
		windowExec(t, ctx, pool, tenant, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,lead_time_secs,created_at,updated_at)
			VALUES($1,$2,$2,true,$3,3600,$4,$4)`, tenant, rule.id, rule.event, activated)
	}
	beforeFallBack := time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("EDT", -4*3600))
	afterFallBack := time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("EST", -5*3600))
	created := activated.Add(10 * time.Minute)
	starting, err := engagement.New("dst-starting", tenant, "DST start", "", created)
	if err != nil {
		t.Fatal(err)
	}
	if err := starting.SetAuthorizationWindow(&beforeFallBack, nil, "America/New_York", created); err != nil {
		t.Fatal(err)
	}
	ending, err := engagement.New("dst-ending", tenant, "DST end", "", created)
	if err != nil {
		t.Fatal(err)
	}
	if err := ending.SetAuthorizationWindow(nil, &afterFallBack, "America/New_York", created); err != nil {
		t.Fatal(err)
	}
	engagements := NewEngagementRepository(pool)
	for _, item := range []*engagement.Engagement{starting, ending} {
		if err := engagements.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := source.Poll(ctx, time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC), 10); err != nil {
		t.Fatal(err)
	}
	windowOccurredAt(t, ctx, pool, tenant, notification.EventEngagementWindowStarting, starting.ID, beforeFallBack.Add(-time.Hour).UTC())
	if _, err := source.Poll(ctx, time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC), 10); err != nil {
		t.Fatal(err)
	}
	windowOccurredAt(t, ctx, pool, tenant, notification.EventEngagementWindowEnding, ending.ID, afterFallBack.Add(-time.Hour).UTC())
}

func windowExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, query string, args ...any) {
	t.Helper()
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, args...)
		return err
	}); err != nil {
		t.Fatalf("tenant fixture write: %v", err)
	}
}

func windowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, query string, args ...any) int {
	t.Helper()
	var count int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(&count)
	}); err != nil {
		t.Fatalf("tenant fixture count: %v", err)
	}
	return count
}

func windowOccurredAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, event notification.EventType, engagementID shared.ID, want time.Time) {
	t.Helper()
	var got time.Time
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT occurred_at FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2 AND engagement_id=$3`, tenant, event, engagementID).Scan(&got)
	}); err != nil {
		t.Fatalf("load %s source record: %v", event, err)
	}
	if !got.Equal(want) {
		t.Fatalf("%s occurred_at=%s want %s", event, got, want)
	}
}
