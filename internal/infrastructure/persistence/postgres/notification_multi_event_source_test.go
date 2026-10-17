package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

func TestNotificationMultiEventSecondaryWindowLeadIsScheduledAndTenantScoped(t *testing.T) {
	pool := notificationTestPool(t)
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	activeTenant, disabledTenant := shared.ID("multi-window-active"), shared.ID("multi-window-disabled")
	activeCtx := shared.WithTenant(context.Background(), activeTenant)
	disabledCtx := shared.WithTenant(context.Background(), disabledTenant)
	if _, err := pool.Exec(activeCtx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, activeTenant, disabledTenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(activeCtx, now, 100); err != nil { // activation baseline for both tenants
		t.Fatal(err)
	}

	for _, item := range []struct {
		tenant  shared.ID
		ctx     context.Context
		enabled bool
		id      string
	}{
		{activeTenant, activeCtx, true, "secondary-window-active"},
		{disabledTenant, disabledCtx, false, "secondary-window-disabled"},
	} {
		windowExec(t, item.ctx, pool, item.tenant, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,event_types,lead_time_secs,created_at,updated_at)
			VALUES($1,$2,$2,$3,$4,ARRAY[$4::text,$5::text],3600,$6,$6)`, item.tenant, item.id, item.enabled, notification.EventEngagementWindowStarting, notification.EventEngagementWindowEnding, now)
		boundary := now.Add(time.Hour)
		e, err := engagement.New(shared.ID(item.id), item.tenant, item.id, "", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.SetAuthorizationWindow(nil, &boundary, "UTC", now); err != nil {
			t.Fatal(err)
		}
		if err := NewEngagementRepository(pool).Create(item.ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := source.Poll(activeCtx, now, 100); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		tenant shared.ID
		ctx    context.Context
		want   int
	}{
		{activeTenant, activeCtx, 1},
		{disabledTenant, disabledCtx, 0},
	} {
		got := windowCount(t, item.ctx, pool, item.tenant, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, item.tenant, notification.EventEngagementWindowEnding)
		if got != item.want {
			t.Fatalf("tenant %s secondary ending records=%d, want %d", item.tenant, got, item.want)
		}
	}
	if _, err := source.Poll(activeCtx, now.Add(time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	if got := windowCount(t, activeCtx, pool, activeTenant, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND event_type=$2`, activeTenant, notification.EventEngagementWindowEnding); got != 1 {
		t.Fatalf("secondary ending replay records=%d, want 1", got)
	}
}

func TestNotificationRuleLeadsIncludesSecondarySelectionsForEveryScheduler(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("multi-lead-query")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		id        string
		secondary notification.EventType
		lead      int64
		enabled   bool
	}{
		{"secondary-window", notification.EventEngagementWindowEnding, 3600, true},
		{"secondary-sla", notification.EventSLAApproaching, 7200, true},
		// This is a selector query test. The domain rejects this particular mixed set because
		// risk acceptance requires team scope while engagement windows do not support it.
		{"secondary-risk-query", notification.EventRiskAcceptanceExpiring, 10800, true},
		{"disabled-window", notification.EventEngagementWindowEnding, 14400, false},
	} {
		windowExec(t, ctx, pool, tenant, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,event_types,lead_time_secs,created_at,updated_at)
			VALUES($1,$2,$2,$3,$4,ARRAY[$4::text,$5::text],$6,$7,$7)`, tenant, item.id, item.enabled, notification.EventEngagementWindowStarting, item.secondary, item.lead, now)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for event, want := range map[notification.EventType]int64{
			notification.EventEngagementWindowEnding: 3600,
			notification.EventSLAApproaching:         7200,
			notification.EventRiskAcceptanceExpiring: 10800,
		} {
			leads, err := notificationRuleLeads(ctx, tx, tenant, event)
			if err != nil {
				return err
			}
			if len(leads) != 1 || leads[0] != want {
				t.Errorf("%s leads = %v, want [%d]", event, leads, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
