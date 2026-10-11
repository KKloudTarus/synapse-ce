package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPersonalInboxProjectsAssigneeAndDoesNotResurrect(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("inbox")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('inbox','Inbox')`); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, query, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	countOf := func(query string) int {
		t.Helper()
		var count int
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, query).Scan(&count)
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('ada','Ada','admin','hash-ada','inbox',false),('gone','Gone','admin','hash-gone','inbox',true)`)
	prefs, err := NewInboxStore(pool).ListInboxPreferences(ctx, tenant, "ada")
	if err != nil {
		t.Fatal(err)
	}
	for _, pref := range prefs {
		available := notification.PersonalDeliveryAvailable(notification.EventType(pref.EventType)) && pref.Channel != "slack" && pref.Channel != "teams"
		if pref.Available != available {
			t.Fatalf("preference %s/%s available=%v, want %v", pref.EventType, pref.Channel, pref.Available, available)
		}
	}
	data, _ := json.Marshal(notification.OwnershipChanged{DecisionID: "decision", FindingID: "finding", EngagementID: "eng", NewAssigneeID: "ada", OldAssigneeID: "gone"})
	repo := NewNotificationRepository(pool)
	event := notification.Event{TenantID: tenant, ID: "event-1", Type: notification.EventOwnershipChanged, SourceKind: "ownership_decision", SourceID: "decision", EngagementID: "eng", SchemaVersion: 1, OccurredAt: now, Data: data}
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if count := countOf(`SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id='ada' AND event_id='event-1'`); count != 1 {
		t.Fatalf("inbox count %d", count)
	}
	if count := countOf(`SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id='gone'`); count != 0 {
		t.Fatalf("disabled user received %d", count)
	}
	exec(`INSERT INTO user_notification_tombstones(tenant_id,user_id,event_id) VALUES('inbox','ada','event-1')`)
	exec(`DELETE FROM user_notifications WHERE tenant_id='inbox' AND user_id='ada'`)
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if count := countOf(`SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id='ada'`); count != 0 {
		t.Fatalf("replay resurrected %d rows", count)
	}
}

func TestPersonalInboxRetentionBatchesCapsAndFencesReplay(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("retention")
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('retention','Retention')`); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id)
		VALUES('ada','Ada','member','retention-ada','retention'),('bob','Bob','member','retention-bob','retention')`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data)
		SELECT 'retention','old-'||g,'finding.ownership_changed','retention','old-'||g,1,$1,
		jsonb_build_object('decision_id','old-'||g,'engagement_id','eng','finding_id','finding','new_assignee_id','ada')
		FROM generate_series(1,205) g`, now.Add(-inboxAge-time.Hour))
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at)
		SELECT 'retention','ada','row-old-'||g,'old-'||g,'finding.ownership_changed','Old','old','/inbox',$1
		FROM generate_series(1,205) g`, now.Add(-inboxAge-time.Hour))
	personalExec(t, ctx, pool, tenant, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data)
		SELECT 'retention','fresh-'||g,'finding.ownership_changed','retention','fresh-'||g,1,$1,'{}'::jsonb
		FROM generate_series(1,1002) g`, now)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at)
		SELECT 'retention','bob','row-fresh-'||lpad(g::text,4,'0'),'fresh-'||g,
		'finding.ownership_changed','Fresh','fresh','/inbox',$1::timestamptz-make_interval(secs=>g)
		FROM generate_series(1,1002) g`, now)
	retain := func() {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return retainPersonalInbox(ctx, tx, tenant, now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	retain()
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='retention' AND user_id='ada'`); count != 5 {
		t.Fatalf("age batch retained %d old rows, want 5", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='retention' AND user_id='bob'`); count != inboxPerUserCap {
		t.Fatalf("per-user cap left %d rows", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notification_tombstones
		WHERE tenant_id='retention' AND user_id='bob' AND event_id IN ('fresh-1001','fresh-1002')`); count != 2 {
		t.Fatalf("cap did not remove the two oldest rows: %d", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notification_tombstones WHERE tenant_id='retention'`); count != 202 {
		t.Fatalf("first batch wrote %d replay fences", count)
	}
	retain()
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='retention' AND user_id='ada'`); count != 0 {
		t.Fatalf("age sweep left %d old rows", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notification_tombstones WHERE tenant_id='retention'`); count != 207 {
		t.Fatalf("retention wrote %d replay fences", count)
	}
	data, _ := json.Marshal(notification.OwnershipChanged{DecisionID: "old-1", EngagementID: "eng", FindingID: "finding", NewAssigneeID: "ada"})
	event := notification.Event{TenantID: tenant, ID: "old-1", Type: notification.EventOwnershipChanged,
		SourceKind: "retention", SourceID: "old-1", SchemaVersion: 1, OccurredAt: now.Add(-inboxAge - time.Hour), Data: data}
	if _, err := NewNotificationRepository(pool).Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='retention' AND user_id='ada'`); count != 0 {
		t.Fatalf("replay resurrected %d expired rows", count)
	}
}
