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
