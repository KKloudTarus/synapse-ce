package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

func TestExplicitRuleRecipientsKeepMissingIDsButDeliverOnlyToEnabledTenantHumans(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("explicit")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('explicit','Explicit'),('explicit-other','Other')`); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
 ('explicit-reader','Reader','readonly','explicit-reader-hash','explicit',false),
 ('explicit-disabled','Disabled','admin','explicit-disabled-hash','explicit',true)`)
	personalExec(t, ctx, pool, "explicit-other", `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('explicit-foreign','Foreign','admin','explicit-foreign-hash','explicit-other',false)`)
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	at := time.Now().UTC().Truncate(time.Microsecond)
	r := notification.Rule{TenantID: tenant, ID: "explicit-rule", Name: "Selected people", Enabled: true, EventType: notification.EventIncidentCreated, Cadence: notification.CadenceHourly, RecipientUserIDs: []shared.ID{"explicit-reader", "explicit-reader", "missing-user", "explicit-disabled", "explicit-foreign"}, Revision: 1, CreatedAt: at, UpdatedAt: at}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.CreateRule(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.RecipientUserIDs) != 4 {
		t.Fatalf("saved targets=%v", stored.RecipientUserIDs)
	}
	loaded, err := repo.GetRule(ctx, tenant, r.ID)
	if err != nil || len(loaded.RecipientUserIDs) != 4 || loaded.Cadence != notification.CadenceHourly {
		t.Fatalf("roundtrip=%+v %v", loaded, err)
	}
	e := notification.Event{TenantID: tenant, ID: "explicit-event", Type: notification.EventIncidentCreated, SourceKind: "incident", SourceID: "explicit-source", SchemaVersion: 1, OccurredAt: at, Severity: shared.SeverityHigh, Data: json.RawMessage(`{"incident_id":"explicit-incident","asset_id":"","title":"Synthetic incident","summary":"Test"}`)}
	for i := 0; i < 2; i++ {
		if _, err := repo.Publish(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='explicit' AND user_id='explicit-reader'`); got != 1 {
		t.Fatalf("recipient inbox=%d", got)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='explicit' AND user_id<>'explicit-reader'`); got != 0 {
		t.Fatalf("ineligible recipient inbox=%d", got)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_digest_members WHERE tenant_id='explicit'`); got != 0 {
		t.Fatalf("personal-only rule batched %d members", got)
	}
	// A template fixture test must never notify a real selected user.
	e.ID, e.SourceKind, e.SourceID = "explicit-fixture", "template_test", "explicit-fixture"
	if _, err := repo.Publish(ctx, e); err != nil {
		t.Fatal(err)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='explicit'`); got != 1 {
		t.Fatalf("fixture test projected %d personal rows", got)
	}
}
