package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
)

func TestEmailDestinationNoticesAreTransactionalDomainOnlyAndMandatory(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := notification.WithActor(context.Background(), "admin")
	tenant := shared.ID("mail-notice")
	_, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('mail-notice','Notices'),('mail-other','Other')`)
	if err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('mail-admin','Admin','admin','mail-admin-hash','mail-notice',false),('mail-member','Member','member','mail-member-hash','mail-notice',false),('mail-disabled','Disabled','admin','mail-disabled-hash','mail-notice',true)`)
	personalExec(t, ctx, pool, "mail-other", `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('mail-foreign','Other','admin','mail-other-hash','mail-other',false)`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES('mail-notice','mail-admin','notification.destination_changed','in_app','disabled',1,now())`)
	repo := NewNotificationRepository(pool)
	repo.EnableDestinationNotices()
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := notification.Channel{TenantID: tenant, ID: "mail", Name: "Mail", Type: notification.ChannelEmail, Enabled: true, Recipients: []string{"alice@example.test"}, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, c, "sealed"); err != nil {
		t.Fatal(err)
	}
	check := func(want int) {
		t.Helper()
		if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_events WHERE tenant_id='mail-notice' AND event_type='notification.destination_changed'`); got != want {
			t.Fatalf("events=%d want=%d", got, want)
		}
		if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='mail-notice' AND user_id='mail-admin'`); got != want {
			t.Fatalf("mandatory inbox=%d want=%d", got, want)
		}
		if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='mail-notice' AND user_id<>'mail-admin'`); got != 0 {
			t.Fatalf("non-admin received %d", got)
		}
	}
	check(1)
	c.Recipients = []string{"bob@example.test"}
	c.Revision++
	c.UpdatedAt = now.Add(time.Second)
	if _, err := repo.UpdateChannel(ctx, c, "rotated", true); err != nil {
		t.Fatal(err)
	}
	check(1)
	c.Name = "Renamed"
	c.Revision++
	c.UpdatedAt = now.Add(2 * time.Second)
	if _, err := repo.UpdateChannel(ctx, c, "", false); err != nil {
		t.Fatal(err)
	}
	check(1)
	c.Recipients = []string{"carol@other.test", "dave@example.test"}
	c.Revision++
	c.UpdatedAt = now.Add(3 * time.Second)
	if _, err := repo.UpdateChannel(ctx, c, "changed", true); err != nil {
		t.Fatal(err)
	}
	check(2)
	if _, err := repo.UpdateChannel(ctx, c, "changed", true); err == nil {
		t.Fatal("same revision accepted")
	}
	check(2)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM notification_events WHERE tenant_id=$1 AND event_type=$2`, tenant, notification.EventDestinationChanged)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw json.RawMessage
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			if strings.Contains(string(raw), "@") || strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "carol") {
				t.Errorf("recipient disclosed: %s", raw)
			}
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	// A failed surrounding transaction must roll back both the channel and mandatory projection.
	rollback := c
	rollback.ID = "rolled-back"
	rollback.Revision = 1
	sentinel := context.Canceled
	err = NewTenantTransactionRunner(pool).Run(shared.WithTenant(ctx, tenant), tenant, func(txCtx context.Context) error {
		if _, err := repo.CreateChannel(txCtx, rollback, "sealed"); err != nil {
			return err
		}
		return sentinel
	})
	if err != sentinel {
		t.Fatalf("rollback=%v", err)
	}
	check(2)
}
