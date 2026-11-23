package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
)

func TestPagerLifecycleCaptureTransportPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("pager-transport")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Pager')`, tenant); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	repo := NewNotificationRepository(pool)
	source := NewNotificationSource(pool, repo, time.Hour)
	lifecycle := notification.PagerLifecycle{Episode: 2, Revision: 7, Terminal: true}
	err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data,subject_kind,subject_id,pager_episode,pager_revision,pager_terminal) VALUES($1,'finding_status','finding:7','finding.status_changed',$2,'{"title":"Changed"}','finding','finding',2,7,true)`, tenant, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// An incident creation trigger stamps the source revision at capture time.
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','',true,$2)`, tenant, now.Add(-time.Second)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_events(tenant_id,incident_id,seq,kind,occurred_at,actor,payload) VALUES($1,'incident-1',1,'created',$2,'test','{"Title":"Test"}')`, tenant, now); err != nil {
			return err
		}
		var kind, id string
		var episode, revision int64
		var terminal bool
		if err := tx.QueryRow(ctx, `SELECT subject_kind,subject_id,pager_episode,pager_revision,pager_terminal FROM notification_source_records WHERE tenant_id=$1 AND source_kind='incident' AND source_id='incident-1'`, tenant).Scan(&kind, &id, &episode, &revision, &terminal); err != nil {
			return err
		}
		if kind != "incident" || id != "incident-1" || episode != 1 || revision != 1 || terminal {
			t.Fatalf("incident lifecycle = %s %s %d %d %v", kind, id, episode, revision, terminal)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The pre-upgrade worker cannot consume or publish a classified record.
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_source_records SET processed_at=$2 WHERE tenant_id=$1`, tenant, now)
		return err
	})
	if err == nil {
		t.Fatal("old worker consumed classified source")
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,occurred_at,data) VALUES($1,'old-worker','finding.status_changed','finding_status','finding:7',$2,'{}')`, tenant, now)
		return err
	})
	if err == nil {
		t.Fatal("old worker published without lifecycle")
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		n, err := source.pollCaptured(ctx, tx, tenant, "finding_status", now.Add(time.Second), 10)
		if err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("poll count = %d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := repo.GetNotificationEvent(ctx, tenant, stableID(tenant.String(), "finding_status", "finding:7"))
	if err != nil || event.PagerLifecycle != lifecycle {
		t.Fatalf("event lifecycle = %+v, %v", event.PagerLifecycle, err)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]any
	if err := json.Unmarshal(raw, &public); err != nil {
		t.Fatal(err)
	}
	if _, ok := public["PagerLifecycle"]; ok {
		t.Fatal("lifecycle leaked into public event")
	}
}
