package response

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type postgresResponseNotificationFacts struct{}

func (postgresResponseNotificationFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return ports.NotificationLifecycleFacts{EngagementName: "Captured engagement", ActorName: "Captured operator", ActorUserID: "operator", LeadUserID: "lead"}, nil
}

type postgresResponseFailAfterAppend struct {
	next ports.NotificationOutbox
}

func (o postgresResponseFailAfterAppend) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return errors.New("injected response source failure")
}

func TestResponseFinishedProducerPostgresAtomicSnapshotAndReplay(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := postgres.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := postgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	tenant := shared.ID("response-notification-" + stamp.Format("20060102150405.000000"))
	engagementID := shared.ID(tenant.String() + "-engagement")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := postgres.WithTenant(shared.WithTenant(ctx, tenant), pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Captured engagement')`, engagementID, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn, acquireErr := pool.Acquire(context.Background())
		if acquireErr != nil {
			return
		}
		defer conn.Release()
		if _, roleErr := conn.Exec(context.Background(), `SET session_replication_role = replica`); roleErr != nil {
			return
		}
		defer conn.Exec(context.Background(), `SET session_replication_role = origin`)
		for _, query := range []string{
			`DELETE FROM notification_source_records WHERE tenant_id=$1`,
			`DELETE FROM response_audit_intents WHERE tenant_id=$1`,
			`DELETE FROM response_actions WHERE tenant_id=$1`,
			`DELETE FROM engagements WHERE tenant_id=$1`,
			`DELETE FROM tenants WHERE id=$1`,
		} {
			_, _ = conn.Exec(context.Background(), query, tenant)
		}
	})
	tenantCtx := shared.WithTenant(ctx, tenant)
	if err := postgres.WithTenant(tenantCtx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(tenantCtx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'framework','activation','v1',true,$2)`, tenant, stamp.Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	store := postgres.NewResponseRepository(pool)
	runner, outbox := postgres.NewTenantTransactionRunner(pool), postgres.NewNotificationOutbox(pool)
	svc, err := newService(&fakeAdmitter{}, &fakeExec{}, store, postgres.NewAuditLog(pool), fixedClock{t: stamp})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifications(runner, postgresResponseFailAfterAppend{next: outbox}, postgresResponseNotificationFacts{}); err != nil {
		t.Fatal(err)
	}
	action, err := rdom.NewAction("response-notification-rollback", rdom.KindIsolateHost, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	record := Record{ID: action.ID, TenantID: tenant, EngagementID: engagementID, Action: action, State: StatePending, ApprovedBy: "operator", UpdatedAt: stamp}
	if err := store.Put(tenantCtx, record); err != nil {
		t.Fatal(err)
	}
	record.State, record.UpdatedAt = StateCancelled, stamp.Add(time.Second)
	intent := responseAuditIntent("response-notification-rollback", "operator", "response.cancelled", record.ID.String(), record.UpdatedAt, map[string]string{})
	if _, _, err := svc.transitionWithAuditAndNotification(tenantCtx, record, StatePending, intent, "failed", "operator"); err == nil {
		t.Fatal("want source failure")
	}
	stored, found, err := store.Get(tenantCtx, record.ID)
	if err != nil || !found || stored.State != StatePending {
		t.Fatalf("source failure escaped response transaction: record=%+v found=%t err=%v", stored, found, err)
	}
	if err := svc.SetNotifications(runner, outbox, postgresResponseNotificationFacts{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.transitionWithAuditAndNotification(tenantCtx, record, StatePending, intent, "failed", "operator"); err != nil {
		t.Fatal(err)
	}
	// Mutate presentation after the source commit but before projection: the sealed v3 snapshot remains authoritative.
	if _, err := pool.Exec(ctx, `UPDATE engagements SET name='Changed engagement' WHERE tenant_id=$1 AND id=$2`, tenant, engagementID); err != nil {
		t.Fatal(err)
	}
	var source notification.SourceRecord
	if err := postgres.WithTenant(tenantCtx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(tenantCtx, `SELECT source_kind,source_id,event_type,engagement_id,occurred_at,data,context,capture_version FROM notification_source_records WHERE tenant_id=$1`, tenant).Scan(&source.SourceKind, &source.SourceID, &source.EventType, &source.EngagementID, &source.OccurredAt, &source.Data, &source.Context, &source.CaptureVersion)
	}); err != nil {
		t.Fatal(err)
	}
	if source.EventType != notification.EventResponseFinished || source.SourceID != record.ID.String()+":failed" || source.CaptureVersion != 3 {
		t.Fatalf("response source=%+v", source)
	}
	var data map[string]any
	if err := json.Unmarshal(source.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["outcome"] != "failed" || data["response_id"] != record.ID.String() || data["engagement_id"] != engagementID.String() {
		t.Fatalf("response source data=%#v", data)
	}
	sealed, err := notification.DecodeTemplateContext(source.Context)
	if err != nil || sealed.Vars["engagement_name"] != "Captured engagement" || sealed.Vars["actor"] != "Captured operator" || sealed.Vars["outcome"] != "failed" {
		t.Fatalf("response immutable snapshot=%+v err=%v", sealed, err)
	}
}
