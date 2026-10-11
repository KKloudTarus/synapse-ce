package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestNotificationCapturedSourceQuarantineDoesNotBlockNextSource(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "quarantine-a")
	tenant := shared.ID("quarantine-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('quarantine-a','A'),('quarantine-b','B')`); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	channel := notification.Channel{TenantID: tenant, ID: "quarantine-hook", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: "quarantine-rule", Name: "Scans", Enabled: true, EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	bad, _ := json.Marshal(map[string]string{"title": strings.Repeat("x", 17*1024)})
	good := []byte(`{"title":"Scan completed","summary":"Done"}`)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for i, item := range []struct {
			id   string
			data []byte
		}{{"bad", bad}, {"good", good}} {
			_, err := tx.Exec(ctx, `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data) VALUES($1,'scan_job',$2,'scan.completed',$3,$4)`, tenant, item.id, now.Add(time.Duration(i+1)*time.Second), item.data)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := source.Poll(ctx, now.Add(3*time.Second), 2); err != nil || n != 2 {
		t.Fatalf("poll processed %d records: %v", n, err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("valid event deliveries = %d: %v", len(page.Items), err)
	}
	failures, err := repo.ListSourceFailures(ctx, ports.NotificationSourceFailureFilter{TenantID: tenant})
	if err != nil || len(failures.Items) != 1 {
		t.Fatalf("quarantined sources = %d: %v", len(failures.Items), err)
	}
	if got := failures.Items[0]; got.SourceID != "bad" || got.FailedReason != "event_data_too_large" || got.ProcessedAt.IsZero() {
		t.Fatalf("unexpected quarantine row: %+v", got)
	}
	if other, err := repo.ListSourceFailures(shared.WithTenant(context.Background(), "quarantine-b"), ports.NotificationSourceFailureFilter{TenantID: "quarantine-b"}); err != nil || len(other.Items) != 0 {
		t.Fatalf("other tenant can see failures: %+v, %v", other, err)
	}
	if n, err := source.Poll(ctx, now.Add(4*time.Second), 2); err != nil || n != 0 {
		t.Fatalf("replay processed %d records: %v", n, err)
	}
}

func TestIdentityCaptureMissingSourceAcrossKindsIsQuarantinedAndNextSourcePublishes(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("identity-source-missing")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Identity source missing')`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES('identity-source-eng',$1,'Identity source')`, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	channel := notification.Channel{TenantID: tenant, ID: "identity-source-hook", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: "identity-source-rule", Name: "Scans", Enabled: true, EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	firstFinished := now.Add(-time.Second)
	if err := NewScanJobStore(pool).Save(ctx, ports.ScanJob{ID: "identity-source-first", EngagementID: "identity-source-eng", Target: "repo", Kind: "git", Status: ports.ScanSucceeded, Stage: "done", StartedAt: firstFinished, FinishedAt: &firstFinished}); err != nil {
		t.Fatal(err)
	}
	projectFinished := now.Add(time.Second)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES('identity-source-project',$1,'Identity source project','identity-source-project','{}')`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO project_analyses(id,tenant_id,project_id,created_at,payload) VALUES('identity-source-healthy',$1,'identity-source-project',$2,'{"gate":{"Results":[]}}')`, tenant, projectFinished); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,engagement_id,occurred_at,data,capture_version)
			VALUES($1,'scan_job','identity-source-first','scan.completed','identity-source-eng',$2,'{}',2),
			($1,'project_analysis_gate','identity-source-missing','quality_gate.failed','',$3,'{}',2),
			($1,'project_analysis_gate','identity-source-healthy','quality_gate.failed','',$4,'{}',2)`, tenant, firstFinished, now, projectFinished)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	source := NewNotificationSource(pool, repo, time.Minute)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if n, err := source.pollCaptured(ctx, tx, tenant, "scan_job", now, 10); err != nil || n != 1 {
			return fmt.Errorf("first scan poll captured n=%d: %w", n, err)
		}
		if n, err := source.pollCaptured(ctx, tx, tenant, "project_analysis_gate", now, 10); err != nil || n != 2 {
			return fmt.Errorf("project-analysis poll captured n=%d: %w", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('synapse.notification_source_quarantine_capability','source-missing-v1',true)`); err != nil {
			return err
		}
		attempt, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		_, err = attempt.Exec(ctx, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data)
			VALUES($1,'quarantine-marker-must-not-publish','quality_gate.failed','project_analysis_gate','identity-source-missing',1,$2,'{}')`, tenant, now)
		if rollbackErr := attempt.Rollback(ctx); rollbackErr != nil {
			return rollbackErr
		}
		if err == nil {
			return fmt.Errorf("quarantine capability authorized publication")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var reason string
	var processed time.Time
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT failed_reason,processed_at FROM notification_source_records WHERE tenant_id=$1 AND source_id='identity-source-missing'`, tenant).Scan(&reason, &processed)
	}); err != nil || reason != "source_missing" || processed.IsZero() {
		t.Fatalf("missing source reason=%q processed=%v err=%v", reason, processed, err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("healthy scan deliveries=%d err=%v", len(page.Items), err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var published int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND source_id IN ('identity-source-first','identity-source-healthy')`, tenant).Scan(&published); err != nil {
			return err
		}
		if published != 2 {
			return fmt.Errorf("healthy cross-kind publications=%d, want 2", published)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var publication, quarantine string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('synapse.notification_source_capability',true),''),COALESCE(current_setting('synapse.notification_source_quarantine_capability',true),'')`).Scan(&publication, &quarantine); err != nil {
			return err
		}
		if publication != "" || quarantine != "" {
			return fmt.Errorf("source capabilities leaked publication=%q quarantine=%q", publication, quarantine)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityCaptureNilProjectorAndUnknownKindStayPending(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("identity-source-retry")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Identity source retry')`, tenant); err != nil {
		t.Fatal(err)
	}
	insert := func(kind, id string) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data,capture_version) VALUES($1,$2,$3,'scan.completed',$4,'{}',2)`, tenant, kind, id, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("scan_job", "nil-projector")
	insert("unknown_source", "unknown-kind")
	source := NewNotificationSource(pool, NewNotificationRepository(pool), time.Minute)
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := source.pollCaptured(ctx, tx, tenant, "scan_job", now.Add(time.Second), 10)
		return err
	}); err == nil {
		t.Fatal("nil projector identity source unexpectedly completed")
	}
	capable := NewNotificationRepository(pool)
	capable.SetEventProjector(notificationuc.NewEventBuilders())
	source = NewNotificationSource(pool, capable, time.Minute)
	for _, kind := range []string{"unknown_source"} {
		err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := source.pollCaptured(ctx, tx, tenant, kind, now.Add(time.Second), 10)
			return err
		})
		if err == nil {
			t.Fatalf("%s identity source unexpectedly completed", kind)
		}
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND capture_version=2 AND processed_at IS NULL`, tenant).Scan(&pending); err != nil {
			return err
		}
		if pending != 2 {
			return fmt.Errorf("pending identity records=%d, want 2", pending)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationPollUsesOneTotalSourceBudget(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "budget-a")
	tenant := shared.ID("budget-a")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('budget-a','A')`); err != nil {
		t.Fatal(err)
	}
	source := NewNotificationSource(pool, NewNotificationRepository(pool), time.Minute)
	if _, err := source.Poll(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for _, kind := range []string{"scan_job", "project_analysis_gate"} {
			_, err := tx.Exec(ctx, `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data) VALUES($1,$2,$2,$3,$4,'{"title":"ok"}')`, tenant, kind, map[string]string{"scan_job": "scan.completed", "project_analysis_gate": "quality_gate.failed"}[kind], now.Add(time.Second))
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := source.Poll(ctx, now.Add(2*time.Second), 1); err != nil || n != 1 {
		t.Fatalf("first poll: %d, %v", n, err)
	}
	if n, err := source.Poll(ctx, now.Add(3*time.Second), 1); err != nil || n != 1 {
		t.Fatalf("second poll: %d, %v", n, err)
	}
}
