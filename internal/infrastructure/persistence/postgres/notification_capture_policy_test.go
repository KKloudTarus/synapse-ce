package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func captureTestAdminDSN(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("SYNAPSE_TEST_DB_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + pool.Config().ConnConfig.Database
	u.RawPath = ""
	return u.String()
}

func TestNotificationCaptureCutoverProtectsLegacyWorkers(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("capture-policy")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,'Capture')", tenant); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO engagements(id,tenant_id,name) VALUES('capture-eng',$1,'Capture')", tenant)
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	channel := notification.Channel{TenantID: tenant, ID: "capture-hook", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: "capture-rule", Name: "Scan", Enabled: true, EventType: notification.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 100); err != nil {
		t.Fatal(err)
	}
	jobs := NewScanJobStore(pool)
	save := func(id string, at time.Time, snapshot bool) {
		t.Helper()
		job := ports.ScanJob{ID: id, EngagementID: "capture-eng", Target: "repo", Kind: "git", Status: ports.ScanSucceeded, Stage: "done", StartedAt: now, FinishedAt: &at}
		if snapshot {
			job.NotificationSnapshot = notification.NewScanSummary("repo", ports.TargetGit, true, []finding.Finding{{ID: shared.ID("finding-" + id), DedupKey: "finding-" + id, Kind: finding.KindSCA, Severity: shared.SeverityHigh}})
		}
		if err := jobs.Save(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	save("capture-old", now.Add(500*time.Millisecond), false)
	save("capture-legacy", now.Add(time.Second), true)
	var version int
	var title string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT capture_version,data->>'title' FROM notification_source_records WHERE tenant_id=$1 AND source_id='capture-legacy'", tenant).Scan(&version, &title)
	}); err != nil || version != 1 || title != "Scan completed" {
		t.Fatalf("legacy version=%d title=%q err=%v", version, title, err)
	}
	if _, err := SetNotificationCaptureMode(ctx, captureTestAdminDSN(t, pool), "identity"); err != nil {
		t.Fatal(err)
	}
	save("capture-identity", now.Add(2*time.Second), true)
	var body string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT capture_version,data::text FROM notification_source_records WHERE tenant_id=$1 AND source_id='capture-identity'", tenant).Scan(&version, &body)
	}); err != nil || version != 2 || body != "{}" {
		t.Fatalf("identity version=%d data=%q err=%v", version, body, err)
	}
	old := NewNotificationRepository(pool) // An old worker has no capable projector path.
	event := notification.Event{TenantID: tenant, ID: "old-empty", Type: notification.EventScanCompleted, SourceKind: "scan_job", SourceID: "capture-identity", EngagementID: "capture-eng", SchemaVersion: 1, OccurredAt: now.Add(2 * time.Second), Data: []byte("{}")}
	_, err := old.PublishToChannel(ctx, event, channel.ID)
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55000" {
		t.Fatalf("old publication err=%v, want capability refusal", err)
	}
	for _, quarantine := range []bool{false, true} {
		err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "UPDATE notification_source_records SET processed_at=now(),failed_reason=CASE WHEN $2 THEN 'invalid_event' ELSE '' END WHERE tenant_id=$1 AND source_id='capture-identity'", tenant, quarantine)
			return err
		})
		if !errors.As(err, &pgerr) || pgerr.Code != "55000" {
			t.Fatalf("old completion quarantine=%v err=%v", quarantine, err)
		}
	}
	var consumed, published int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_id='capture-identity' AND processed_at IS NOT NULL", tenant).Scan(&consumed); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND id='old-empty'", tenant).Scan(&published)
	}); err != nil || consumed != 0 || published != 0 {
		t.Fatalf("old worker consumed=%d published=%d err=%v", consumed, published, err)
	}
	if pending, err := SetNotificationCaptureMode(ctx, captureTestAdminDSN(t, pool), "legacy"); err != nil || pending != 1 {
		t.Fatalf("rollback pending=%d err=%v", pending, err)
	}
	if _, err := source.Poll(ctx, now.Add(3*time.Second), 100); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("capable deliveries=%d err=%v", len(page.Items), err)
	}
	assertEvent := func(sourceID string, wantVersion int, wantCount bool) {
		t.Helper()
		var (
			version int
			data    []byte
		)
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT schema_version,data FROM notification_events WHERE tenant_id=$1 AND source_kind='scan_job' AND source_id=$2", tenant, sourceID).Scan(&version, &data)
		}); err != nil {
			t.Fatal(err)
		}
		if version != wantVersion {
			t.Fatalf("%s schema_version=%d, want %d", sourceID, version, wantVersion)
		}
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatal(err)
		}
		_, hasTotal := body["total_count"]
		if hasTotal != wantCount || (wantCount && body["total_count"] != float64(1)) {
			t.Fatalf("%s data=%s, want aggregate=%t", sourceID, data, wantCount)
		}
	}
	assertEvent("capture-old", 1, false)
	assertEvent("capture-legacy", 2, true)
	assertEvent("capture-identity", 2, true)
	if pending, err := SetNotificationCaptureMode(ctx, captureTestAdminDSN(t, pool), "legacy"); err != nil || pending != 0 {
		t.Fatalf("drained pending=%d err=%v", pending, err)
	}
	// A transaction-local marker must not survive pool connection reuse.
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var marker string
		if err := tx.QueryRow(ctx, "SELECT COALESCE(current_setting('synapse.notification_source_capability',true),'')").Scan(&marker); err != nil {
			return err
		}
		if marker != "" {
			t.Fatalf("capability leaked between transactions: %q", marker)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationCaptureModeWaitsForInflightCapture(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared(78146)"); err != nil {
		t.Fatal(err)
	}
	blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if _, err := SetNotificationCaptureMode(blocked, captureTestAdminDSN(t, pool), "identity"); err == nil {
		t.Fatal("mode changed before in-flight captures released the barrier")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := SetNotificationCaptureMode(ctx, captureTestAdminDSN(t, pool), "identity"); err != nil {
		t.Fatal(err)
	}
}
