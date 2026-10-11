package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestNotificationPostgresComposesIdentityOnlyCaptures covers the records a later identity-only
// capture trigger will write (#1344, second phase). The capture trigger still writes the data
// today; this worker must already publish an identity-only record exactly as it publishes a legacy
// one, so the trigger can switch once every running worker is this one. A legacy record and an
// identity-only record of the same kinds are both published with the 0163 data.
func TestNotificationPostgresComposesIdentityOnlyCaptures(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("notify-identity")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('notify-identity','I')"); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO engagements(id,tenant_id,name) VALUES('eng-identity','notify-identity','E')")
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	channel := notification.Channel{TenantID: tenant, ID: "channel", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []notification.EventType{notification.EventScanCompleted, notification.EventQualityGateFailed, notification.EventIncidentCreated} {
		if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: shared.ID(kind), Name: string(kind), Enabled: true, EventType: kind, ChannelIDs: []shared.ID{channel.ID}, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, now, 100); err != nil {
		t.Fatal(err)
	}

	// The identity-only records are written first, as the later trigger would, so the current
	// trigger's insert for the same sources is a no-op (ON CONFLICT DO NOTHING).
	happened := now.Add(time.Second)
	for _, r := range []struct{ kind, id, eventType, subject, engagement, severity string }{
		{"scan_job", "scan", "scan.completed", "scan_job", "eng-identity", ""},
		{"project_analysis_gate", "analysis", "quality_gate.failed", "project_analysis", "", ""},
		{"incident", "incident", "incident.created", "incident", "", "high"},
	} {
		exec(`INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,engagement_id,severity,occurred_at,data,subject_kind,subject_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,'{}'::jsonb,$8,$3)`, tenant, r.kind, r.id, r.eventType, r.engagement, r.severity, happened, r.subject)
	}
	if err := NewScanJobStore(pool).Save(ctx, ports.ScanJob{ID: "scan", EngagementID: "eng-identity", Target: "ignored", Kind: "git", Status: ports.ScanSucceeded, Stage: "done", StartedAt: happened, FinishedAt: &happened}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES('project-identity','notify-identity','P','pi','{}')`)
	exec(`INSERT INTO project_analyses(id,tenant_id,project_id,created_at,payload) VALUES('analysis','notify-identity','project-identity',$1,'{"gate":{"Passed":false}}')`, happened)
	exec(`INSERT INTO incident_events(tenant_id,incident_id,seq,kind,occurred_at,actor,payload) VALUES('notify-identity','incident',1,'created',$1,'correlator','{"Severity":"high","Title":"Detected"}')`, happened)

	if _, err := source.Poll(ctx, now.Add(2*time.Second), 100); err != nil {
		t.Fatal(err)
	}
	page, err := repo.ListDeliveries(ctx, ports.NotificationDeliveryFilter{TenantID: tenant})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("deliveries = %d, %v, want one per identity-only record", len(page.Items), err)
	}
	for _, d := range page.Items {
		w, err := repo.LoadWork(ctx, tenant, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		assertPublishedEventSchema(t, w.Event)
		assertComposedFromIdentity(t, w.Event)
	}
}

// assertComposedFromIdentity is assertComposedFromSource for the identity-only fixtures above,
// whose project has its own ID.
func assertComposedFromIdentity(t *testing.T, e notification.Event) {
	t.Helper()
	if e.Type == notification.EventQualityGateFailed {
		var data map[string]any
		if err := json.Unmarshal(e.Data, &data); err != nil || data["project_id"] != "project-identity" || data["analysis_id"] != "analysis" || data["title"] != "Quality gate failed" {
			t.Fatalf("composed gate data = %s, %v", e.Data, err)
		}
		return
	}
	assertComposedFromSource(t, e)
}
