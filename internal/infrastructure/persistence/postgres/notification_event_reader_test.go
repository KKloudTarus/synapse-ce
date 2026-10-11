package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// The template preview (#1372) reads a tenant's newest events of one type, and one event by ID,
// never another tenant's. Migration 0205 indexes the listing.
func TestNotificationEventReaderPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('preview-a','A'),('preview-b','B')"); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	base := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	publish := func(tenant, id shared.ID, eventType notification.EventType, at time.Time) {
		t.Helper()
		e := notification.Event{TenantID: tenant, ID: id, Type: eventType, SourceKind: "preview-test", SourceID: id.String(), Severity: shared.SeverityHigh,
			EngagementID: "eng-1", SchemaVersion: 1, OccurredAt: at, Data: json.RawMessage(`{"title":"Preview ` + id.String() + `"}`)}
		if _, err := repo.Publish(shared.WithTenant(ctx, tenant), e); err != nil {
			t.Fatalf("publish %s: %v", id, err)
		}
	}
	for n := 0; n < 25; n++ {
		publish("preview-a", shared.ID(fmt.Sprintf("a-%02d", n)), notification.EventIncidentCreated, base.Add(time.Duration(n)*time.Minute))
	}
	// Two events at the same instant are ordered by ID, newest-first.
	publish("preview-a", "a-tie", notification.EventIncidentCreated, base.Add(24*time.Minute))
	publish("preview-a", "a-scan", notification.EventScanCompleted, base.Add(time.Hour))
	publish("preview-b", "b-newest", notification.EventIncidentCreated, base.Add(2*time.Hour))

	events, err := repo.ListRecentNotificationEvents(ctx, "preview-a", notification.EventIncidentCreated, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 20 {
		t.Fatalf("listed %d events, want 20", len(events))
	}
	if events[0].ID != "a-tie" || events[1].ID != "a-24" || events[2].ID != "a-23" || events[19].ID != "a-06" {
		t.Fatalf("order = %s %s %s … %s", events[0].ID, events[1].ID, events[2].ID, events[19].ID)
	}
	for _, e := range events {
		if e.TenantID != "preview-a" || e.Type != notification.EventIncidentCreated || e.EngagementID != "eng-1" || e.Severity != shared.SeverityHigh || len(e.Data) == 0 {
			t.Fatalf("event = %+v", e)
		}
	}
	if other, err := repo.ListRecentNotificationEvents(ctx, "preview-b", notification.EventIncidentCreated, 20); err != nil || len(other) != 1 || other[0].ID != "b-newest" {
		t.Fatalf("tenant b = %+v (%v)", other, err)
	}
	if capped, err := repo.ListRecentNotificationEvents(ctx, "preview-a", notification.EventIncidentCreated, 0); err != nil || len(capped) != 26 {
		t.Fatalf("limit 0 lists %d (%v), want every event under the cap", len(capped), err)
	}

	got, err := repo.GetNotificationEvent(ctx, "preview-a", "a-03")
	if err != nil || got.ID != "a-03" || !got.OccurredAt.Equal(base.Add(3*time.Minute)) || string(got.Data) == "" {
		t.Fatalf("get = %+v (%v)", got, err)
	}
	if _, err := repo.GetNotificationEvent(ctx, "preview-b", "a-03"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get = %v, want not found", err)
	}
	if _, err := repo.GetNotificationEvent(ctx, "preview-a", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing get = %v", err)
	}

	var valid bool
	if err := pool.QueryRow(ctx, `SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'notification_events_type_recent_idx'`).Scan(&valid); err != nil || !valid {
		t.Fatalf("recent-event index valid=%v err=%v", valid, err)
	}
}
