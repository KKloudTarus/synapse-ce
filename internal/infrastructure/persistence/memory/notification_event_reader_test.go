package memory

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

// The memory reader orders and scopes events like the Postgres one (#1372).
func TestNotificationEventReaderMemory(t *testing.T) {
	base := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	repo := NewNotificationRepository(nil, func() time.Time { return base })
	ctx := context.Background()
	publish := func(tenant, id shared.ID, eventType notification.EventType, at time.Time) {
		t.Helper()
		e := notification.Event{TenantID: tenant, ID: id, Type: eventType, SourceKind: "preview-test", SourceID: id.String(),
			SchemaVersion: 1, OccurredAt: at, Data: json.RawMessage(`{"title":"x"}`)}
		if _, err := repo.Publish(ctx, e); err != nil {
			t.Fatalf("publish %s: %v", id, err)
		}
	}
	for n := 0; n < 22; n++ {
		publish("a", shared.ID(fmt.Sprintf("a-%02d", n)), notification.EventIncidentCreated, base.Add(time.Duration(n)*time.Minute))
	}
	publish("a", "a-tie", notification.EventIncidentCreated, base.Add(21*time.Minute))
	publish("a", "a-scan", notification.EventScanCompleted, base.Add(time.Hour))
	publish("b", "b-1", notification.EventIncidentCreated, base.Add(time.Hour))

	events, err := repo.ListRecentNotificationEvents(ctx, "a", notification.EventIncidentCreated, 20)
	if err != nil || len(events) != 20 || events[0].ID != "a-tie" || events[1].ID != "a-21" || events[19].ID != "a-03" {
		t.Fatalf("events = %d first %v (%v)", len(events), events[0].ID, err)
	}
	if got, err := repo.GetNotificationEvent(ctx, "a", "a-05"); err != nil || got.ID != "a-05" {
		t.Fatalf("get = %+v (%v)", got, err)
	}
	if _, err := repo.GetNotificationEvent(ctx, "b", "a-05"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get = %v", err)
	}
}
