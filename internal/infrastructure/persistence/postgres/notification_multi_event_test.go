package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestNotificationPostgresMixedEventDigest(t *testing.T) {
	pool := notificationTestPool(t)
	for _, cadence := range []notification.DeliveryCadence{notification.CadenceHourly, notification.CadenceDaily} {
		t.Run(string(cadence), func(t *testing.T) {
			f := newPostgresDigestFixture(t, pool, shared.ID("mixed-events-"+string(cadence)), cadence)
			rule := f.rule
			if err := json.Unmarshal([]byte(`{"event_type":"engagement.created","event_types":["engagement.created","engagement.status_changed","finding.created","finding.status_changed","finding.commented"]}`), &rule); err != nil {
				t.Fatal(err)
			}
			rule.Revision++
			if _, err := f.repo.UpdateRule(f.ctx, rule); err != nil {
				t.Fatal(err)
			}
			publish := func(id shared.ID, typ notification.EventType, severity shared.Severity) []shared.ID {
				t.Helper()
				contextJSON, err := json.Marshal(map[string]any{"vars": map[string]string{"event_type": string(typ), "occurred_at": f.at.Format(time.RFC3339), "title": "Mixed source"}})
				if err != nil {
					t.Fatal(err)
				}
				event := notification.Event{TenantID: f.tenant, ID: id, Type: typ, SourceKind: "mixed-source", SourceID: id.String(), Severity: severity, SchemaVersion: 1, OccurredAt: f.at, Data: json.RawMessage(`{"title":"Mixed source"}`), Context: contextJSON}
				deliveries, err := f.repo.Publish(f.ctx, event)
				if err != nil {
					t.Fatal(err)
				}
				return deliveries
			}
			types := []notification.EventType{notification.EventEngagementCreated, notification.EventEngagementStatusChanged, notification.EventFindingCreated, notification.EventFindingStatusChanged, notification.EventFindingCommented}
			for i, typ := range types {
				id := shared.ID("mixed-" + string(rune('a'+i)))
				if got := publish(id, typ, shared.SeverityMedium); len(got) != 0 {
					t.Fatalf("batched source %s immediately delivered %v", typ, got)
				}
				publish(id, typ, shared.SeverityMedium)
			}
			if got := publish("critical-source", notification.EventFindingCreated, shared.SeverityCritical); len(got) != 1 {
				t.Fatalf("critical event did not bypass mixed digest: %v", got)
			}
			if err := WithTenant(f.ctx, pool, f.tenant.String(), func(tx pgx.Tx) error {
				var members, distinctTypes int
				err := tx.QueryRow(f.ctx, `SELECT count(*),count(DISTINCT e.event_type) FROM notification_digest_members m JOIN notification_events e ON e.tenant_id=m.tenant_id AND e.id=m.event_id WHERE m.tenant_id=$1`, f.tenant).Scan(&members, &distinctTypes)
				if err == nil && (members != 5 || distinctTypes != 5) {
					t.Fatalf("captured members=%d types=%d, want five", members, distinctTypes)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if n, err := f.materialize(f.ctx, f.at.Add(25*time.Hour), 10); err != nil || n != 1 {
				t.Fatalf("materialize=%d err=%v", n, err)
			}
			if n, err := f.materialize(f.ctx, f.at.Add(25*time.Hour), 10); err != nil || n != 0 {
				t.Fatalf("rerun=%d err=%v", n, err)
			}
			page, err := f.repo.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant})
			if err != nil || len(page.Items) != 2 {
				t.Fatalf("deliveries=%+v err=%v", page, err)
			}
			var work ports.NotificationWork
			for _, delivery := range page.Items {
				candidate, err := f.repo.LoadWork(f.ctx, f.tenant, delivery.ID)
				if err != nil {
					t.Fatal(err)
				}
				if candidate.Event.Type == notification.EventDigest {
					work = candidate
				}
			}
			found := map[notification.EventType]bool{}
			for _, item := range work.Event.DigestItems {
				found[item.Event.Type] = true
				if item.Event.ID == "critical-source" {
					t.Fatal("critical source entered digest")
				}
			}
			if len(work.Event.DigestItems) != 5 || len(found) != 5 {
				t.Fatalf("mixed digest members=%d distinct types=%d, want five each", len(work.Event.DigestItems), len(found))
			}
		})
	}
}
