package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type failedSnapshotProjector struct {
	ports.NotificationEventProjector
	err error
}

func (p failedSnapshotProjector) Project(context.Context, notification.Event) (notification.Event, error) {
	return notification.Event{}, p.err
}

func TestNotificationSnapshotCrashRecoveryAndIsolation(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	for _, tenant := range []shared.ID{"snapshot-a", "snapshot-b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, at, 200); err != nil {
		t.Fatal(err)
	}
	outbox := NewNotificationOutbox(pool)
	runner := NewTenantTransactionRunner(pool)
	types := []notification.EventType{
		notification.EventFindingCreated, notification.EventFindingStatusChanged, notification.EventFindingRetestCompleted,
		notification.EventScanFailed, notification.EventDASTRunFinished, notification.EventReconRunFinished, notification.EventCSPMRunFinished,
		notification.EventSLABreached, notification.EventRiskAcceptanceCreated, notification.EventRiskAcceptanceExpiring, notification.EventRiskAcceptanceExpired,
	}
	services := make(map[shared.ID]*notificationuc.Service)
	channels := make(map[shared.ID]shared.ID)
	cipher, err := vault.NewCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []shared.ID{"snapshot-a", "snapshot-b"} {
		service, err := notificationuc.NewService(repo, cipher, nil, NewAuditLog(pool), &notificationTestClock{at}, &notificationTestIDs{})
		if err != nil {
			t.Fatal(err)
		}
		service.SetTransactionRunner(runner)
		channel, err := service.CreateChannel(shared.WithTenant(ctx, tenant), "operator", notificationuc.ChannelInput{Name: "Snapshot receiver", Type: notification.ChannelWebhook, Enabled: true, URL: "https://example.com/events", Secret: "1234567890abcdef"})
		if err != nil {
			t.Fatal(err)
		}
		services[tenant], channels[tenant] = service, channel.ID
	}
	for _, eventType := range types {
		for _, tenant := range []shared.ID{"snapshot-a", "snapshot-b"} {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "guide", "schemas", "events", string(eventType)+".v1.fixture.json"))
			if err != nil {
				t.Fatal(err)
			}
			var fixture notification.Event
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			ruleCtx := shared.WithTenant(ctx, tenant)
			var fixtureData struct {
				Lead int64 `json:"lead_time_seconds"`
			}
			if err := json.Unmarshal(fixture.Data, &fixtureData); err != nil {
				t.Fatal(err)
			}
			spec, _ := notification.LookupEvent(eventType)
			if spec.HasTeam && tenant == "snapshot-b" {
				// Tenant-wide lifecycle subscriptions include unassigned findings.
				var data map[string]any
				if err := json.Unmarshal(fixture.Data, &data); err != nil {
					t.Fatal(err)
				}
				delete(data, "team_id")
				fixture.Data, err = json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := services[tenant].CreateRule(ruleCtx, "operator", notificationuc.RuleInput{Name: string(eventType), Enabled: true, EventType: eventType, ChannelIDs: []shared.ID{channels[tenant]}, AllTeams: spec.HasTeam, LeadTimeSeconds: fixtureData.Lead}); err != nil {
				t.Fatal(err)
			}
			record, err := notification.SnapshotSourceRecord(notification.SourceRecord{
				TenantID: tenant, SourceKind: "snapshot_test", SourceID: string(eventType), EventType: eventType,
				Severity: fixture.Severity, EngagementID: fixture.EngagementID, OccurredAt: at.Add(time.Second),
				Data: fixture.Data, SchemaVersion: 1,
			}, map[string]string{"finding_title": "Original finding", "engagement_name": "Original engagement", "severity": string(fixture.Severity)})
			if err != nil {
				t.Fatal(err)
			}
			appendRecord := func(txctx context.Context) error { return outbox.Append(txctx, record) }
			// A caller that fails after append must leave no committed intent.
			injected := errors.New("injected producer failure")
			if err := runner.Run(ctx, tenant, func(txctx context.Context) error {
				if err := appendRecord(txctx); err != nil {
					return err
				}
				return injected
			}); !errors.Is(err, injected) {
				t.Fatalf("rollback %s: %v", eventType, err)
			}
			if err := runner.Run(ctx, tenant, appendRecord); err != nil {
				t.Fatal(err)
			}
			// Replaying a committed source cannot replace its historical facts.
			record.Context = json.RawMessage(`{"vars":{"finding_title":"Changed finding","engagement_name":"Changed engagement"}}`)
			if err := runner.Run(ctx, tenant, appendRecord); err != nil {
				t.Fatal(err)
			}
			if err := runner.Run(ctx, "snapshot-b", appendRecord); tenant == "snapshot-a" && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("foreign outbox append %s: %v", eventType, err)
			}
		}
	}
	// Lose the projector before publication. Nothing may acknowledge the sources.
	projectionFailure := errors.New("projector unavailable")
	repo.SetEventProjector(failedSnapshotProjector{NotificationEventProjector: notificationuc.NewEventBuilders(), err: projectionFailure})
	if _, err := source.Poll(ctx, at.Add(time.Minute), 200); !errors.Is(err, projectionFailure) {
		t.Fatalf("failed projection: %v", err)
	}
	// Construct a new worker after the producer committed, with no subject rows to
	// hydrate. Concurrent restart ticks must project every committed source once.
	restartedRepo := NewNotificationRepository(pool)
	restartedRepo.SetEventProjector(notificationuc.NewEventBuilders())
	restarted := NewNotificationSource(pool, restartedRepo, time.Minute)
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := restarted.Poll(ctx, at.Add(2*time.Minute), 200)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := restarted.Poll(ctx, at.Add(3*time.Minute), 200); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []shared.ID{"snapshot-a", "snapshot-b"} {
		var events, processed, deliveries int
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND source_kind='snapshot_test'),
				(SELECT count(*) FROM notification_source_records WHERE tenant_id=$1 AND source_kind='snapshot_test' AND processed_at IS NOT NULL),
				(SELECT count(*) FROM notification_deliveries WHERE tenant_id=$1)`, tenant).Scan(&events, &processed, &deliveries)
		}); err != nil || events != len(types) || processed != len(types) || deliveries != len(types) {
			t.Fatalf("tenant %s event/ack/delivery count %d/%d/%d: %v", tenant, events, processed, deliveries, err)
		}
		for _, eventType := range types {
			list, err := restartedRepo.ListRecentNotificationEvents(ctx, tenant, eventType, 10)
			if err != nil || len(list) != 1 {
				t.Fatalf("%s/%s: %d %v", tenant, eventType, len(list), err)
			}
			event := list[0]
			assertPublishedEventSchema(t, event)
			snapshot, err := notification.DecodeTemplateContext(event.Context)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Vars["engagement_name"] == "Changed engagement" || snapshot.Vars["finding_title"] == "Changed finding" {
				t.Fatal("replay replaced event-time facts")
			}
			foreign := shared.ID("snapshot-b")
			if tenant == foreign {
				foreign = "snapshot-a"
			}
			if _, err := restartedRepo.GetNotificationEvent(ctx, foreign, event.ID); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("foreign event read: %v", err)
			}
			if (notification.Rule{TenantID: foreign, Enabled: true, EventType: event.Type, AllTeams: true}).Matches(event) {
				t.Fatal("foreign rule matched event")
			}
		}
	}
	// The database enforces immutability even when a runtime caller bypasses the
	// producer and tries to update stored snapshot content directly.
	if err := WithTenant(ctx, pool, "snapshot-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_source_records SET context='{}' WHERE tenant_id=$1 AND source_kind='snapshot_test'`, "snapshot-a")
		return err
	}); err == nil {
		t.Fatal("database allowed snapshot facts to be changed")
	}
}

func TestNotificationSnapshotActivationBoundary(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('snapshot-clock','Clock')`); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	if _, err := NewNotificationSource(pool, repo, time.Minute).Poll(ctx, at, 200); err != nil {
		t.Fatal(err)
	}
	for i, delta := range []time.Duration{-time.Microsecond, 0, time.Microsecond} {
		record, err := notification.SnapshotSourceRecord(notification.SourceRecord{
			TenantID: "snapshot-clock", SourceKind: "snapshot_clock", SourceID: fmt.Sprint(i),
			EventType: notification.EventFindingCreated, OccurredAt: at.Add(delta),
			Data: json.RawMessage(`{"title":"Finding created","summary":"A finding was created.","finding_id":"f","engagement_id":"e","finding_kind":"manual","status":"open","finding_version":1}`),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := NewTenantTransactionRunner(pool).Run(ctx, record.TenantID, func(txctx context.Context) error {
			return NewNotificationOutbox(pool).Append(txctx, record)
		}); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := WithTenant(ctx, pool, "snapshot-clock", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records WHERE tenant_id='snapshot-clock'`).Scan(&count)
	}); err != nil || count != 2 {
		t.Fatalf("activation inclusive boundary captures=%d: %v", count, err)
	}
}
