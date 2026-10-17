package postgres

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestNotificationRuleLegacyUpdatesPreserveDigestAndRecipients(t *testing.T) {
	pool := notificationTestPool(t)
	for _, cadence := range []notification.DeliveryCadence{notification.CadenceHourly, notification.CadenceDaily} {
		t.Run(string(cadence), func(t *testing.T) {
			f := newPostgresDigestFixture(t, pool, shared.ID("rule-update-"+string(cadence)), cadence)
			rule := f.rule
			rule.RecipientUserIDs = []shared.ID{"missing-saved-person"}
			rule.Revision++
			stored, err := f.repo.UpdateRule(f.ctx, rule)
			if err != nil {
				t.Fatal(err)
			}
			stored, err = f.repo.GetRule(f.ctx, f.tenant, stored.ID)
			if err != nil {
				t.Fatal(err)
			}
			f.publish(t, "pending-source", "", notification.EventScanCompleted, shared.SeverityMedium)
			service, err := notificationuc.NewService(f.repo, notificationEmailTestProtector{}, nil, NewAuditLog(pool), &notificationTestClock{at: f.at}, &notificationTestIDs{})
			if err != nil {
				t.Fatal(err)
			}
			service.SetTransactionRunner(NewTenantTransactionRunner(pool))
			for _, field := range []string{"cadence", "recipient_user_ids", "both"} {
				in := notificationuc.RuleInput{Name: "Renamed", Enabled: true, EventType: stored.EventType,
					ChannelIDs: stored.ChannelIDs, Cadence: cadence, RecipientUserIDs: stored.RecipientUserIDs, Revision: stored.Revision}
				if field == "cadence" || field == "both" {
					in.Cadence = ""
				}
				if field == "recipient_user_ids" || field == "both" {
					in.RecipientUserIDs = nil
				}
				if _, err := service.UpdateRule(f.ctx, "admin", stored.ID, in); !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("omitted %s: want validation error, got %v", field, err)
				}
				loaded, err := f.repo.GetRule(f.ctx, f.tenant, stored.ID)
				if err != nil || !reflect.DeepEqual(loaded, stored) {
					t.Fatalf("rejected update changed persisted rule: %+v err=%v", loaded, err)
				}
			}
			if n, err := f.materialize(f.ctx, f.at.Add(48*time.Hour), 10); err != nil || n != 1 {
				t.Fatalf("retained pending window: materialized=%d err=%v", n, err)
			}
			page, err := f.repo.ListDeliveries(f.ctx, ports.NotificationDeliveryFilter{TenantID: f.tenant})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("retained digest deliveries=%+v err=%v", page, err)
			}
			work, err := f.repo.LoadWork(f.ctx, f.tenant, page.Items[0].ID)
			if err != nil || work.Event.Type != notification.EventDigest || len(work.Event.DigestItems) != 1 || work.Event.DigestItems[0].Event.ID != "pending-source" {
				t.Fatalf("retained digest work=%+v err=%v", work, err)
			}
			updated, err := service.UpdateRule(f.ctx, "admin", stored.ID, notificationuc.RuleInput{
				Name: stored.Name, Enabled: true, EventType: stored.EventType, ChannelIDs: stored.ChannelIDs,
				Cadence: notification.CadenceImmediate, RecipientUserIDs: []shared.ID{}, Revision: stored.Revision,
			})
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := f.repo.GetRule(f.ctx, f.tenant, stored.ID)
			if err != nil || loaded.Cadence != notification.CadenceImmediate || len(loaded.RecipientUserIDs) != 0 || loaded.Revision != updated.Revision {
				t.Fatalf("explicit clearing roundtrip: %+v err=%v", loaded, err)
			}
		})
	}
}
