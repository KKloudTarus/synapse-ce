package notification

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRuleUpdateRequiresSavedDeliveryFields(t *testing.T) {
	for _, cadence := range []domain.DeliveryCadence{domain.CadenceHourly, domain.CadenceDaily} {
		for _, field := range []string{"cadence", "recipient_user_ids", "both", "null recipients"} {
			t.Run(string(cadence)+"/"+field, func(t *testing.T) {
				f := newBindingFixture(t)
				channel := f.slackChannel(t)
				created, err := f.svc.CreateRule(f.ctx, "ada", RuleInput{
					Name: "Saved targets", Enabled: true, EventType: domain.EventScanCompleted,
					ChannelIDs: []shared.ID{channel.ID}, Cadence: cadence, RecipientUserIDs: []shared.ID{"saved-person"},
				})
				if err != nil {
					t.Fatal(err)
				}
				body := map[string]any{"name": "Renamed", "enabled": true, "event_type": created.EventType,
					"channel_ids": created.ChannelIDs, "revision": created.Revision,
					"cadence": cadence, "recipient_user_ids": []string{"saved-person"}}
				switch field {
				case "cadence":
					delete(body, "cadence")
				case "recipient_user_ids":
					delete(body, "recipient_user_ids")
				case "both":
					delete(body, "cadence")
					delete(body, "recipient_user_ids")
				case "null recipients":
					body["recipient_user_ids"] = nil
				}
				wire, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				var in RuleInput
				if err := json.Unmarshal(wire, &in); err != nil {
					t.Fatal(err)
				}
				if _, err := f.svc.UpdateRule(f.ctx, "ada", created.ID, in); !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("omitted %s: want validation error, got %v", field, err)
				}
				stored, err := f.repo.GetRule(f.ctx, created.TenantID, created.ID)
				if err != nil || !reflect.DeepEqual(stored, created) {
					t.Fatalf("rejected update changed saved rule: %+v err=%v", stored, err)
				}
				// An explicit choice to restore immediate delivery and remove people remains valid.
				in.Cadence, in.RecipientUserIDs = domain.CadenceImmediate, []shared.ID{}
				updated, err := f.svc.UpdateRule(f.ctx, "ada", created.ID, in)
				if err != nil || updated.Cadence != domain.CadenceImmediate || len(updated.RecipientUserIDs) != 0 {
					t.Fatalf("explicit clear: %+v err=%v", updated, err)
				}
			})
		}
	}
}

func TestLegacyImmediateRuleUpdateAllowsOmittedDeliveryFields(t *testing.T) {
	f := newBindingFixture(t)
	channel := f.slackChannel(t)
	in := RuleInput{Name: "Legacy", Enabled: true, EventType: domain.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}}
	created, err := f.svc.CreateRule(f.ctx, "ada", in)
	if err != nil {
		t.Fatal(err)
	}
	in.Revision, in.Name = created.Revision, "Renamed legacy"
	updated, err := f.svc.UpdateRule(f.ctx, "ada", created.ID, in)
	if err != nil || updated.Cadence != domain.CadenceImmediate || len(updated.RecipientUserIDs) != 0 {
		t.Fatalf("legacy update: %+v err=%v", updated, err)
	}
}
