package inbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeDelivery struct {
	message ports.PersonalMessage
	ok      bool
	asked   []string
}

func (f *fakeDelivery) LoadPersonalDelivery(_ context.Context, tenant, user, event, contact shared.ID, version int, channel string) (ports.PersonalMessage, bool, error) {
	f.asked = append(f.asked, channel)
	m := f.message
	m.TenantID, m.UserID, m.EventID, m.ContactID, m.Channel = tenant, user, event, contact, channel
	return m, f.ok, nil
}

type fakeSender struct {
	sent   []ports.PersonalMessage
	result ports.NotificationSendResult
}

func (f *fakeSender) SendPersonal(_ context.Context, m ports.PersonalMessage) ports.NotificationSendResult {
	f.sent = append(f.sent, m)
	return f.result
}

type fakeDefaults struct {
	stored []notification.PersonalDefault
	saved  []string
}

func (f *fakeDefaults) ListPersonalDefaults(context.Context, shared.ID) ([]notification.PersonalDefault, error) {
	return f.stored, nil
}

func (f *fakeDefaults) SavePersonalDefault(_ context.Context, _ shared.ID, actor string, event notification.EventType, channel string, enabled bool, revision int, _ time.Time) (notification.PersonalDefault, error) {
	f.saved = append(f.saved, actor+":"+string(event)+":"+channel)
	return notification.PersonalDefault{EventType: event, Channel: channel, Enabled: enabled, Revision: revision + 1}, nil
}

const jobPayload = `{"event_id":"e","user_id":"u","contact_id":"c","contact_version":1}`

func TestSlackAndTeamsJobsSendThroughTheirSender(t *testing.T) {
	for kind, channel := range map[string]string{SlackJobKind: notification.PersonalSlack, TeamsJobKind: notification.PersonalTeams} {
		t.Run(kind, func(t *testing.T) {
			svc, _ := NewService(&fakeInbox{}, fixedClock{})
			delivery := &fakeDelivery{ok: true, message: ports.PersonalMessage{Recipient: "r", Title: "t"}}
			sender := &fakeSender{}
			svc.SetPersonalDelivery(delivery)
			svc.SetPersonalSender(channel, sender)
			if err := svc.HandleJob(context.Background(), ports.QueuedJob{Kind: kind, TenantID: "tenant", Payload: []byte(jobPayload)}); err != nil {
				t.Fatal(err)
			}
			if len(sender.sent) != 1 || sender.sent[0].Channel != channel || sender.sent[0].TenantID != "tenant" || delivery.asked[0] != channel {
				t.Fatalf("sent = %+v asked = %v", sender.sent, delivery.asked)
			}
		})
	}
}

func TestPersonalChannelJobOutcomes(t *testing.T) {
	svc, _ := NewService(&fakeInbox{}, fixedClock{})
	delivery := &fakeDelivery{ok: false}
	sender := &fakeSender{}
	svc.SetPersonalDelivery(delivery)
	svc.SetPersonalSender(notification.PersonalSlack, sender)
	job := ports.QueuedJob{Kind: SlackJobKind, TenantID: "tenant", Payload: []byte(jobPayload)}
	// A message the reload no longer admits ends without sending.
	if err := svc.HandleJob(context.Background(), job); err != nil || len(sender.sent) != 0 {
		t.Fatalf("stale: err=%v sent=%d", err, len(sender.sent))
	}
	delivery.ok = true
	sender.result = ports.NotificationSendResult{ErrorCode: "slack_ratelimited", Retryable: true, RetryAfter: 30 * time.Second}
	err := svc.HandleJob(context.Background(), job)
	var failure *mailError
	if !errors.As(err, &failure) || failure.Terminal() || failure.RetryAfter() != 30*time.Second {
		t.Fatalf("rate limited: %v", err)
	}
	sender.result = ports.NotificationSendResult{ErrorCode: "slack_workspace_unavailable"}
	if err := svc.HandleJob(context.Background(), job); !errors.As(err, &failure) || !failure.Terminal() {
		t.Fatalf("final failure: %v", err)
	}
	// Teams without a sender is final, never retried.
	if err := svc.HandleJob(context.Background(), ports.QueuedJob{Kind: TeamsJobKind, TenantID: "tenant", Payload: []byte(jobPayload)}); !errors.As(err, &failure) || !failure.Terminal() {
		t.Fatalf("no Teams sender: %v", err)
	}
	if err := svc.HandleJob(context.Background(), ports.QueuedJob{Kind: SlackJobKind, TenantID: "tenant", Payload: []byte(`{"event_id":"e"}`)}); !errors.As(err, &failure) || !failure.Terminal() {
		t.Fatalf("bad payload: %v", err)
	}
	if err := svc.HandleJob(context.Background(), ports.QueuedJob{Kind: "personal.pager", TenantID: "tenant", Payload: []byte(jobPayload)}); !errors.As(err, &failure) || !failure.Terminal() {
		t.Fatalf("unknown kind: %v", err)
	}
}

func TestTeamsPreferenceNeedsTheOperatorBot(t *testing.T) {
	svc, _ := NewService(&fakeInbox{}, fixedClock{})
	if _, err := svc.SavePreference(context.Background(), "tenant", "user", notification.EventOwnershipChanged, notification.PersonalTeams, notification.PreferenceEnabled, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Teams without a bot: %v", err)
	}
	// Muting it is always allowed.
	if _, err := svc.SavePreference(context.Background(), "tenant", "user", notification.EventOwnershipChanged, notification.PersonalTeams, notification.PreferenceDisabled, 0); err != nil {
		t.Fatal(err)
	}
	svc.SetTeamsAvailable(true)
	if _, err := svc.SavePreference(context.Background(), "tenant", "user", notification.EventOwnershipChanged, notification.PersonalTeams, notification.PreferenceEnabled, 0); err != nil {
		t.Fatal(err)
	}
	for _, channel := range []string{notification.PersonalSlack, notification.PersonalEmail} {
		if _, err := svc.SavePreference(context.Background(), "tenant", "user", notification.EventOwnershipChanged, channel, notification.PreferenceEnabled, 0); err != nil {
			t.Fatalf("%s: %v", channel, err)
		}
	}
	if _, err := svc.SavePreference(context.Background(), "tenant", "user", notification.EventOwnershipChanged, "sms", notification.PreferenceEnabled, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown channel: %v", err)
	}
}

type prefInbox struct {
	fakeInbox
	items []ports.InboxPreference
}

func (p *prefInbox) ListInboxPreferences(context.Context, shared.ID, shared.ID) ([]ports.InboxPreference, error) {
	return p.items, nil
}

func TestPreferencesMarkTeamsUnavailableWithoutTheBot(t *testing.T) {
	store := &prefInbox{items: []ports.InboxPreference{{Channel: notification.PersonalTeams, Available: true}, {Channel: notification.PersonalSlack, Available: true}}}
	svc, _ := NewService(store, fixedClock{})
	items, err := svc.Preferences(context.Background(), "tenant", "user")
	if err != nil || items[0].Available || items[0].Reason == "" || !items[1].Available {
		t.Fatalf("items = %+v %v", items, err)
	}
}

func TestPersonalDefaultsMatrixAndSave(t *testing.T) {
	svc, _ := NewService(&fakeInbox{}, fixedClock{at: time.Unix(1700000000, 0)})
	if _, err := svc.PersonalDefaults(context.Background(), "tenant"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("without a store: %v", err)
	}
	defaults := &fakeDefaults{stored: []notification.PersonalDefault{{EventType: notification.EventOwnershipChanged, Channel: notification.PersonalSlack, Enabled: true, Revision: 2}}}
	svc.SetPersonalDefaults(defaults)
	items, err := svc.PersonalDefaults(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	want := (len(notification.ConfigurableEvents()) + 2) * len(notification.ExternalPersonalChannels())
	if len(items) != want {
		t.Fatalf("items = %d, want %d", len(items), want)
	}
	for _, item := range items {
		stored := item.EventType == notification.EventOwnershipChanged && item.Channel == notification.PersonalSlack
		if stored != !item.Builtin || (stored && (!item.Enabled || item.Revision != 2)) || (!stored && item.Enabled) {
			t.Fatalf("item = %+v", item)
		}
	}
	if _, err := svc.SavePersonalDefault(context.Background(), "tenant", "ada", PersonalDefaultInput{EventType: notification.EventScanCompleted, Channel: notification.PersonalEmail, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]PersonalDefaultInput{
		"inbox":    {EventType: notification.EventScanCompleted, Channel: notification.PersonalInApp, Enabled: false},
		"unknown":  {EventType: notification.EventScanCompleted, Channel: "sms", Enabled: true},
		"test":     {EventType: notification.EventTest, Channel: notification.PersonalEmail, Enabled: true},
		"negative": {EventType: notification.EventScanCompleted, Channel: notification.PersonalEmail, Enabled: true, Revision: -1},
	} {
		if _, err := svc.SavePersonalDefault(context.Background(), "tenant", "ada", in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(defaults.saved) != 1 || defaults.saved[0] != "ada:scan.completed:email" {
		t.Fatalf("saved = %v", defaults.saved)
	}
}
