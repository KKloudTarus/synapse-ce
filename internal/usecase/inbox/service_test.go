package inbox

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeInbox struct {
	cutoff time.Time
	items  []ports.InboxItem
}

func (f *fakeInbox) ListInbox(context.Context, shared.ID, shared.ID, time.Time, shared.ID, bool, int) ([]ports.InboxItem, error) {
	return f.items, nil
}
func (f *fakeInbox) UnreadInbox(context.Context, shared.ID, shared.ID) (int, error) { return 0, nil }
func (f *fakeInbox) MarkInboxRead(context.Context, shared.ID, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (f *fakeInbox) MarkInboxAllRead(_ context.Context, _, _ shared.ID, cutoff time.Time) error {
	f.cutoff = cutoff
	return nil
}
func (f *fakeInbox) ListInboxPreferences(context.Context, shared.ID, shared.ID) ([]ports.InboxPreference, error) {
	return nil, nil
}
func (f *fakeInbox) SaveInboxPreference(context.Context, shared.ID, shared.ID, notification.EventType, string, notification.Preference, int, time.Time) (ports.InboxPreference, error) {
	return ports.InboxPreference{}, nil
}
func (f *fakeInbox) LoadPersonalMail(context.Context, shared.ID, shared.ID, shared.ID, shared.ID, int) (string, string, string, bool, error) {
	return "", "", "", false, nil
}

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

func TestMarkAllUsesRequestCutoff(t *testing.T) {
	store := &fakeInbox{}
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	svc, err := NewService(store, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.MarkAllRead(context.Background(), "tenant", "user"); err != nil {
		t.Fatal(err)
	}
	if !store.cutoff.Equal(now) {
		t.Fatalf("cutoff %s", store.cutoff)
	}
}

func TestCursorBindsUnreadFilter(t *testing.T) {
	at := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	svc, err := NewService(&fakeInbox{items: []ports.InboxItem{{ID: "n", CreatedAt: at}}}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	page, err := svc.List(context.Background(), "tenant", "user", "", true, 1)
	if err != nil || page.Next == "" {
		t.Fatalf("cursor %q: %v", page.Next, err)
	}
	if _, err := svc.List(context.Background(), "tenant", "user", page.Next, false, 1); err == nil {
		t.Fatal("unread cursor was accepted for the full inbox")
	}
}

func TestCursorRejectsTampering(t *testing.T) {
	svc, err := NewService(&fakeInbox{}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.List(context.Background(), "tenant", "user", "not-a-cursor", false, 25); err == nil {
		t.Fatal("expected invalid cursor")
	}
}

func TestMandatoryInAppCannotBeMuted(t *testing.T) {
	svc, err := NewService(&fakeInbox{}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.SavePreference(context.Background(), "tenant", "user", notification.EventDestinationChanged, notification.PersonalInApp, notification.PreferenceDisabled, 0)
	if err == nil {
		t.Fatal("expected mandatory preference to be rejected")
	}
}

func TestStalePersonalMailIsNotRetargeted(t *testing.T) {
	svc, err := NewService(&fakeInbox{}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	svc.SetMailer(mailFunc(func(context.Context, string, string, string, shared.ID) ports.NotificationSendResult {
		called = true
		return ports.NotificationSendResult{}
	}))
	err = svc.HandleJob(context.Background(), ports.QueuedJob{Kind: JobKind, TenantID: "tenant", Payload: []byte(`{"event_id":"e","user_id":"u","contact_id":"c","contact_version":2}`)})
	if err != nil || called {
		t.Fatalf("stale mail err=%v called=%v", err, called)
	}
}

type mailFunc func(context.Context, string, string, string, shared.ID) ports.NotificationSendResult

func (f mailFunc) SendPersonalNotice(ctx context.Context, recipient, title, summary string, id shared.ID) ports.NotificationSendResult {
	return f(ctx, recipient, title, summary, id)
}
