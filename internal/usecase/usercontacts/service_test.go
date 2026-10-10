package usercontacts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeStore struct {
	contacts  []ports.UserContact
	created   []ports.UserContact
	challenge ports.UserContactChallenge
	delivery  ports.UserContactDelivery
	sent      bool
}

func (f *fakeStore) List(context.Context, shared.ID, shared.ID) ([]ports.UserContact, error) {
	return f.contacts, nil
}
func (f *fakeStore) Create(_ context.Context, c ports.UserContact) (ports.UserContact, error) {
	f.created = append(f.created, c)
	return c, nil
}
func (f *fakeStore) Delete(context.Context, shared.ID, shared.ID, shared.ID) error { return nil }
func (f *fakeStore) RequestVerification(_ context.Context, c ports.UserContactChallenge, _ shared.ID) error {
	f.challenge = c
	return nil
}
func (f *fakeStore) Verify(context.Context, shared.ID, shared.ID, shared.ID, func(shared.ID) string, time.Time) (ports.UserContact, error) {
	return ports.UserContact{}, nil
}
func (f *fakeStore) LoadDelivery(context.Context, shared.ID, shared.ID) (ports.UserContactDelivery, bool, error) {
	return f.delivery, f.delivery.ChallengeID != "", nil
}
func (f *fakeStore) MarkSent(context.Context, shared.ID, shared.ID, time.Time) error {
	f.sent = true
	return nil
}
func (f *fakeStore) MarkDeliveryFailed(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (f *fakeStore) ImportOIDCEmail(context.Context, shared.ID, shared.ID, shared.ID, string, string, time.Time) error {
	return nil
}
func (f *fakeStore) RevokeOIDCEmail(context.Context, shared.ID, shared.ID, string, time.Time) error {
	return nil
}

type fakeUsers struct{ ports.UserRepository }

type fakeSlack struct {
	checked []string
	codes   []string
	result  ports.NotificationSendResult
	refuse  error
}

func (f *fakeSlack) CheckSlackMember(_ context.Context, _ shared.ID, team, member string) error {
	f.checked = append(f.checked, team+":"+member)
	return f.refuse
}

func (f *fakeSlack) SendSlackVerification(_ context.Context, _ shared.ID, recipient, code string) ports.NotificationSendResult {
	f.codes = append(f.codes, recipient+"="+code)
	return f.result
}

type fakeMailer struct{ sent int }

func (m *fakeMailer) SendContactVerification(context.Context, string, string, shared.ID) ports.NotificationSendResult {
	m.sent++
	return ports.NotificationSendResult{}
}

type clock struct{}

func (clock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

func newTestService(t *testing.T, store *fakeStore, mailer ports.UserContactMailer, mail bool) (*Service, *vault.Cipher) {
	t.Helper()
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(store, fakeUsers{}, cipher, mailer, idgen.RandomID{}, clock{}, DeriveVerifierKey("master"), mail)
	if err != nil {
		t.Fatal(err)
	}
	return svc, cipher
}

func TestAddSlackChecksTheMemberWithTheWorkspaceApp(t *testing.T) {
	store := &fakeStore{}
	svc, _ := newTestService(t, store, nil, false)
	if _, err := svc.AddSlack(context.Background(), "tenant", "ada", "T0123", "U0ADA"); !errors.Is(err, ErrSlackUnavailable) {
		t.Fatalf("without Slack: %v", err)
	}
	slack := &fakeSlack{}
	svc.SetSlack(slack)
	contact, err := svc.AddSlack(context.Background(), "tenant", "ada", " T0123 ", " U0ADA ")
	if err != nil {
		t.Fatal(err)
	}
	if contact.Kind != "slack" || contact.Value != "T0123:U0ADA" || contact.VerifiedAt != nil || slack.checked[0] != "T0123:U0ADA" {
		t.Fatalf("contact = %+v checked = %v", contact, slack.checked)
	}
	// An email or a name is never accepted as a member, and nothing is looked up for it.
	if _, err := svc.AddSlack(context.Background(), "tenant", "ada", "T0123", "ada@example.com"); !errors.Is(err, shared.ErrValidation) || len(slack.checked) != 1 {
		t.Fatalf("email as member: %v", err)
	}
	slack.refuse = errors.New("not a member")
	if _, err := svc.AddSlack(context.Background(), "tenant", "ada", "T0123", "U0FAR"); err == nil || len(store.created) != 1 {
		t.Fatalf("refused member: %v created=%d", err, len(store.created))
	}
}

func TestSlackVerificationDoesNotNeedSMTP(t *testing.T) {
	store := &fakeStore{contacts: []ports.UserContact{{ID: "c1", Kind: "slack", Value: "T0123:U0ADA", Version: 1}, {ID: "c2", Kind: "email", Value: "ada@example.com", Version: 1}}}
	svc, _ := newTestService(t, store, nil, false)
	if err := svc.RequestVerification(context.Background(), "tenant", "ada", "c1"); !errors.Is(err, ErrSlackUnavailable) {
		t.Fatalf("Slack without the app: %v", err)
	}
	svc.SetSlack(&fakeSlack{})
	if err := svc.RequestVerification(context.Background(), "tenant", "ada", "c1"); err != nil {
		t.Fatalf("Slack verification: %v", err)
	}
	if store.challenge.ContactID != "c1" {
		t.Fatalf("challenge = %+v", store.challenge)
	}
	if err := svc.RequestVerification(context.Background(), "tenant", "ada", "c2"); !errors.Is(err, ErrMailUnavailable) {
		t.Fatalf("email without SMTP: %v", err)
	}
}

func TestSendVerificationRoutesByContactKind(t *testing.T) {
	store := &fakeStore{}
	mailer := &fakeMailer{}
	svc, cipher := newTestService(t, store, mailer, true)
	slack := &fakeSlack{}
	svc.SetSlack(slack)
	sealed, err := cipher.Seal([]byte("12345678"), challengeAAD("tenant", "ch1", "c1", 1))
	if err != nil {
		t.Fatal(err)
	}
	store.delivery = ports.UserContactDelivery{ChallengeID: "ch1", ContactID: "c1", ContactVersion: 1, Recipient: "T0123:U0ADA", SealedCode: sealed, Kind: "slack"}
	if err := svc.SendVerification(context.Background(), "tenant", "ch1"); err != nil {
		t.Fatal(err)
	}
	if len(slack.codes) != 1 || slack.codes[0] != "T0123:U0ADA=12345678" || mailer.sent != 0 || !store.sent {
		t.Fatalf("slack codes = %v mail = %d sent = %v", slack.codes, mailer.sent, store.sent)
	}
	slack.result = ports.NotificationSendResult{ErrorCode: "slack_ratelimited", Retryable: true}
	store.sent = false
	if err := svc.SendVerification(context.Background(), "tenant", "ch1"); err == nil || errors.Is(err, ErrSlackUnavailable) || store.sent {
		t.Fatalf("transient Slack failure: %v", err)
	}
	slack.result = ports.NotificationSendResult{ErrorCode: "slack_workspace_unavailable"}
	if err := svc.SendVerification(context.Background(), "tenant", "ch1"); !errors.Is(err, ErrSlackUnavailable) {
		t.Fatalf("final Slack failure: %v", err)
	}
	store.delivery.Kind, store.delivery.Recipient = "email", "ada@example.com"
	sealed, _ = cipher.Seal([]byte("87654321"), challengeAAD("tenant", "ch1", "c1", 1))
	store.delivery.SealedCode = sealed
	if err := svc.SendVerification(context.Background(), "tenant", "ch1"); err != nil || mailer.sent != 1 {
		t.Fatalf("email: %v sent=%d", err, mailer.sent)
	}
}
