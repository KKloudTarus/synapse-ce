package teamslink

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	serviceURL = "https://smba.trafficmanager.net/amer/"
	personOID  = "0a0b0c0d-1111-2222-3333-444455556666"
)

type sentActivity struct {
	ref  ports.TeamsConversationRef
	body string
}

type fakeBot struct {
	mu   sync.Mutex
	sent []sentActivity
	err  error
}

func (b *fakeBot) Send(_ context.Context, ref ports.TeamsConversationRef, activity []byte) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, sentActivity{ref, string(activity)})
	if b.err != nil {
		return "", b.err
	}
	return "activity-1", nil
}

type botError struct{ result ports.NotificationSendResult }

func (e botError) Error() string                             { return "teams bot: " + e.result.ErrorCode }
func (e botError) TeamsResult() ports.NotificationSendResult { return e.result }

// memoryOffers mirrors the SECURITY DEFINER functions of migration 0224.
type memoryOffers struct {
	mu     sync.Mutex
	now    func() time.Time
	offers map[string]offer
}

type offer struct {
	conversation, sealed string
	expires              time.Time
}

func (m *memoryOffers) OfferTeamsLink(_ context.Context, digest, conversation, sealed string, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	live := 0
	for _, o := range m.offers {
		if o.conversation == conversation && o.expires.After(m.now()) {
			live++
		}
	}
	if live >= 3 {
		return false, nil
	}
	m.offers[digest] = offer{conversation, sealed, expires}
	return true, nil
}

func (m *memoryOffers) ClaimTeamsLink(_ context.Context, digest string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.offers[digest]
	delete(m.offers, digest)
	if !ok || !o.expires.After(m.now()) {
		return "", false, nil
	}
	return o.sealed, true, nil
}

type memoryContacts struct {
	mu            sync.Mutex
	attempts      int
	quota         int
	linked        []ports.UserContact
	conversations map[shared.ID]string
}

func (m *memoryContacts) LinkTeamsContact(_ context.Context, c ports.UserContact, sealed string) (ports.UserContact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.linked = append(m.linked, c)
	m.conversations[c.ID] = sealed
	return c, nil
}

func (m *memoryContacts) CountTeamsLinkAttempt(context.Context, shared.ID, shared.ID, shared.ID, time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.attempts >= m.quota {
		return shared.ErrConflict
	}
	m.attempts++
	return nil
}

func (m *memoryContacts) TeamsConversation(_ context.Context, _, contact shared.ID) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sealed, ok := m.conversations[contact]
	return sealed, ok, nil
}

type clock struct{ at time.Time }

func (c *clock) Now() time.Time { return c.at }

type fixture struct {
	svc      *Service
	bot      *fakeBot
	offers   *memoryOffers
	contacts *memoryContacts
	clock    *clock
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{bot: &fakeBot{}, contacts: &memoryContacts{quota: 5, conversations: map[shared.ID]string{}}, clock: &clock{at: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)}}
	f.offers = &memoryOffers{now: f.clock.Now, offers: map[string]offer{}}
	f.svc, err = NewService(Config{Bot: f.bot, Offers: f.offers, Contacts: f.contacts, Protector: cipher, IDs: idgen.RandomID{}, Clock: f.clock,
		Key: DeriveKey("master"), AcceptsServiceURL: func(raw string) bool { return raw == serviceURL }, Formatter: messageformat.TeamsFormatter{}, PublicBaseURL: "https://synapse.example"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func personalMessage() ports.TeamsActivity {
	return ports.TeamsActivity{Type: "message", Text: "hi", ServiceURL: serviceURL, ConversationID: "a:1conv", ConversationType: "personal", FromObjectID: strings.ToUpper(personOID), TenantID: "tenant-entra"}
}

var codePattern = regexp.MustCompile(`code is ([0-9A-Z]{5}-[0-9A-Z]{5})\.`)

// The bot answers a 1:1 message with a code, which links the person in their profile.
func (f fixture) requestCode(t *testing.T) string {
	t.Helper()
	if err := f.svc.HandleActivity(context.Background(), personalMessage()); err != nil {
		t.Fatal(err)
	}
	last := f.bot.sent[len(f.bot.sent)-1]
	match := codePattern.FindStringSubmatch(last.body)
	if match == nil {
		t.Fatalf("reply has no code: %s", last.body)
	}
	return match[1]
}

func TestLinkFlowStoresAVerifiedContactAndItsConversation(t *testing.T) {
	f := newFixture(t)
	code := f.requestCode(t)
	reply := f.bot.sent[0]
	if reply.ref.ConversationID != "a:1conv" || reply.ref.UserObjectID != personOID {
		t.Fatalf("reply went to %+v", reply.ref)
	}
	contact, err := f.svc.Link(context.Background(), "tenant-a", "ada", " "+strings.ToLower(code)+" ")
	if err != nil {
		t.Fatal(err)
	}
	if contact.Kind != "teams" || contact.Value != personOID || contact.VerifiedAt == nil || contact.UserID != "ada" || contact.TenantID != "tenant-a" {
		t.Fatalf("contact = %+v", contact)
	}
	// The stored conversation is sealed for the tenant and contact, and opens to the reference.
	sealed := f.contacts.conversations[contact.ID]
	if strings.Contains(sealed, "a:1conv") || strings.Contains(sealed, personOID) {
		t.Fatalf("the conversation is stored in clear: %s", sealed)
	}
	// A code works once.
	if _, err := f.svc.Link(context.Background(), "tenant-a", "ada", code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("second use: %v", err)
	}
}

func TestLinkRefusesWrongExpiredAndMalformedCodes(t *testing.T) {
	f := newFixture(t)
	code := f.requestCode(t)
	for _, bad := range []string{"AAAAA-AAAAA", "short", "ABCDE-FGHJ!", strings.Repeat("A", 70)} {
		if _, err := f.svc.Link(context.Background(), "tenant-a", "ada", bad); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	f.clock.at = f.clock.at.Add(11 * time.Minute)
	if _, err := f.svc.Link(context.Background(), "tenant-a", "ada", code); !errors.Is(err, shared.ErrConflict) && !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expired code: %v", err)
	}
}

func TestLinkAttemptsAreRateLimitedBeforeTheCodeIsTried(t *testing.T) {
	f := newFixture(t)
	code := f.requestCode(t)
	f.contacts.quota = 0
	if _, err := f.svc.Link(context.Background(), "tenant-a", "ada", code); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("over quota: %v", err)
	}
	// The refused attempt did not burn the code.
	f.contacts.quota = 5
	if _, err := f.svc.Link(context.Background(), "tenant-a", "ada", code); err != nil {
		t.Fatalf("code after quota reset: %v", err)
	}
}

func TestBotIgnoresEverythingButAPersonalMessage(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*ports.TeamsActivity){
		"channel message":     func(a *ports.TeamsActivity) { a.ConversationType = "channel" },
		"group chat":          func(a *ports.TeamsActivity) { a.ConversationType = "groupChat" },
		"typing":              func(a *ports.TeamsActivity) { a.Type = "typing" },
		"foreign service url": func(a *ports.TeamsActivity) { a.ServiceURL = "https://evil.example/" },
		"no object id":        func(a *ports.TeamsActivity) { a.FromObjectID = "" },
		"not an object id":    func(a *ports.TeamsActivity) { a.FromObjectID = "29:1abc" },
	} {
		a := personalMessage()
		mutate(&a)
		if err := f.svc.HandleActivity(context.Background(), a); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if len(f.bot.sent) != 0 || len(f.offers.offers) != 0 {
		t.Fatalf("ignored activities produced %d replies and %d offers", len(f.bot.sent), len(f.offers.offers))
	}
}

func TestBotCapsLiveCodesPerConversation(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 3; i++ {
		f.requestCode(t)
	}
	if err := f.svc.HandleActivity(context.Background(), personalMessage()); err != nil {
		t.Fatal(err)
	}
	if last := f.bot.sent[len(f.bot.sent)-1].body; !strings.Contains(last, "already have Synapse link codes") {
		t.Fatalf("fourth reply = %s", last)
	}
	// Offers hold only digests and sealed references.
	for digest, o := range f.offers.offers {
		if len(digest) != 64 || strings.Contains(o.sealed, "a:1conv") || strings.Contains(o.sealed, personOID) {
			t.Fatalf("offer stored in clear: %s %+v", digest, o)
		}
	}
}

func TestSendPersonalPostsAnAdaptiveCardIntoTheLinkedConversation(t *testing.T) {
	f := newFixture(t)
	contact, err := f.svc.Link(context.Background(), "tenant-a", "ada", f.requestCode(t))
	if err != nil {
		t.Fatal(err)
	}
	result := f.svc.SendPersonal(context.Background(), ports.PersonalMessage{TenantID: "tenant-a", UserID: "ada", ContactID: contact.ID, Recipient: personOID,
		Title: "Finding ownership changed", Summary: "[Reset](https://evil.example) <at>everyone</at>", LinkPath: "/engagements/e1/findings#finding-f1"})
	if result.ErrorCode != "" || result.RemoteRef != "activity-1" {
		t.Fatalf("result = %+v", result)
	}
	last := f.bot.sent[len(f.bot.sent)-1]
	if last.ref.ConversationID != "a:1conv" {
		t.Fatalf("sent to %+v", last.ref)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(last.body), &payload); err != nil || payload["type"] != "message" || !strings.Contains(last.body, "application/vnd.microsoft.card.adaptive") {
		t.Fatalf("payload = %s", last.body)
	}
	if !strings.Contains(last.body, `"url":"https://synapse.example/engagements/e1/findings#finding-f1"`) || strings.Contains(last.body, `"url":"https://evil.example"`) {
		t.Fatalf("links = %s", last.body)
	}
}

func TestSendPersonalRefusesAMismatchedOrMissingConversation(t *testing.T) {
	f := newFixture(t)
	contact, err := f.svc.Link(context.Background(), "tenant-a", "ada", f.requestCode(t))
	if err != nil {
		t.Fatal(err)
	}
	if r := f.svc.SendPersonal(context.Background(), ports.PersonalMessage{TenantID: "tenant-a", ContactID: contact.ID, Recipient: "ffffffff-1111-2222-3333-444455556666"}); r.ErrorCode != "teams_conversation_invalid" {
		t.Fatalf("other recipient: %+v", r)
	}
	// A conversation sealed for another tenant does not open.
	if r := f.svc.SendPersonal(context.Background(), ports.PersonalMessage{TenantID: "tenant-b", ContactID: contact.ID, Recipient: personOID}); r.ErrorCode != "teams_conversation_unavailable" {
		t.Fatalf("other tenant: %+v", r)
	}
	if r := f.svc.SendPersonal(context.Background(), ports.PersonalMessage{TenantID: "tenant-a", ContactID: "missing", Recipient: personOID}); r.ErrorCode != "teams_conversation_missing" {
		t.Fatalf("missing: %+v", r)
	}
	f.bot.err = botError{ports.NotificationSendResult{ErrorCode: "teams_conversation_gone"}}
	if r := f.svc.SendPersonal(context.Background(), ports.PersonalMessage{TenantID: "tenant-a", ContactID: contact.ID, Recipient: personOID, Title: "x"}); r.ErrorCode != "teams_conversation_gone" || r.Retryable {
		t.Fatalf("bot error: %+v", r)
	}
}

func TestNewServiceRequiresItsDependencies(t *testing.T) {
	if _, err := NewService(Config{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v", err)
	}
}
