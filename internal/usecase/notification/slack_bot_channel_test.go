package notification

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	slackToken      = "xoxb" + "-1111111111-2222222222-slackBOTsecretValue"
	otherSlackToken = "xoxb" + "-3333333333-4444444444-otherBOTsecretValue"
)

type slackCode string

func (c slackCode) Error() string     { return "slack api: " + string(c) }
func (c slackCode) SlackCode() string { return string(c) }

// fakeWorkspace is a Slack workspace with a table of conversations. It records which token each
// call used and whether a call happened inside a transaction.
type fakeWorkspace struct {
	mu            sync.Mutex
	team          string
	conversations map[string]ports.SlackConversation
	identifyErr   error
	listErr       error
	tokens        []string
	calls         int
	inTx          *bool
}

func newFakeWorkspace() *fakeWorkspace {
	return &fakeWorkspace{team: "T0123", conversations: map[string]ports.SlackConversation{
		"C0000000001": {ID: "C0000000001", Name: "security", Member: true},
		"C0000000002": {ID: "C0000000002", Name: "connect", Shared: true, Member: true},
		"C0000000003": {ID: "C0000000003", Name: "old", Archived: true},
		"G0000000004": {ID: "G0000000004", Name: "private-out", Private: true},
		"C0000000005": {ID: "C0000000005", Name: "alerts", Member: true},
	}}
}

func (w *fakeWorkspace) record(token string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.tokens = append(w.tokens, token)
	w.calls++
	if w.inTx != nil && *w.inTx {
		panic("a Slack call ran inside the administration transaction")
	}
}

func (w *fakeWorkspace) Identify(_ context.Context, token string) (ports.SlackIdentity, error) {
	w.record(token)
	if w.identifyErr != nil {
		return ports.SlackIdentity{}, w.identifyErr
	}
	return ports.SlackIdentity{TeamID: w.team, TeamName: "Acme", BotUserID: "U0BOT"}, nil
}

func (w *fakeWorkspace) Conversation(_ context.Context, token, id string) (ports.SlackConversation, error) {
	w.record(token)
	c, ok := w.conversations[id]
	if !ok {
		return ports.SlackConversation{}, slackCode("channel_not_found")
	}
	return c, nil
}

func (w *fakeWorkspace) Conversations(_ context.Context, token string) ([]ports.SlackConversation, bool, error) {
	w.record(token)
	if w.listErr != nil {
		return nil, false, w.listErr
	}
	out := make([]ports.SlackConversation, 0, len(w.conversations))
	for _, c := range w.conversations {
		out = append(out, c)
	}
	out = append(out, ports.SlackConversation{ID: "D0000000009", Name: "a-dm"})
	return out, true, nil
}

// txFlag is a transaction runner that marks the time a transaction is open.
type txFlag struct{ open bool }

func (t *txFlag) Run(ctx context.Context, _ shared.ID, fn func(context.Context) error) error {
	t.open = true
	defer func() { t.open = false }()
	return fn(ctx)
}

type recordedAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
}

func (a *recordedAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

type slackFixture struct {
	ctx       context.Context
	svc       *Service
	repo      *memory.NotificationRepository
	workspace *fakeWorkspace
	audit     *recordedAudit
	tx        *txFlag
}

func newSlackFixture(t *testing.T) slackFixture {
	t.Helper()
	clock := &stepClock{at: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)}
	jobs := memory.NewJobQueue(idgen.RandomID{}, clock.Now)
	repo := memory.NewNotificationRepository(jobs, clock.Now)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	audit := &recordedAudit{}
	svc, err := NewService(repo, cipher, nil, audit, clock, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	f := slackFixture{ctx: shared.WithTenant(context.Background(), "tenant-s"), svc: svc, repo: repo, workspace: newFakeWorkspace(), audit: audit, tx: &txFlag{}}
	f.workspace.inTx = &f.tx.open
	svc.SetSlackWorkspace(f.workspace)
	svc.SetTransactionRunner(f.tx)
	return f
}

func (f slackFixture) create(t *testing.T, conversation string, allowShared bool) (domain.Channel, error) {
	t.Helper()
	return f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "Security", Type: domain.ChannelSlackBot, Enabled: true, Secret: slackToken, ConversationID: conversation, AllowSharedConversation: allowShared})
}

// sealedConfig opens the configuration the repository stored for a channel.
func (f slackFixture) sealedConfig(t *testing.T, id shared.ID) ports.SlackBotChannelConfig {
	t.Helper()
	cfg, err := f.svc.openSlackBotConfig(f.ctx, "tenant-s", id)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSlackBotChannelValidation(t *testing.T) {
	good := ChannelInput{Name: "ops", Type: domain.ChannelSlackBot, Secret: " " + slackToken + " ", ConversationID: " C0123456789 ", AllowSharedConversation: true}
	config, destination, recipients, err := validateChannel(good, true)
	if err != nil || destination != "https://slack.com/…" || recipients != nil {
		t.Fatalf("valid input: %#v %q %v", config, destination, err)
	}
	if got := config.(ports.SlackBotChannelConfig); got.BotToken != slackToken || got.ChannelID != "C0123456789" || !got.AllowShared {
		t.Fatalf("config = %#v", got)
	}
	raw, _ := json.Marshal(config)
	if decoded, code := decodeChannelConfig(domain.ChannelSlackBot, raw); code != "" || decoded != config {
		t.Fatalf("decode = %#v %q", decoded, code)
	}
	bad := []ChannelInput{
		{Secret: "xoxp" + "-1111111111-user-token-value", ConversationID: "C0123456789"}, // a user token
		{Secret: "xapp" + "-1-app-level-token-value-123", ConversationID: "C0123456789"}, // an app-level token
		{Secret: slackToken}, // no conversation
		{Secret: slackToken, ConversationID: "D0123456789"}, // a DM is not a channel
		{Secret: slackToken, ConversationID: "#security"},   // a name, not an ID
		{Secret: slackToken, ConversationID: "c0123456789"}, // lower case
		{ConversationID: "C0123456789"},                     // no token
	}
	for _, in := range bad {
		in.Name, in.Type = "ops", domain.ChannelSlackBot
		_, _, _, err := validateChannel(in, true)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v: err = %v", in, err)
		}
		if err != nil && (strings.Contains(err.Error(), "xoxp") || strings.Contains(err.Error(), "xapp") || strings.Contains(err.Error(), slackToken)) {
			t.Errorf("validation error echoes the token: %v", err)
		}
	}
}

func TestSlackBotChannelIsCheckedWithSlackBeforeTheTransaction(t *testing.T) {
	f := newSlackFixture(t)
	created, err := f.create(t, "C0000000001", false)
	if err != nil {
		t.Fatal(err)
	}
	if created.Type != domain.ChannelSlackBot || created.Destination != "https://slack.com/…" || created.Class() != domain.DataClassSignal {
		t.Fatalf("channel = %+v", created)
	}
	cfg := f.sealedConfig(t, created.ID)
	if cfg.TeamID != "T0123" || cfg.ChannelID != "C0000000001" || cfg.BotToken != slackToken || cfg.AllowShared {
		t.Fatalf("sealed config = %#v", cfg)
	}
	// auth.test and conversations.info, both outside the transaction (the fake panics otherwise).
	if f.workspace.calls != 2 {
		t.Fatalf("slack calls = %d, want 2", f.workspace.calls)
	}
	raw, _ := json.Marshal([]any{created, f.audit.entries})
	if strings.Contains(string(raw), slackToken) || strings.Contains(string(raw), "slackBOTsecret") {
		t.Fatalf("the token leaked into the channel or audit: %s", raw)
	}
}

func TestSlackBotChannelRefusesUnusableConversations(t *testing.T) {
	cases := map[string]string{
		"C0000000002": "shared with another workspace",
		"C0000000003": "archived",
		"G0000000004": "invite the Slack app",
		"C0000000099": "channel_not_found",
	}
	for conversation, want := range cases {
		t.Run(conversation, func(t *testing.T) {
			f := newSlackFixture(t)
			_, err := f.create(t, conversation, false)
			if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want a validation error mentioning %q", err, want)
			}
			if channels, _ := f.repo.ListChannels(f.ctx, "tenant-s"); len(channels) != 0 {
				t.Fatalf("a refused channel was stored: %+v", channels)
			}
		})
	}
}

func TestSlackBotChannelMayPostToASharedConversationWhenAllowed(t *testing.T) {
	f := newSlackFixture(t)
	created, err := f.create(t, "C0000000002", true)
	if err != nil {
		t.Fatal(err)
	}
	if !f.sealedConfig(t, created.ID).AllowShared {
		t.Fatal("allow_shared was not sealed")
	}
}

func TestSlackBotChannelRefusesARefusedToken(t *testing.T) {
	f := newSlackFixture(t)
	f.workspace.identifyErr = slackCode("invalid_auth")
	_, err := f.create(t, "C0000000001", false)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "invalid_auth") || strings.Contains(err.Error(), slackToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestSlackBotChannelNeedsTheWorkspaceReader(t *testing.T) {
	f := newSlackFixture(t)
	f.svc.SetSlackWorkspace(nil)
	if _, err := f.create(t, "C0000000001", false); !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("err = %v", err)
	}
}

func TestSlackBotChannelRepointing(t *testing.T) {
	f := newSlackFixture(t)
	created, err := f.create(t, "C0000000001", false)
	if err != nil {
		t.Fatal(err)
	}
	// A rename keeps the sealed destination and asks Slack nothing.
	calls := f.workspace.calls
	renamed, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, ChannelInput{Name: "Renamed", Type: domain.ChannelSlackBot, Enabled: true, Revision: created.Revision})
	if err != nil || renamed.SecretVersion != created.SecretVersion || f.workspace.calls != calls {
		t.Fatalf("rename: %+v %v calls=%d", renamed, err, f.workspace.calls-calls)
	}
	// Without administer a new conversation, the shared switch or a token is refused.
	for _, in := range []ChannelInput{{ConversationID: "C0000000005"}, {AllowSharedConversation: true}, {Secret: otherSlackToken}} {
		in.Name, in.Type, in.Enabled, in.Revision = "Renamed", domain.ChannelSlackBot, true, renamed.Revision
		if _, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, in); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("%+v without administer: %v", in, err)
		}
	}
	// A new conversation alone needs the token again.
	if _, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, ChannelInput{Name: "Renamed", Type: domain.ChannelSlackBot, Enabled: true, Revision: renamed.Revision, ConversationID: "C0000000005", AllowDestinationChange: true}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("conversation without token: %v", err)
	}
	// An administrator re-points it with the token; the new conversation is checked with Slack.
	moved, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, ChannelInput{Name: "Renamed", Type: domain.ChannelSlackBot, Enabled: true, Revision: renamed.Revision, Secret: otherSlackToken, ConversationID: "C0000000005", AllowDestinationChange: true})
	if err != nil || moved.SecretVersion != created.SecretVersion+1 {
		t.Fatalf("re-point: %+v %v", moved, err)
	}
	if cfg := f.sealedConfig(t, created.ID); cfg.BotToken != otherSlackToken || cfg.ChannelID != "C0000000005" {
		t.Fatalf("sealed config = %#v", cfg)
	}
	// Re-pointing at a shared conversation without allowing it is refused like on create.
	if _, err := f.svc.UpdateChannel(f.ctx, "ada", created.ID, ChannelInput{Name: "Renamed", Type: domain.ChannelSlackBot, Enabled: true, Revision: moved.Revision, Secret: slackToken, ConversationID: "C0000000002", AllowDestinationChange: true}); !errors.Is(err, errSlackShared) && !strings.Contains(err.Error(), "shared") {
		t.Fatalf("shared re-point: %v", err)
	}
}

func TestListSlackConversationsForAnEnteredToken(t *testing.T) {
	f := newSlackFixture(t)
	out, err := f.svc.ListSlackConversations(f.ctx, SlackConversationsInput{BotToken: " " + slackToken + " "})
	if err != nil {
		t.Fatal(err)
	}
	if out.TeamID != "T0123" || out.TeamName != "Acme" || !out.Truncated {
		t.Fatalf("result = %+v", out)
	}
	var names []string
	for _, item := range out.Items {
		names = append(names, item.Name)
	}
	// Sorted by name; the archived channel and the DM are not offered; shared ones are, marked.
	if strings.Join(names, ",") != "alerts,connect,private-out,security" {
		t.Fatalf("names = %v", names)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "xoxb") {
		t.Fatalf("the result echoes the token: %s", raw)
	}
}

func TestListSlackConversationsForAnExistingChannel(t *testing.T) {
	f := newSlackFixture(t)
	created, err := f.create(t, "C0000000001", false)
	if err != nil {
		t.Fatal(err)
	}
	f.workspace.tokens = nil
	if _, err := f.svc.ListSlackConversations(f.ctx, SlackConversationsInput{ChannelID: created.ID}); err != nil {
		t.Fatal(err)
	}
	for _, token := range f.workspace.tokens {
		if token != slackToken {
			t.Fatalf("listing used token %q, want the channel's sealed token", token)
		}
	}
	// Another tenant's channel ID is not found.
	other := shared.WithTenant(context.Background(), "tenant-other")
	if _, err := f.svc.ListSlackConversations(other, SlackConversationsInput{ChannelID: created.ID}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant listing: %v", err)
	}
}

func TestListSlackConversationsInputRules(t *testing.T) {
	f := newSlackFixture(t)
	slack, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "hook", Type: domain.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/x"})
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]SlackConversationsInput{
		"neither":         {},
		"both":            {BotToken: slackToken, ChannelID: slack.ID},
		"malformed":       {BotToken: "xoxp-user-token-1234567890"},
		"webhook channel": {ChannelID: slack.ID},
	} {
		if _, err := f.svc.ListSlackConversations(f.ctx, in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	f.workspace.listErr = slackCode("missing_scope")
	if _, err := f.svc.ListSlackConversations(f.ctx, SlackConversationsInput{BotToken: slackToken}); err == nil || !strings.Contains(err.Error(), "missing_scope") {
		t.Fatalf("listing error = %v", err)
	}
	f.svc.SetDisabledChannelTypes([]domain.ChannelType{domain.ChannelSlackBot})
	if _, err := f.svc.ListSlackConversations(f.ctx, SlackConversationsInput{BotToken: slackToken}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("disabled type: %v", err)
	}
}
