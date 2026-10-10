package notification

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type directMessage struct {
	token, member, body string
}

type fakeDirect struct {
	mu     sync.Mutex
	sent   []directMessage
	result ports.NotificationSendResult
}

func (d *fakeDirect) SendSlackDirect(_ context.Context, token, member string, formatted []byte) ports.NotificationSendResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, directMessage{token, member, string(formatted)})
	if d.result.ErrorCode != "" {
		return d.result
	}
	return ports.NotificationSendResult{StatusCode: 200, RemoteRef: "1700000000.0001"}
}

// memberWorkspace adds users.info to the fake workspace.
type memberWorkspace struct {
	*fakeWorkspace
	members map[string]ports.SlackMember
}

func (w memberWorkspace) Member(_ context.Context, token, member string) (ports.SlackMember, error) {
	w.record(token)
	m, ok := w.members[member]
	if !ok {
		return ports.SlackMember{}, slackCode("user_not_found")
	}
	return m, nil
}

func newPersonalSlackFixture(t *testing.T) (slackFixture, *fakeDirect, domain.Channel) {
	t.Helper()
	f := newSlackFixture(t)
	f.svc.SetSlackWorkspace(memberWorkspace{fakeWorkspace: f.workspace, members: map[string]ports.SlackMember{
		"U0ADA":  {ID: "U0ADA", TeamID: "T0123"},
		"U0GONE": {ID: "U0GONE", TeamID: "T0123", Deleted: true},
		"U0BOT":  {ID: "U0BOT", TeamID: "T0123", Bot: true},
		"U0FAR":  {ID: "U0FAR", TeamID: "T0999"},
	}})
	direct := &fakeDirect{}
	f.svc.SetSlackDirect(direct)
	f.svc.SetFormatters(messageformat.Formatters())
	f.svc.SetPublicBaseURL("https://synapse.example")
	channel, err := f.create(t, "C0000000001", false)
	if err != nil {
		t.Fatal(err)
	}
	return f, direct, channel
}

func TestSlackWorkspacesListsEnabledBotsOnce(t *testing.T) {
	f, _, _ := newPersonalSlackFixture(t)
	if _, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "Alerts", Type: domain.ChannelSlackBot, Enabled: true, Secret: otherSlackToken, ConversationID: "C0000000005"}); err != nil {
		t.Fatal(err)
	}
	workspaces, err := f.svc.SlackWorkspaces(f.ctx)
	if err != nil || len(workspaces) != 1 || workspaces[0].TeamID != "T0123" || workspaces[0].TeamName != "Acme" {
		t.Fatalf("workspaces = %+v %v", workspaces, err)
	}
	// Another tenant sees none of them.
	other, err := f.svc.SlackWorkspaces(shared.WithTenant(context.Background(), "tenant-other"))
	if err != nil || len(other) != 0 {
		t.Fatalf("other tenant = %+v %v", other, err)
	}
}

func TestCheckSlackMember(t *testing.T) {
	f, _, _ := newPersonalSlackFixture(t)
	if err := f.svc.CheckSlackMember(f.ctx, "tenant-s", "T0123", "U0ADA"); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[string]string{"U0GONE": "not an active person", "U0BOT": "not an active person", "U0FAR": "not an active person", "U0NOBODY": "user_not_found"} {
		if err := f.svc.CheckSlackMember(f.ctx, "tenant-s", "T0123", member); !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", member, err)
		}
	}
	if err := f.svc.CheckSlackMember(f.ctx, "tenant-s", "T0999", "U0ADA"); !errors.Is(err, ErrSlackWorkspaceUnavailable) {
		t.Errorf("workspace without a bot: %v", err)
	}
}

func TestPersonalSlackMessageUsesTheWorkspaceBot(t *testing.T) {
	f, direct, _ := newPersonalSlackFixture(t)
	result := f.svc.PersonalSlack().SendPersonal(f.ctx, ports.PersonalMessage{TenantID: "tenant-s", Recipient: "T0123:U0ADA",
		Title: "Finding ownership changed", Summary: "<!channel> [Reset](https://evil.example)", LinkPath: "/engagements/e1/findings#finding-f1"})
	if result.ErrorCode != "" || len(direct.sent) != 1 {
		t.Fatalf("result = %+v sent = %d", result, len(direct.sent))
	}
	sent := direct.sent[0]
	if sent.token != slackToken || sent.member != "U0ADA" {
		t.Fatalf("sent with %q to %q", sent.token, sent.member)
	}
	if !strings.Contains(sent.body, `"url":"https://synapse.example/engagements/e1/findings#finding-f1"`) || strings.Contains(sent.body, "<!channel>") || strings.Contains(sent.body, `"url":"https://evil.example"`) {
		t.Fatalf("body = %s", sent.body)
	}
}

func TestPersonalSlackMessageFailures(t *testing.T) {
	f, direct, channel := newPersonalSlackFixture(t)
	if r := f.svc.PersonalSlack().SendPersonal(f.ctx, ports.PersonalMessage{TenantID: "tenant-s", Recipient: "ada@example.com"}); r.ErrorCode != "contact_invalid" {
		t.Fatalf("bad contact: %+v", r)
	}
	if r := f.svc.PersonalSlack().SendPersonal(f.ctx, ports.PersonalMessage{TenantID: "tenant-s", Recipient: "T0999:U0ADA"}); r.ErrorCode != codeSlackWorkspaceUnavailable || r.Retryable {
		t.Fatalf("no bot: %+v", r)
	}
	// A switched-off bot channel is no longer a way into its workspace.
	if _, err := f.svc.UpdateChannel(f.ctx, "ada", channel.ID, ChannelInput{Name: channel.Name, Type: domain.ChannelSlackBot, Enabled: false, Revision: channel.Revision}); err != nil {
		t.Fatal(err)
	}
	if r := f.svc.PersonalSlack().SendPersonal(f.ctx, ports.PersonalMessage{TenantID: "tenant-s", Recipient: "T0123:U0ADA"}); r.ErrorCode != codeSlackWorkspaceUnavailable {
		t.Fatalf("disabled bot: %+v", r)
	}
	if len(direct.sent) != 0 {
		t.Fatalf("sent %d messages", len(direct.sent))
	}
}

func TestSlackVerificationCodeIsADirectMessage(t *testing.T) {
	f, direct, _ := newPersonalSlackFixture(t)
	if r := f.svc.SendSlackVerification(f.ctx, "tenant-s", "T0123:U0ADA", "12345678"); r.ErrorCode != "" {
		t.Fatalf("result = %+v", r)
	}
	if len(direct.sent) != 1 || !strings.Contains(direct.sent[0].body, "12345678") || direct.sent[0].member != "U0ADA" {
		t.Fatalf("sent = %+v", direct.sent)
	}
	direct.result = ports.NotificationSendResult{ErrorCode: "slack_ratelimited", Retryable: true}
	if r := f.svc.SendSlackVerification(f.ctx, "tenant-s", "T0123:U0ADA", "12345678"); r.ErrorCode != "slack_ratelimited" || !r.Retryable {
		t.Fatalf("rate limited: %+v", r)
	}
}
