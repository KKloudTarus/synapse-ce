package notifylive

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var updateCaptures = flag.Bool("update-captures", false, "rewrite the committed payload captures")

// captureRoot is where the committed payloads live, beside the rest of the event's evidence.
const captureRoot = "../../docs/evidence/report-generated/payloads"

// TestReportGeneratedPayloadCaptures writes, and then pins, exactly what each destination
// receives for report.generated. The webhook capture is the receiver's parsed body, which is one
// of the artifacts #1410 asks for and the only one that needs no third-party workspace. The chat
// and mail captures are the bytes behind the client screenshots, so a reviewer can compare what a
// client rendered against what Synapse sent.
func TestReportGeneratedPayloadCaptures(t *testing.T) {
	catalog := notificationbuiltin.New()
	formatters := messageformat.Formatters()
	targets := []destination{
		{name: "slack", channel: domain.ChannelSlack, config: ports.SlackChannelConfig{URL: "https://hooks.slack.test/x"}},
		{name: "teams", channel: domain.ChannelTeams, config: ports.TeamsChannelConfig{URL: "https://teams.test/x"}},
		{name: "discord", channel: domain.ChannelDiscord, config: ports.DiscordChannelConfig{URL: "https://discord.test/x"}},
		{name: "google-chat", channel: domain.ChannelGoogleChat, config: ports.GoogleChatChannelConfig{URL: "https://chat.test/x"}},
		{name: "telegram", channel: domain.ChannelTelegram, config: ports.TelegramChannelConfig{BotToken: "token", ChatID: "1"}},
		{name: "pagerduty", channel: domain.ChannelPagerDuty, config: ports.PagerDutyChannelConfig{RoutingKey: "key"}},
		{name: "email", channel: domain.ChannelEmail, config: ports.EmailChannelConfig{Recipients: []string{"reviewer@example.test"}}},
	}
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, target := range targets {
			work := reportGeneratedWork(t, catalog, formatters, target, locale, liveVars(captureInstant))
			if work.Formatted == nil {
				t.Fatalf("%s/%s rendered no payload", target.name, locale)
			}
			body := stableJSON(t, work.Formatted.Body)
			recorded := capture{Body: body, Subject: work.Formatted.Subject, HTMLBody: string(work.Formatted.HTMLBody)}
			if body == nil {
				// A mail body is plain text, not JSON.
				recorded.Text = string(work.Formatted.Body)
			}
			checkCapture(t, target.name+"-"+string(locale)+".json", recorded)
		}
		checkCapture(t, "webhook-"+string(locale)+".json", capture{Body: webhookEnvelope(t)})
	}
}

type capture struct {
	Body     json.RawMessage `json:"body,omitempty"`
	Text     string          `json:"text,omitempty"`
	Subject  string          `json:"subject,omitempty"`
	HTMLBody string          `json:"html_body,omitempty"`
}

// webhookEnvelope is the default receiver body: the versioned envelope with the class-filtered
// context, which is what a webhook receiver parses.
func webhookEnvelope(t *testing.T) json.RawMessage {
	t.Helper()
	spec, ok := domain.LookupEvent(domain.EventReportGenerated)
	if !ok {
		t.Fatal("report.generated is missing from the catalog")
	}
	vars := liveVars(captureInstant)
	event := domain.Event{
		TenantID: "live", ID: "live-report-generated", Type: domain.EventReportGenerated,
		SchemaVersion: spec.SchemaVersion, Severity: "high", SubjectKind: "report", SubjectID: vars["content_hash"],
	}
	raw, err := domain.RenderWebhookEnvelope(event, spec.Snapshot(vars).Filter(spec, domain.DataClassDetail))
	if err != nil {
		t.Fatalf("render the webhook envelope: %v", err)
	}
	return stableJSON(t, raw)
}

// captureInstant keeps the committed captures byte-stable; the live suite stamps the real time.
const captureInstant = "2026-10-23T09:00:00Z"

// stableJSON re-encodes a payload with sorted keys and pins every timestamp, so a capture changes
// only when the content does. A payload that is not JSON returns nil and is captured as text.
func stableJSON(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	encoded, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return json.RawMessage(encoded)
}

func checkCapture(t *testing.T, name string, got capture) {
	t.Helper()
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join(captureRoot, name)
	if *updateCaptures {
		if err := os.MkdirAll(captureRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture (run with -update-captures to create it): %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(encoded)) {
		t.Fatalf("%s changed\n got: %s\nwant: %s", name, encoded, want)
	}
}
