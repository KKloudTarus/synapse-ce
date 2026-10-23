// Package notifylive posts one event through the shipped template, the shipped formatter and the
// real channel driver into whatever destinations the operator configured. It exists so the client
// evidence #1410 asks for is one command per workspace rather than a hand-made payload: what lands
// in Slack, Teams, Telegram, Discord, Google Chat, PagerDuty, a mailbox or a webhook receiver is
// what a delivery lands.
//
// It is opt-in, like the Postgres, syslog, S3 and Teams suites. Configure any subset; each
// destination runs only when its variables are set:
//
//	SYNAPSE_TEST_NOTIFY_SLACK_WEBHOOK       Slack incoming webhook URL
//	SYNAPSE_TEST_NOTIFY_TEAMS_WEBHOOK       Teams Workflows webhook URL
//	SYNAPSE_TEST_NOTIFY_DISCORD_WEBHOOK     Discord webhook URL
//	SYNAPSE_TEST_NOTIFY_GOOGLECHAT_WEBHOOK  Google Chat space webhook URL
//	SYNAPSE_TEST_NOTIFY_TELEGRAM_BOT_TOKEN  with SYNAPSE_TEST_NOTIFY_TELEGRAM_CHAT_ID
//	SYNAPSE_TEST_NOTIFY_WEBHOOK_URL         with SYNAPSE_TEST_NOTIFY_WEBHOOK_SECRET
//	SYNAPSE_TEST_NOTIFY_PAGERDUTY_KEY       Events API v2 routing key
//	SYNAPSE_TEST_NOTIFY_EMAIL_TO            with SYNAPSE_TEST_NOTIFY_SMTP_HOST, _SMTP_PORT,
//	                                        _SMTP_FROM and optional _SMTP_USER, _SMTP_PASSWORD
//	SYNAPSE_TEST_NOTIFY_LOCALES             optional, "en", "vi" or "en,vi" (default both)
//	SYNAPSE_PUBLIC_BASE_URL                 optional console origin for the deep link
//
// Use dedicated test workspaces. Every destination here is a credential, and the suite never logs
// one.
package notifylive

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/notificationsender"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// destination is one configured client, named as the capture files name it.
type destination struct {
	name    string
	channel domain.ChannelType
	config  ports.NotificationChannelConfig
}

func configuredDestinations() []destination {
	var out []destination
	add := func(name string, channel domain.ChannelType, config ports.NotificationChannelConfig, ok bool) {
		if ok {
			out = append(out, destination{name: name, channel: channel, config: config})
		}
	}
	slack := os.Getenv("SYNAPSE_TEST_NOTIFY_SLACK_WEBHOOK")
	add("slack", domain.ChannelSlack, ports.SlackChannelConfig{URL: slack}, slack != "")
	teams := os.Getenv("SYNAPSE_TEST_NOTIFY_TEAMS_WEBHOOK")
	add("teams", domain.ChannelTeams, ports.TeamsChannelConfig{URL: teams}, teams != "")
	discord := os.Getenv("SYNAPSE_TEST_NOTIFY_DISCORD_WEBHOOK")
	add("discord", domain.ChannelDiscord, ports.DiscordChannelConfig{URL: discord}, discord != "")
	chat := os.Getenv("SYNAPSE_TEST_NOTIFY_GOOGLECHAT_WEBHOOK")
	add("google-chat", domain.ChannelGoogleChat, ports.GoogleChatChannelConfig{URL: chat}, chat != "")
	token, chatID := os.Getenv("SYNAPSE_TEST_NOTIFY_TELEGRAM_BOT_TOKEN"), os.Getenv("SYNAPSE_TEST_NOTIFY_TELEGRAM_CHAT_ID")
	add("telegram", domain.ChannelTelegram, ports.TelegramChannelConfig{BotToken: token, ChatID: chatID}, token != "" && chatID != "")
	hook := os.Getenv("SYNAPSE_TEST_NOTIFY_WEBHOOK_URL")
	add("webhook", domain.ChannelWebhook, ports.WebhookChannelConfig{URL: hook, Secret: os.Getenv("SYNAPSE_TEST_NOTIFY_WEBHOOK_SECRET")}, hook != "")
	routing := os.Getenv("SYNAPSE_TEST_NOTIFY_PAGERDUTY_KEY")
	add("pagerduty", domain.ChannelPagerDuty, ports.PagerDutyChannelConfig{RoutingKey: routing}, routing != "")
	recipients := trimmed(strings.Split(os.Getenv("SYNAPSE_TEST_NOTIFY_EMAIL_TO"), ","))
	add("email", domain.ChannelEmail, ports.EmailChannelConfig{Recipients: recipients}, len(recipients) > 0)
	return out
}

func trimmed(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func TestNotificationLiveClients(t *testing.T) {
	destinations := configuredDestinations()
	if len(destinations) == 0 {
		t.Skip("set at least one SYNAPSE_TEST_NOTIFY_* destination to run the live client suite")
	}
	sender := notificationsender.New(smtpConfig(), 20*time.Second)
	formatters := messageformat.Formatters()
	catalog := notificationbuiltin.New()
	ctx := context.Background()

	for _, locale := range locales(t) {
		for _, target := range destinations {
			t.Run(target.name+"-"+string(locale), func(t *testing.T) {
				work := reportGeneratedWork(t, catalog, formatters, target, locale)
				result := sender.Send(ctx, work, target.config)
				if result.ErrorCode != "" {
					t.Fatalf("%s refused the message: code=%s status=%d", target.name, result.ErrorCode, result.StatusCode)
				}
				if result.TemplateFallback {
					t.Fatalf("%s received built-in fallback content instead of the shipped template", target.name)
				}
				t.Logf("delivered to %s: capture it as %s-report-generated-%s-<theme>.png", target.name, target.name, locale)
			})
		}
	}
}

func smtpConfig() notificationsender.SMTPConfig {
	port, _ := strconv.Atoi(os.Getenv("SYNAPSE_TEST_NOTIFY_SMTP_PORT"))
	return notificationsender.SMTPConfig{
		Host: os.Getenv("SYNAPSE_TEST_NOTIFY_SMTP_HOST"), Port: port,
		From:     os.Getenv("SYNAPSE_TEST_NOTIFY_SMTP_FROM"),
		Username: os.Getenv("SYNAPSE_TEST_NOTIFY_SMTP_USER"),
		Password: os.Getenv("SYNAPSE_TEST_NOTIFY_SMTP_PASSWORD"),
	}
}

func locales(t *testing.T) []tenancy.Locale {
	t.Helper()
	switch strings.TrimSpace(os.Getenv("SYNAPSE_TEST_NOTIFY_LOCALES")) {
	case "en":
		return []tenancy.Locale{tenancy.LocaleEnglish}
	case "vi":
		return []tenancy.Locale{tenancy.LocaleVietnamese}
	case "", "en,vi", "vi,en":
		return []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese}
	default:
		t.Fatalf("SYNAPSE_TEST_NOTIFY_LOCALES must be en, vi or en,vi")
		return nil
	}
}

func liveVars() map[string]string {
	now := time.Now().UTC().Format(time.RFC3339)
	return map[string]string{
		"event_type": string(domain.EventReportGenerated), "event_label": "Report generated",
		"occurred_at": now, "generated_at": now,
		"title": "Report generated", "summary": "A report artifact was sealed from stored data.",
		"severity": "high", "report_kind": "engagement_report", "finding_count": "7",
		"engagement_name": "Live acceptance", "report_title": "Security assessment report: Live acceptance",
		"content_hash": "3f786850e387550fdab836ed7e6dc881de23001b1b4ca1f1e1b9a1c0d2e3f4a5",
	}
}

// reportGeneratedWork builds the delivery a worker hands the driver: the event with its sealed
// context, the channel, and the wire payload rendered from the shipped template by the channel's
// own formatter.
func reportGeneratedWork(t *testing.T, catalog *notificationbuiltin.Catalog, formatters map[domain.ChannelType]ports.NotificationFormatter, target destination, locale tenancy.Locale) ports.NotificationWork {
	t.Helper()
	spec, ok := domain.LookupEvent(domain.EventReportGenerated)
	if !ok {
		t.Fatal("report.generated is missing from the catalog")
	}
	vars := liveVars()
	encoded, err := spec.Snapshot(vars).Encode()
	if err != nil {
		t.Fatalf("encode the event context: %v", err)
	}
	event := domain.Event{
		TenantID: "live", ID: shared.ID("live-report-generated"), Type: domain.EventReportGenerated,
		SchemaVersion: spec.SchemaVersion, OccurredAt: time.Now().UTC(), Severity: shared.SeverityHigh,
		SubjectKind: "report", SubjectID: vars["content_hash"], Context: encoded,
	}
	channel := domain.Channel{
		TenantID: "live", ID: shared.ID("live-" + target.name), Type: target.channel,
		Enabled: true, DataClass: domain.DataClassDetail, Locale: locale,
	}
	work := ports.NotificationWork{
		Event: event, Channel: channel,
		Delivery: domain.Delivery{ID: "live-delivery", EventID: event.ID, ChannelID: channel.ID},
	}
	family, hasFamily := domain.FamilyForChannelType(target.channel)
	formatter, hasFormatter := formatters[target.channel]
	if !hasFamily || !hasFormatter {
		// A generic webhook has no rendered content: its body is the versioned envelope.
		return work
	}
	formatted, err := formatter.Format(renderBuiltin(t, catalog, spec, family, locale, vars))
	if err != nil {
		t.Fatalf("format for %s: %v", target.name, err)
	}
	work.Formatted = &formatted
	return work
}

// renderBuiltin renders the shipped template of the event for one family and locale, through the
// same engine the delivery path uses.
func renderBuiltin(t *testing.T, catalog *notificationbuiltin.Catalog, spec domain.EventSpec, family domain.TemplateFamily, locale tenancy.Locale, vars map[string]string) ports.RenderedMessage {
	t.Helper()
	template, ok := catalog.Builtin(spec.Type, family, locale)
	if !ok {
		t.Fatalf("no shipped %s template for %s in %s", family, spec.Type, locale)
	}
	schema := eventSchema(t, spec)
	fields := make(map[string]string, len(template.Fields))
	for name, source := range template.Fields {
		compiled, err := msgtemplate.Compile(name, source, schema)
		if err != nil {
			t.Fatalf("compile the shipped %s field: %v", name, err)
		}
		out, err := compiled.Render(msgtemplate.Data{Vars: vars}, 8000)
		if err != nil {
			t.Fatalf("render the shipped %s field: %v", name, err)
		}
		fields[name] = out.Text
	}
	rendered := ports.RenderedMessage{Fields: fields, TemplateRef: template.Ref, Severity: shared.SeverityHigh}
	if base := strings.TrimRight(os.Getenv("SYNAPSE_PUBLIC_BASE_URL"), "/"); base != "" {
		rendered.Links = []ports.RenderedLink{{Label: "Open in Synapse", URL: base + "/engagements"}}
	}
	return rendered
}

// eventSchema mirrors templateSchemas in internal/usecase/notification.
func eventSchema(t *testing.T, spec domain.EventSpec) *msgtemplate.Schema {
	t.Helper()
	var names []string
	lists := map[string]msgtemplate.List{}
	for _, variable := range spec.Variables {
		if variable.ListCap == 0 {
			names = append(names, variable.Name)
			continue
		}
		lists[variable.Name] = msgtemplate.List{Cap: variable.ListCap, Fields: append([]string(nil), variable.ItemFields...)}
	}
	schema, err := msgtemplate.NewSchema(msgtemplate.SchemaSpec{Vars: names, Lists: lists})
	if err != nil {
		t.Fatalf("event schema: %v", err)
	}
	return schema
}

// TestNotifyLivePayloadsRenderForEveryClient runs the payload half of the live suite without a
// destination: every client the suite can target renders the shipped template through its own
// formatter, in both locales. It keeps the suite honest before a workspace is spent on it, and it
// fails if a template or a formatter stops producing content for one family.
func TestNotifyLivePayloadsRenderForEveryClient(t *testing.T) {
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
		{name: "webhook", channel: domain.ChannelWebhook, config: ports.WebhookChannelConfig{URL: "https://receiver.test/x"}},
	}
	for _, target := range targets {
		english := payloadText(t, catalog, formatters, target, tenancy.LocaleEnglish)
		vietnamese := payloadText(t, catalog, formatters, target, tenancy.LocaleVietnamese)
		if target.channel == domain.ChannelWebhook {
			if english != "" || vietnamese != "" {
				t.Fatalf("the generic webhook sends its versioned envelope, not rendered content")
			}
			continue
		}
		for locale, body := range map[tenancy.Locale]string{tenancy.LocaleEnglish: english, tenancy.LocaleVietnamese: vietnamese} {
			if body == "" {
				t.Fatalf("%s/%s rendered no payload", target.name, locale)
			}
			// A chat formatter escapes Markdown punctuation, so the comparison drops
			// the escapes rather than asserting one channel's spelling.
			if !strings.Contains(strings.ReplaceAll(body, `\`, ""), "engagement_report") {
				t.Fatalf("%s/%s lost the report kind: %s", target.name, locale, body)
			}
		}
		if english == vietnamese {
			t.Fatalf("%s rendered the same payload for both locales", target.name)
		}
		if !strings.ContainsAny(vietnamese, "ạảấầéèếịớồộúùưữăâđêôơ") {
			t.Fatalf("%s rendered no Vietnamese text: %s", target.name, vietnamese)
		}
	}
}

// payloadText is everything a client would show for one destination and locale: the wire body,
// the email subject and the HTML alternative.
func payloadText(t *testing.T, catalog *notificationbuiltin.Catalog, formatters map[domain.ChannelType]ports.NotificationFormatter, target destination, locale tenancy.Locale) string {
	t.Helper()
	work := reportGeneratedWork(t, catalog, formatters, target, locale)
	if work.Formatted == nil {
		return ""
	}
	return string(work.Formatted.Body) + work.Formatted.Subject + string(work.Formatted.HTMLBody)
}
