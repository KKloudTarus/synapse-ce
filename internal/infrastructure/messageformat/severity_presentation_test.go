package messageformat

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSeverityTitleUsesTypedPaletteAndPreservesLimits(t *testing.T) {
	for severity, want := range map[shared.Severity]string{
		shared.SeverityCritical: "🔴",
		shared.SeverityHigh:     "🟠",
		shared.SeverityMedium:   "🟡",
		shared.SeverityLow:      "🔵",
		shared.SeverityInfo:     "⚪",
	} {
		t.Run(string(severity), func(t *testing.T) {
			if got := severityTitle(severity, "Finding", 20); got != want+" Finding" {
				t.Fatalf("title = %q", got)
			}
		})
	}
	for _, severity := range []shared.Severity{"", shared.SeverityUnknown, "unrecognized"} {
		t.Run("omits_"+string(severity), func(t *testing.T) {
			if got := severityTitle(severity, "Finding", 20); got != "Finding" {
				t.Fatalf("title = %q", got)
			}
		})
	}
	for _, limit := range []int{slackHeaderRunes, telegramTitleRunes, teamsTitleRunes, googleChatTitleRunes} {
		got := severityTitle(shared.SeverityHigh, strings.Repeat("é", limit+10), limit)
		if !strings.HasPrefix(got, "🟠 ") || utf8.RuneCountInString(got) != limit {
			t.Fatalf("limit %d produced %q (%d runes)", limit, got, utf8.RuneCountInString(got))
		}
	}
}

func TestChatFormattersPrefixTypedSeverityBadge(t *testing.T) {
	message := ports.RenderedMessage{
		Severity: shared.SeverityHigh,
		Fields: map[string]string{
			// This is the stored template form of a hostile title value.
			"title": "Finding: " + msgtemplate.EscapeMarkdown("<!channel>"),
			"body":  "body",
		},
	}

	slack, err := (Slack{}).Format(message)
	if err != nil {
		t.Fatal(err)
	}
	fallback, header, _ := slackTextsOf(t, slack.Body)
	if header != "🟠 Finding: <!channel>" || strings.Contains(fallback, "<!channel>") || !strings.Contains(fallback, "&lt;!channel&gt;") {
		t.Fatalf("Slack header %q, fallback %q", header, fallback)
	}
	if title := formattedChatTitle(t, SlackBot{}, message); title != "🟠 Finding: <!channel>" {
		t.Fatalf("Slack bot title %q", title)
	}

	telegram, err := Telegram(message)
	if err != nil {
		t.Fatal(err)
	}
	var telegramPayload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(telegram.Body, &telegramPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(telegramPayload.Text, "*🟠 Finding: ") || !strings.Contains(telegramPayload.Text, `\!channel`) {
		t.Fatalf("Telegram title %q", telegramPayload.Text)
	}

	teams, err := Teams(message)
	if err != nil {
		t.Fatal(err)
	}
	var teamsPayload struct {
		Attachments []struct {
			Content struct {
				Body []struct {
					Inlines []struct {
						Text string `json:"text"`
					} `json:"inlines"`
				} `json:"body"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(teams.Body, &teamsPayload); err != nil {
		t.Fatal(err)
	}
	if got := teamsPayload.Attachments[0].Content.Body[0].Inlines[0].Text; !strings.HasPrefix(got, "🟠 Finding: ") || !strings.Contains(got, `\!channel`) {
		t.Fatalf("Teams title %q", got)
	}

	googleChat, err := GoogleChat(message)
	if err != nil {
		t.Fatal(err)
	}
	var googleChatPayload struct {
		CardsV2 []struct {
			Card struct {
				Header struct {
					Title string `json:"title"`
				} `json:"header"`
			} `json:"card"`
		} `json:"cardsV2"`
	}
	if err := json.Unmarshal(googleChat.Body, &googleChatPayload); err != nil {
		t.Fatal(err)
	}
	if got := googleChatPayload.CardsV2[0].Card.Header.Title; !strings.HasPrefix(got, "🟠 Finding: ") || !strings.Contains(got, `\!channel`) {
		t.Fatalf("Google Chat title %q", got)
	}

	for _, formatter := range []ports.NotificationFormatter{MattermostFormatter{}, RocketChatFormatter{}} {
		out, err := formatter.Format(message)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(out.Body, &payload); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(payload.Text, "**🟠 ") || strings.Contains(payload.Text, "\n@channel") {
			t.Fatalf("%T title %q", formatter, payload.Text)
		}
	}
}

func TestEveryChatFormatterOmitsBadgeForAbsentOrUnknownSeverity(t *testing.T) {
	formatters := []ports.NotificationFormatter{Slack{}, SlackBot{}, TeamsFormatter{}, TelegramFormatter{}, GoogleChatFormatter{}, MattermostFormatter{}, RocketChatFormatter{}}
	for _, severity := range []shared.Severity{"", shared.SeverityUnknown, "unrecognized"} {
		for _, formatter := range formatters {
			t.Run(string(formatter.ChannelType())+"/"+string(severity), func(t *testing.T) {
				title := formattedChatTitle(t, formatter, ports.RenderedMessage{Severity: severity, Fields: map[string]string{"title": "Finding", "body": "body"}})
				for _, badge := range []string{"🔴", "🟠", "🟡", "🔵", "⚪"} {
					if strings.Contains(title, badge) {
						t.Fatalf("%T added badge to %q", formatter, title)
					}
				}
			})
		}
	}
}

func TestSeverityBadgeFitsProviderTitleLimits(t *testing.T) {
	message := ports.RenderedMessage{Severity: shared.SeverityHigh, Fields: map[string]string{"title": strings.Repeat("é", 400), "body": "body"}}

	slack, err := (Slack{}).Format(message)
	if err != nil {
		t.Fatal(err)
	}
	_, header, _ := slackTextsOf(t, slack.Body)
	if n := utf8.RuneCountInString(header); n != slackHeaderRunes || !strings.HasPrefix(header, "🟠 ") {
		t.Fatalf("Slack header = %q (%d runes)", header, n)
	}

	telegram, err := Telegram(message)
	if err != nil {
		t.Fatal(err)
	}
	var telegramPayload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(telegram.Body, &telegramPayload); err != nil {
		t.Fatal(err)
	}
	title, _, _ := strings.Cut(telegramPayload.Text, "\n\n")
	if n := utf8.RuneCountInString(title); n != telegramTitleRunes+2 || !strings.HasPrefix(title, "*🟠 ") {
		t.Fatalf("Telegram title = %q (%d runes)", title, n)
	}

	if title := formattedChatTitle(t, TeamsFormatter{}, message); utf8.RuneCountInString(title) != teamsTitleRunes || !strings.HasPrefix(title, "🟠 ") {
		t.Fatalf("Teams title = %q", title)
	}

	if title := formattedChatTitle(t, GoogleChatFormatter{}, message); utf8.RuneCountInString(title) != googleChatTitleRunes || !strings.HasPrefix(title, "🟠 ") {
		t.Fatalf("Google Chat title = %q", title)
	}
}

func formattedChatTitle(t *testing.T, formatter ports.NotificationFormatter, message ports.RenderedMessage) string {
	t.Helper()
	out, err := formatter.Format(message)
	if err != nil {
		t.Fatal(err)
	}
	switch formatter.ChannelType() {
	case "slack", "slack_bot":
		_, header, _ := slackTextsOf(t, out.Body)
		return header
	case "telegram":
		var payload struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(out.Body, &payload); err != nil {
			t.Fatal(err)
		}
		title, _, _ := strings.Cut(payload.Text, "\n\n")
		return title
	case "teams":
		var payload struct {
			Attachments []struct {
				Content struct {
					Body []struct {
						Inlines []struct {
							Text string `json:"text"`
						} `json:"inlines"`
					} `json:"body"`
				} `json:"content"`
			} `json:"attachments"`
		}
		if err := json.Unmarshal(out.Body, &payload); err != nil {
			t.Fatal(err)
		}
		return payload.Attachments[0].Content.Body[0].Inlines[0].Text
	case "google_chat":
		var payload struct {
			CardsV2 []struct {
				Card struct {
					Header struct {
						Title string `json:"title"`
					} `json:"header"`
				} `json:"card"`
			} `json:"cardsV2"`
		}
		if err := json.Unmarshal(out.Body, &payload); err != nil {
			t.Fatal(err)
		}
		return payload.CardsV2[0].Card.Header.Title
	case "mattermost", "rocket_chat":
		var payload struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(out.Body, &payload); err != nil {
			t.Fatal(err)
		}
		return payload.Text
	default:
		t.Fatalf("unsupported chat formatter %T", formatter)
		return ""
	}
}
