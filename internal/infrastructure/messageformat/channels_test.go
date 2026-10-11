package messageformat

import (
	"encoding/json"
	"errors"
	"html"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// renderer is one channel renderer under test, reduced to its wire bytes.
type renderer func(ports.RenderedMessage) ([]byte, error)

func fromFormatted(f func(ports.RenderedMessage) (ports.FormattedMessage, error)) renderer {
	return func(m ports.RenderedMessage) ([]byte, error) {
		out, err := f(m)
		return out.Body, err
	}
}

var channelRenderers = map[string]renderer{
	"telegram":   fromFormatted(Telegram),
	"discord":    fromFormatted(Discord),
	"teams":      fromFormatted(Teams),
	"googlechat": fromFormatted(GoogleChat),
	"jira_adf": func(m ports.RenderedMessage) ([]byte, error) {
		doc, err := JiraADF(m.Fields["body"], m.Links)
		if err != nil {
			return nil, err
		}
		return json.Marshal(doc)
	},
	"jira_wiki": func(m ports.RenderedMessage) ([]byte, error) {
		out, err := JiraWiki(m.Fields["body"], m.Links)
		return []byte(out), err
	},
}

func indentJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("invalid JSON %s: %v", raw, err)
	}
	pretty, _ := json.MarshalIndent(decoded, "", "  ")
	return append(pretty, '\n')
}

func TestChannelGolden(t *testing.T) {
	for name, render := range channelRenderers {
		out, err := render(sampleMessage())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "jira_wiki" {
			checkGolden(t, name+".txt", out)
			continue
		}
		checkGolden(t, name+".json", indentJSON(t, out))
	}
}

func TestChannelsRefuseUncheckedLinks(t *testing.T) {
	for name, render := range channelRenderers {
		if _, err := render(ports.RenderedMessage{Links: []ports.RenderedLink{{Label: "x", URL: "javascript:alert(1)"}}}); !errors.Is(err, ErrInvalidLink) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// literalBody returns the message whose body is "Value: " and the escaped value, as msgtemplate
// renders an interpolated value, and the plain text the recipient must see.
func literalBody(value string) (ports.RenderedMessage, string) {
	clean := msgtemplate.Sanitize(value)
	return ports.RenderedMessage{Fields: map[string]string{"body": "Value: " + msgtemplate.EscapeMarkdown(clean)}}, "Value: " + clean
}

func TestTelegramInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		message, want := literalBody(value)
		out, err := Telegram(message)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Text      string `json:"text"`
			ParseMode string `json:"parse_mode"`
		}
		_ = json.Unmarshal(out.Body, &payload)
		if payload.ParseMode != "MarkdownV2" || payload.Text != escapeTelegram(want) {
			t.Errorf("%q: text %q", value, payload.Text)
		}
		assertEscaped(t, "telegram "+value, payload.Text, telegramSpecial)
	}
}

func TestDiscordInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		message, want := literalBody(value)
		out, err := Discord(message)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Embeds          []map[string]string `json:"embeds"`
			AllowedMentions struct {
				Parse []string `json:"parse"`
			} `json:"allowed_mentions"`
		}
		_ = json.Unmarshal(out.Body, &payload)
		if len(payload.Embeds) != 1 || payload.Embeds[0]["description"] != escapeDiscord(want) {
			t.Errorf("%q: embeds %+v", value, payload.Embeds)
		}
		if payload.AllowedMentions.Parse == nil || len(payload.AllowedMentions.Parse) != 0 || !strings.Contains(string(out.Body), `"parse":[]`) {
			t.Errorf("%q: allowed_mentions does not suppress every mention: %s", value, out.Body)
		}
		assertEscaped(t, "discord "+value, payload.Embeds[0]["description"], asciiPunctuation)
	}
}

func TestTeamsInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		message, want := literalBody(value)
		out, err := Teams(message)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Attachments []struct {
				Content struct {
					Body []struct {
						Type    string           `json:"type"`
						Inlines []map[string]any `json:"inlines"`
					} `json:"body"`
				} `json:"content"`
			} `json:"attachments"`
		}
		_ = json.Unmarshal(out.Body, &payload)
		body := payload.Attachments[0].Content.Body
		if len(body) != 1 || body[0].Type != "RichTextBlock" || len(body[0].Inlines) != 1 {
			t.Fatalf("%q: card body %+v", value, body)
		}
		run := body[0].Inlines[0]
		if run["type"] != "TextRun" || run["text"] != want || len(run) != 2 {
			t.Errorf("%q: run %+v", value, run)
		}
		if strings.Contains(string(out.Body), `"TextBlock"`) {
			t.Errorf("%q: a Markdown-parsing TextBlock was used", value)
		}
	}
}

func TestGoogleChatInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		message, want := literalBody(value)
		out, err := GoogleChat(message)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Text    *string `json:"text"`
			CardsV2 []struct {
				Card struct {
					Sections []struct {
						Widgets []struct {
							TextParagraph struct {
								Text string `json:"text"`
							} `json:"textParagraph"`
						} `json:"widgets"`
					} `json:"sections"`
				} `json:"card"`
			} `json:"cardsV2"`
		}
		_ = json.Unmarshal(out.Body, &payload)
		if payload.Text != nil {
			t.Fatalf("%q: a plain text field, which Chat parses for mentions, was set", value)
		}
		got := payload.CardsV2[0].Card.Sections[0].Widgets[0].TextParagraph.Text
		if got != html.EscapeString(want) || strings.ContainsAny(got, "<>") {
			t.Errorf("%q: paragraph %q", value, got)
		}
	}
}

func TestJiraInjectionValuesStayLiteral(t *testing.T) {
	for _, value := range injectionValues {
		message, want := literalBody(value)
		doc, err := JiraADF(message.Fields["body"], nil)
		if err != nil {
			t.Fatal(err)
		}
		paragraph := doc["content"].([]any)[0].(map[string]any)
		nodes := paragraph["content"].([]any)
		if len(nodes) != 1 || nodes[0].(map[string]any)["text"] != want || nodes[0].(map[string]any)["marks"] != nil {
			t.Errorf("%q: ADF %+v", value, nodes)
		}
		wiki, err := JiraWiki(message.Fields["body"], nil)
		if err != nil {
			t.Fatal(err)
		}
		if wiki != escapeWiki(want) {
			t.Errorf("%q: wiki %q", value, wiki)
		}
		assertEscaped(t, "jira wiki "+value, strings.NewReplacer("&#92;", "", "&amp;", "", "&#58;", "").Replace(wiki), wikiSpecial)
		if strings.ContainsAny(strings.NewReplacer("&#92;", "", "&amp;", "", "&#58;", "").Replace(strings.ReplaceAll(wiki, "\\", "")), "&:") {
			t.Errorf("%q: wiki has a raw & or : %q", value, wiki)
		}
	}
}

// assertEscaped checks that every special character in out is preceded by a backslash, and that
// every backslash escapes the character after it.
func assertEscaped(t *testing.T, label, out, special string) {
	t.Helper()
	for i := 0; i < len(out); i++ {
		c := out[i]
		if c == '\\' {
			if i+1 >= len(out) {
				t.Errorf("%s: dangling backslash in %q", label, out)
				return
			}
			i++
			continue
		}
		if strings.IndexByte(special, c) >= 0 {
			t.Errorf("%s: unescaped %q in %q", label, c, out)
			return
		}
	}
}

func TestTelegramSeparatesAdjacentItalics(t *testing.T) {
	out, err := Telegram(ports.RenderedMessage{Fields: map[string]string{"body": "*a*_b_ **bold *nested* bold**"}})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(out.Body, &payload)
	if payload.Text != "_a_**_b_ *bold _nested_ bold*" {
		t.Fatalf("text %q", payload.Text)
	}
}

func TestDiscordCodeSpansHoldBackticks(t *testing.T) {
	cases := map[string]string{"plain": "`plain`", "a`b": "``a`b``", "`edge": "`` `edge ``", "x``y": "```x``y```"}
	for value, want := range cases {
		if got := discordCode(value); got != want {
			t.Errorf("discordCode(%q) = %q, want %q", value, got, want)
		}
	}
}

// Every channel with a hard limit gets content that fits it, whatever the escaping costs.
func TestLimitsHoldForPunctuationHeavyContent(t *testing.T) {
	heavy := strings.Repeat(msgtemplate.EscapeMarkdown("*_[]()~`>#+-=|{}.!")+" ", 600)
	message := ports.RenderedMessage{
		Fields: map[string]string{"title": strings.Repeat("|", 400), "body": heavy},
		Links:  []ports.RenderedLink{{Label: "Open", URL: "https://synapse.example.com/f"}},
	}
	out, err := Discord(message)
	if err != nil {
		t.Fatal(err)
	}
	var discord struct {
		Embeds []map[string]string `json:"embeds"`
	}
	_ = json.Unmarshal(out.Body, &discord)
	if n := utf8.RuneCountInString(discord.Embeds[0]["description"]); n > discordDescriptionRunes {
		t.Errorf("discord description has %d runes", n)
	}
	if n := utf8.RuneCountInString(discord.Embeds[0]["title"]); n > discordTitleRunes {
		t.Errorf("discord title has %d runes", n)
	}
	if !strings.Contains(discord.Embeds[0]["description"], "(https://synapse.example.com/f)") {
		t.Error("discord dropped the link to fit")
	}

	tg, err := Telegram(message)
	if err != nil {
		t.Fatal(err)
	}
	var telegram struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(tg.Body, &telegram)
	// Telegram counts characters after parsing: escapes, markers and link targets are not shown.
	if n := visibleTelegram(telegram.Text); n > telegramTextRunes {
		t.Errorf("telegram text has %d visible runes", n)
	}
}

// visibleTelegram approximates the parsed length: it drops escaping backslashes, the bold markers
// of the title and the "(url)" part of links.
func visibleTelegram(text string) int {
	if title, rest, ok := strings.Cut(text, "\n\n"); ok && strings.HasPrefix(title, "*") && strings.HasSuffix(title, "*") {
		text = title[1:len(title)-1] + "\n\n" + rest
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '\\' && i+1 < len(text) {
			i++
		}
		b.WriteByte(text[i])
	}
	visible := b.String()
	if i := strings.LastIndex(visible, "]("); i >= 0 {
		visible = visible[:i]
	}
	return utf8.RuneCountInString(visible)
}
