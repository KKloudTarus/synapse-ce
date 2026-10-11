package messageformat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSelfHostedFormattersRenderTrustedCanonicalMarkdownAndLinks(t *testing.T) {
	message := ports.RenderedMessage{
		Fields: map[string]string{
			"title": "**Critical**: /api",
			"body":  "**Rule**: `CWE-89`\n\n- Host: api.example.com\n- Status: _open_",
		},
		Links: []ports.RenderedLink{{Label: "Open finding", URL: "https://console.example/findings/(1)"}},
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
		for _, want := range []string{"**Critical**: /api", "**Rule**: `CWE-89`", "\n\n- Host: api.example.com", "\n- Status: _open_", "[Open finding](https://console.example/findings/%281%29)"} {
			if !strings.Contains(payload.Text, want) {
				t.Errorf("%T lacks %q: %q", formatter, want, payload.Text)
			}
		}
		if strings.Contains(payload.Text, `\:`) || strings.Contains(payload.Text, `\/`) {
			t.Errorf("%T escaped ordinary URL punctuation: %q", formatter, payload.Text)
		}
		if strings.Contains(string(out.Body), `"blocks"`) {
			t.Errorf("%T used Slack-only blocks: %s", formatter, out.Body)
		}
	}
}

func TestSelfHostedFormattersKeepEscapedEventValuesLiteral(t *testing.T) {
	value := "@channel [forged](HTTPs://evil.example/a) www.evil.example <!here> **bold**"
	canonical := msgtemplate.EscapeMarkdown(msgtemplate.Sanitize(value))
	message := ports.RenderedMessage{
		Fields: map[string]string{"title": "Finding: " + canonical, "body": "Value: " + canonical},
		Links:  []ports.RenderedLink{{Label: "Open finding", URL: "https://console.example/findings/1"}},
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
		forbidden := []string{"\n@channel", "[forged](HTTPs://evil.example", "HTTPs://evil.example", "www.evil.example"}
		if _, mattermost := formatter.(MattermostFormatter); mattermost {
			forbidden = append(forbidden, "**bold**")
		}
		for _, forbidden := range forbidden {
			if strings.Contains(payload.Text, forbidden) {
				t.Errorf("%T exposed event syntax %q: %q", formatter, forbidden, payload.Text)
			}
		}
		for _, want := range []string{"@\u200bchannel", "HTTPs:\u200b//evil.example/a", "w\u200bww.evil.example"} {
			if !strings.Contains(payload.Text, want) {
				t.Errorf("%T did not neutralize event value %q: %q", formatter, want, payload.Text)
			}
		}
		switch formatter.(type) {
		case MattermostFormatter:
			for _, want := range []string{`&lt;\!here&gt;`, `\*\*bold\*\*`} {
				if !strings.Contains(payload.Text, want) {
					t.Errorf("Mattermost did not retain literal event value %q: %q", want, payload.Text)
				}
			}
		case RocketChatFormatter:
			for _, forbidden := range []string{`\[`, `\(`, `\*`, `&lt;`, `&gt;`} {
				if strings.Contains(payload.Text, forbidden) {
					t.Errorf("Rocket.Chat left visible literal escape %q: %q", forbidden, payload.Text)
				}
			}
			if !strings.Contains(payload.Text, "`") || !strings.Contains(payload.Text, "<!here> **bold**") {
				t.Errorf("Rocket.Chat did not place hostile text in a literal code span: %q", payload.Text)
			}
		}
		if !strings.Contains(payload.Text, "[Open finding](https://console.example/findings/1)") {
			t.Errorf("%T did not retain checked link: %q", formatter, payload.Text)
		}
	}
}

func TestSelfHostedFormattersKeepHostileBlockMarkersLiteralAtBodyStart(t *testing.T) {
	for _, value := range []string{"# heading", "- item", "+ item", "= heading"} {
		t.Run(value, func(t *testing.T) {
			message := ports.RenderedMessage{Fields: map[string]string{"body": msgtemplate.EscapeMarkdown(value)}}
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
				want := "\\" + value
				if _, rocket := formatter.(RocketChatFormatter); rocket {
					want = "`" + value + "`"
				}
				if payload.Text != want {
					t.Errorf("%T rendered block marker %q as %q", formatter, value, payload.Text)
				}
			}
		})
	}
}

func TestRocketChatKeepsOrdinaryAmpersandsVisible(t *testing.T) {
	message := ports.RenderedMessage{Fields: map[string]string{"body": msgtemplate.EscapeMarkdown("React & Go")}}
	out, err := (RocketChatFormatter{}).Format(message)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(out.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Text != "React & Go" {
		t.Fatalf("ordinary text = %q", payload.Text)
	}
}

func TestSelfHostedFormattersKeepNumberedEventLinesLiteral(t *testing.T) {
	message := ports.RenderedMessage{Fields: map[string]string{"body": msgtemplate.EscapeMarkdown("1. forged\n2. second\nVersion 1.2 is ready.")}}
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
		want := "1\\. forged\n2\\. second\nVersion 1.2 is ready."
		if _, rocket := formatter.(RocketChatFormatter); rocket {
			want = "`1. forged`\n`2. second`\nVersion 1.2 is ready."
		}
		if payload.Text != want {
			t.Errorf("%T rendered numbered event lines as %q, want %q", formatter, payload.Text, want)
		}
	}
}
