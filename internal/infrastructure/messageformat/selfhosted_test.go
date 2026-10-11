package messageformat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestSelfHostedFormattersKeepHostileContentLiteralAndAllowTrustedLinks(t *testing.T) {
	message := ports.RenderedMessage{Fields: map[string]string{"title": "P1 @channel", "body": "[forged](https://evil.example) <!here> **bold**"}, Links: []ports.RenderedLink{{Label: "Open finding", URL: "https://console.example/findings/1"}}}
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
		for _, want := range []string{`\[forged\]\(https\:\/\/evil\.example\)`, `\<\!here\>`, `\*\*bold\*\*`, `https://console.example/findings/1`} {
			if !strings.Contains(payload.Text, want) {
				t.Errorf("%T lacks %q: %q", formatter, want, payload.Text)
			}
		}
		if strings.Contains(string(out.Body), `"blocks"`) {
			t.Errorf("%T used Slack-only blocks: %s", formatter, out.Body)
		}
	}
}
