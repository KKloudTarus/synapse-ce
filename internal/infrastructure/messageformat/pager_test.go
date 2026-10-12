package messageformat

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPagerFormattersExposeOnlySummaryAndTrustedLinks(t *testing.T) {
	message := ports.RenderedMessage{Fields: map[string]string{"summary": "critical", "body": "secret body", "title": "secret title"}, Links: []ports.RenderedLink{{Label: "Open", URL: "https://console.example/f/1"}}}
	for _, formatter := range []ports.NotificationFormatter{PagerDutyFormatter{}, JSMFormatter{}} {
		out, err := formatter.Format(message)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out.Body, []byte(`"summary":"critical"`)) || bytes.Contains(out.Body, []byte("secret")) || !bytes.Contains(out.Body, []byte("console.example")) {
			t.Errorf("%T unsafe pager output: %s", formatter, out.Body)
		}
	}
}

func TestPagerFormattersShowCanonicalSummaryAsPlainText(t *testing.T) {
	for _, value := range []string{
		"request-review",
		"Cảnh báo: 2 mới, 1 đã sửa",
		"[Reset password](https://evil.example) @everyone <!channel> **bold**",
		`C:\synthetic\report.json`,
	} {
		for _, formatter := range []ports.NotificationFormatter{PagerDutyFormatter{}, JSMFormatter{}} {
			out, err := formatter.Format(ports.RenderedMessage{Fields: map[string]string{
				"summary": "**Alert:** " + msgtemplate.EscapeMarkdown(msgtemplate.Sanitize(value)),
			}})
			if err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Summary string `json:"summary"`
			}
			if err := json.Unmarshal(out.Body, &payload); err != nil {
				t.Fatal(err)
			}
			if want := "Alert: " + value; payload.Summary != want {
				t.Errorf("%T summary = %q, want %q", formatter, payload.Summary, want)
			}
		}
	}
}

func TestPagerFormattersBoundUnicodeSummaryForTheirProvider(t *testing.T) {
	summary := strings.Repeat("Cảnh báo 🔥 <@here> ", 200)
	for _, tc := range []struct {
		formatter ports.NotificationFormatter
		max       int
	}{
		{PagerDutyFormatter{}, PagerDutySummaryRunes},
		{JSMFormatter{}, JSMMessageRunes},
	} {
		out, err := tc.formatter.Format(ports.RenderedMessage{Fields: map[string]string{"summary": summary}})
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Summary string `json:"summary"`
		}
		if err := json.Unmarshal(out.Body, &payload); err != nil {
			t.Fatal(err)
		}
		if !utf8.ValidString(payload.Summary) || utf8.RuneCountInString(payload.Summary) > tc.max {
			t.Errorf("%T summary invalid/beyond %d runes: %d", tc.formatter, tc.max, utf8.RuneCountInString(payload.Summary))
		}
	}
}
