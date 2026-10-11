package messageformat

import (
	"encoding/json"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Teams formats the chat fields as a message carrying one Adaptive Card, the body a Teams
// Workflows webhook or a bot accepts.
//
// All text goes into RichTextBlock TextRuns. A TextBlock interprets a Markdown subset and Teams
// honours backslash escapes inconsistently across desktop and mobile, while a TextRun is shown
// literally and carries bold, italic and monospace as properties, so no value can become
// formatting, a link or a mention. List items are runs prefixed with a bullet, because a
// RichTextBlock has no list element. Links are Action.OpenUrl buttons.
//
// A Teams message is limited to about 28 KB; the body is cut to teamsBodyRunes of visible text,
// which keeps the card well inside that.
func Teams(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	var body []any
	if title := strings.TrimSpace(msgtemplate.Sanitize(message.Fields["title"])); title != "" {
		body = append(body, teamsRichText([]map[string]any{{"type": "TextRun", "text": truncateRunes(title, teamsTitleRunes), "weight": "Bolder", "size": "Medium"}}))
	}
	for _, block := range truncateDocument(msgmarkdown.Parse(message.Fields["body"]), teamsBodyRunes).Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			if runs := teamsRuns(v.Inlines, teamsStyle{}); len(runs) > 0 {
				body = append(body, teamsRichText(runs))
			}
		case msgmarkdown.List:
			for _, item := range v.Items {
				runs := append([]map[string]any{{"type": "TextRun", "text": "• "}}, teamsRuns(item, teamsStyle{})...)
				body = append(body, teamsRichText(runs))
			}
		}
	}
	card := map[string]any{
		"type": "AdaptiveCard", "version": "1.4",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"body":    body,
	}
	if len(links) > 0 {
		actions := make([]any, len(links))
		for i, l := range links {
			actions[i] = map[string]any{"type": "Action.OpenUrl", "title": l.label, "url": l.url}
		}
		card["actions"] = actions
	}
	payload, err := json.Marshal(map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     card,
		}},
	})
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: payload}, nil
}

const (
	teamsTitleRunes = 256
	teamsBodyRunes  = 8000
)

type teamsStyle struct{ bold, italic, code bool }

func teamsRichText(runs []map[string]any) map[string]any {
	inlines := make([]any, len(runs))
	for i, run := range runs {
		inlines[i] = run
	}
	return map[string]any{"type": "RichTextBlock", "inlines": inlines}
}

func teamsRuns(inlines []msgmarkdown.Inline, style teamsStyle) []map[string]any {
	var out []map[string]any
	for _, n := range inlines {
		switch v := n.(type) {
		case msgmarkdown.Text:
			if v.Value != "" {
				out = append(out, teamsRun(v.Value, style))
			}
		case msgmarkdown.Strong:
			bold := style
			bold.bold = true
			out = append(out, teamsRuns(v.Children, bold)...)
		case msgmarkdown.Emphasis:
			italic := style
			italic.italic = true
			out = append(out, teamsRuns(v.Children, italic)...)
		case msgmarkdown.Code:
			if v.Value != "" {
				code := style
				code.code = true
				out = append(out, teamsRun(v.Value, code))
			}
		case msgmarkdown.LineBreak:
			out = append(out, teamsRun("\n", teamsStyle{}))
		}
	}
	return out
}

func teamsRun(text string, style teamsStyle) map[string]any {
	run := map[string]any{"type": "TextRun", "text": text}
	if style.bold {
		run["weight"] = "Bolder"
	}
	if style.italic {
		run["italic"] = true
	}
	if style.code {
		run["fontType"] = "Monospace"
	}
	return run
}
