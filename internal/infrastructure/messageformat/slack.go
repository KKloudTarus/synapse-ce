package messageformat

import (
	"encoding/json"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Slack formats the chat fields ("title", "body") as Block Kit for incoming webhooks and
// chat.postMessage.
//
// The body is a rich_text block. Its text elements are shown literally and styling is carried by a
// style object, so no character of a value is ever read as mrkdwn: Slack mrkdwn has no way to
// escape "*", "_", "~" or "`", and would turn "<!channel>" or "<url|label>" into a mention or a
// link. The title is a plain_text header. The fallback "text", which Slack shows in notifications
// and reads as mrkdwn, has its control characters &, < and > escaped as Slack documents.
type Slack struct{}

var _ ports.NotificationFormatter = Slack{}

const slackHeaderRunes = 150 // Block Kit header text limit

func (Slack) ChannelType() notification.ChannelType { return notification.ChannelSlack }

func (Slack) Format(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	title := truncateRunes(strings.TrimSpace(msgtemplate.Sanitize(message.Fields["title"])), slackHeaderRunes)
	blocks := []any{}
	if title != "" {
		blocks = append(blocks, map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": title, "emoji": false}})
	}
	if elements := slackRichText(msgmarkdown.Parse(message.Fields["body"]), links); len(elements) > 0 {
		blocks = append(blocks, map[string]any{"type": "rich_text", "elements": elements})
	}
	body, err := json.Marshal(map[string]any{"text": escapeSlackControl(title), "blocks": blocks})
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: body}, nil
}

// escapeSlackControl escapes the three characters Slack parses as control sequences in mrkdwn.
func escapeSlackControl(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value)
}

type slackStyle struct {
	Bold   bool `json:"bold,omitempty"`
	Italic bool `json:"italic,omitempty"`
	Code   bool `json:"code,omitempty"`
}

// slackRichText converts the document into rich_text elements: a rich_text_section per paragraph,
// a bullet rich_text_list per list, and a final section of links. Paragraphs are separated by a
// line break, as Slack renders consecutive sections on one line.
func slackRichText(doc msgmarkdown.Document, links []link) []any {
	var elements []any
	for i, block := range doc.Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			inline := slackInlines(v.Inlines, slackStyle{})
			if i < len(doc.Blocks)-1 || len(links) > 0 {
				inline = append(inline, slackText("\n", slackStyle{}))
			}
			elements = append(elements, map[string]any{"type": "rich_text_section", "elements": inline})
		case msgmarkdown.List:
			var items []any
			for _, item := range v.Items {
				if inline := slackInlines(item, slackStyle{}); len(inline) > 0 {
					items = append(items, map[string]any{"type": "rich_text_section", "elements": inline})
				}
			}
			if len(items) > 0 {
				elements = append(elements, map[string]any{"type": "rich_text_list", "style": "bullet", "indent": 0, "elements": items})
			}
		}
	}
	if len(links) > 0 {
		var inline []any
		for i, l := range links {
			if i > 0 {
				inline = append(inline, slackText(" · ", slackStyle{}))
			}
			inline = append(inline, map[string]any{"type": "link", "url": l.url, "text": l.label})
		}
		elements = append(elements, map[string]any{"type": "rich_text_section", "elements": inline})
	}
	return elements
}

func slackInlines(inlines []msgmarkdown.Inline, style slackStyle) []any {
	var out []any
	for _, n := range inlines {
		switch v := n.(type) {
		case msgmarkdown.Text:
			if v.Value != "" {
				out = append(out, slackText(v.Value, style))
			}
		case msgmarkdown.Strong:
			bold := style
			bold.Bold = true
			out = append(out, slackInlines(v.Children, bold)...)
		case msgmarkdown.Emphasis:
			italic := style
			italic.Italic = true
			out = append(out, slackInlines(v.Children, italic)...)
		case msgmarkdown.Code:
			if v.Value != "" {
				code := style
				code.Code = true
				out = append(out, slackText(v.Value, code))
			}
		case msgmarkdown.LineBreak:
			out = append(out, slackText("\n", slackStyle{}))
		}
	}
	return out
}

func slackText(value string, style slackStyle) map[string]any {
	element := map[string]any{"type": "text", "text": value}
	if style != (slackStyle{}) {
		element["style"] = style
	}
	return element
}

// SlackBot formats the messages of a Slack bot channel (#1383). chat.postMessage takes the same
// Block Kit as an incoming webhook, so it is Slack under the bot channel's type; the driver adds
// the conversation and switches link unfurling off.
type SlackBot struct{ Slack }

var _ ports.NotificationFormatter = SlackBot{}

func (SlackBot) ChannelType() notification.ChannelType { return notification.ChannelSlackBot }
