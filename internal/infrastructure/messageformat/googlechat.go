package messageformat

import (
	"encoding/json"
	"html"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// GoogleChat formats the chat fields as a message with one cardsV2 card. Card text fields take a
// small HTML subset, so the body is rendered as HTML with every text node escaped: "<users/all>"
// in a value arrives as "&lt;users/all&gt;" and shows as text instead of mentioning everyone. The
// message has no plain "text" field, which Chat would parse for mentions and Markdown. The header
// title is plain text. Links are buttons that open the checked URL.
//
// A Chat message is limited to 32,000 bytes; the body is cut to googleChatBodyRunes of visible
// text, which keeps the card inside that.
func GoogleChat(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	var widgets []any
	if paragraph := googleChatHTML(truncateDocument(msgmarkdown.Parse(message.Fields["body"]), googleChatBodyRunes)); paragraph != "" {
		widgets = append(widgets, map[string]any{"textParagraph": map[string]any{"text": paragraph}})
	}
	if len(links) > 0 {
		buttons := make([]any, len(links))
		for i, l := range links {
			buttons[i] = map[string]any{"text": l.label, "onClick": map[string]any{"openLink": map[string]any{"url": l.url}}}
		}
		widgets = append(widgets, map[string]any{"buttonList": map[string]any{"buttons": buttons}})
	}
	card := map[string]any{"sections": []any{map[string]any{"widgets": widgets}}}
	if title := truncateRunes(strings.TrimSpace(msgtemplate.Sanitize(message.Fields["title"])), googleChatTitleRunes); title != "" {
		card["header"] = map[string]any{"title": title}
	}
	payload, err := json.Marshal(map[string]any{"cardsV2": []any{map[string]any{"cardId": "synapse-notification", "card": card}}})
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: payload}, nil
}

const (
	googleChatTitleRunes = 200
	googleChatBodyRunes  = 8000
)

// googleChatHTML renders paragraphs separated by a blank line and list items as "• " lines. Chat
// card text keeps line breaks written as <br>.
func googleChatHTML(doc msgmarkdown.Document) string {
	parts := make([]string, 0, len(doc.Blocks))
	for _, block := range doc.Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			parts = append(parts, googleChatInlines(v.Inlines))
		case msgmarkdown.List:
			lines := make([]string, 0, len(v.Items))
			for _, item := range v.Items {
				lines = append(lines, "• "+googleChatInlines(item))
			}
			parts = append(parts, strings.Join(lines, "<br>"))
		}
	}
	return strings.Join(parts, "<br><br>")
}

func googleChatInlines(inlines []msgmarkdown.Inline) string {
	var b strings.Builder
	for _, n := range inlines {
		switch v := n.(type) {
		case msgmarkdown.Text:
			b.WriteString(html.EscapeString(v.Value))
		case msgmarkdown.Strong:
			b.WriteString("<b>" + googleChatInlines(v.Children) + "</b>")
		case msgmarkdown.Emphasis:
			b.WriteString("<i>" + googleChatInlines(v.Children) + "</i>")
		case msgmarkdown.Code:
			b.WriteString("<code>" + html.EscapeString(v.Value) + "</code>")
		case msgmarkdown.LineBreak:
			b.WriteString("<br>")
		}
	}
	return b.String()
}
