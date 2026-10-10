package messageformat

import (
	"bytes"
	"html"
	"html/template"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Email formats the email fields ("subject", "body") as a text/plain body and a header-safe
// subject. EmailHTML renders the same content as an HTML fragment for the multipart layout of
// #1368; both come from one syntax tree, so the two parts cannot disagree.
type Email struct{}

var _ ports.NotificationFormatter = Email{}

const emailSubjectRunes = 180

var emailLayout = template.Must(template.New("email").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body><main>{{.Body}}</main></body></html>`))

func (Email) ChannelType() notification.ChannelType { return notification.ChannelEmail }

func (Email) Format(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	text := emailText(msgmarkdown.Parse(message.Fields["body"]), links)
	htmlBody, err := EmailHTML(message)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{
		ContentType: "text/plain; charset=UTF-8",
		Body:        []byte(text),
		HTMLBody:    []byte(htmlBody),
		Subject:     EmailSubject(message.Fields["subject"]),
	}, nil
}

// EmailSubject makes a subject safe for a single header line: sanitized, whitespace collapsed and
// bounded. msgtemplate.Sanitize already turns line breaks into spaces, which rules out header
// injection.
func EmailSubject(subject string) string {
	return truncateRunes(strings.Join(strings.Fields(msgtemplate.Sanitize(subject)), " "), emailSubjectRunes)
}

// emailText renders plain text: paragraphs separated by a blank line, list items as "- item",
// emphasis without markers, and links as "label: url" lines at the end.
func emailText(doc msgmarkdown.Document, links []link) string {
	var parts []string
	for _, block := range doc.Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			parts = append(parts, plainText(v.Inlines))
		case msgmarkdown.List:
			lines := make([]string, 0, len(v.Items))
			for _, item := range v.Items {
				lines = append(lines, "- "+plainText(item))
			}
			parts = append(parts, strings.Join(lines, "\n"))
		}
	}
	if len(links) > 0 {
		lines := make([]string, 0, len(links))
		for _, l := range links {
			lines = append(lines, l.label+": "+l.url)
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	return strings.Join(parts, "\n\n")
}

func plainText(inlines []msgmarkdown.Inline) string {
	var b strings.Builder
	var walk func([]msgmarkdown.Inline)
	walk = func(inlines []msgmarkdown.Inline) {
		for _, n := range inlines {
			switch v := n.(type) {
			case msgmarkdown.Text:
				b.WriteString(v.Value)
			case msgmarkdown.Strong:
				walk(v.Children)
			case msgmarkdown.Emphasis:
				walk(v.Children)
			case msgmarkdown.Code:
				b.WriteString(v.Value)
			case msgmarkdown.LineBreak:
				b.WriteByte('\n')
			}
		}
	}
	walk(inlines)
	return b.String()
}

// EmailHTML renders a complete code-owned HTML document. Every message text node and attribute is
// escaped before it becomes the layout's trusted fragment, and a link is an anchor only for a
// checked https URL. The layout has no remote assets.
func EmailHTML(message ports.RenderedMessage) (string, error) {
	fragment, err := emailHTMLFragment(message)
	if err != nil {
		return "", err
	}
	var output bytes.Buffer
	if err := emailLayout.Execute(&output, struct{ Body template.HTML }{Body: template.HTML(fragment)}); err != nil {
		return "", err
	}
	return output.String(), nil
}

func emailHTMLFragment(message ports.RenderedMessage) (string, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, block := range msgmarkdown.Parse(message.Fields["body"]).Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			b.WriteString("<p>")
			htmlInlines(&b, v.Inlines)
			b.WriteString("</p>\n")
		case msgmarkdown.List:
			b.WriteString("<ul>\n")
			for _, item := range v.Items {
				b.WriteString("<li>")
				htmlInlines(&b, item)
				b.WriteString("</li>\n")
			}
			b.WriteString("</ul>\n")
		}
	}
	if len(links) > 0 {
		b.WriteString("<p>")
		for i, l := range links {
			if i > 0 {
				b.WriteString(" &middot; ")
			}
			b.WriteString(`<a href="` + html.EscapeString(l.url) + `" rel="noopener noreferrer">` + html.EscapeString(l.label) + "</a>")
		}
		b.WriteString("</p>\n")
	}
	return b.String(), nil
}

func htmlInlines(b *strings.Builder, inlines []msgmarkdown.Inline) {
	for _, n := range inlines {
		switch v := n.(type) {
		case msgmarkdown.Text:
			b.WriteString(html.EscapeString(v.Value))
		case msgmarkdown.Strong:
			b.WriteString("<strong>")
			htmlInlines(b, v.Children)
			b.WriteString("</strong>")
		case msgmarkdown.Emphasis:
			b.WriteString("<em>")
			htmlInlines(b, v.Children)
			b.WriteString("</em>")
		case msgmarkdown.Code:
			b.WriteString("<code>" + html.EscapeString(v.Value) + "</code>")
		case msgmarkdown.LineBreak:
			b.WriteString("<br>\n")
		}
	}
}
