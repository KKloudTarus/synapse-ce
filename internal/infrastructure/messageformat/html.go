package messageformat

import (
	"html"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// HTMLFragment renders canonical Markdown as code-owned HTML. Body text cannot
// create anchors or raw HTML; only checked typed HTTPS links become anchors.
func HTMLFragment(body string, renderedLinks []ports.RenderedLink) (string, error) {
	links, err := checkLinks(renderedLinks)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, block := range msgmarkdown.Parse(body).Blocks {
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
			b.WriteString(html.EscapeString(defangEmailURLs(v.Value)))
		case msgmarkdown.Strong:
			b.WriteString("<strong>")
			htmlInlines(b, v.Children)
			b.WriteString("</strong>")
		case msgmarkdown.Emphasis:
			b.WriteString("<em>")
			htmlInlines(b, v.Children)
			b.WriteString("</em>")
		case msgmarkdown.Code:
			b.WriteString("<code>" + html.EscapeString(defangEmailURLs(v.Value)) + "</code>")
		case msgmarkdown.LineBreak:
			b.WriteString("<br>\n")
		}
	}
}
