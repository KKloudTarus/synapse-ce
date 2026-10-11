package messageformat

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JiraWiki renders a ticket body as Jira wiki markup for Jira Data Center (API v2).
//
// Wiki markup is escaped character by character. A backslash before a special character shows it
// literally, which covers text effects (*bold*, _italic_, -deleted-, +inserted+, ^sup^, ~sub~,
// ??citation??, {{monospace}}), macros ({...}), links and user mentions ([...|...], [~user]),
// images and tables (!...!, |), lists and headings at a line start (*, #, -, h1.), and emoticons
// such as (y) or :). Only those characters are escaped, because a backslash before any other
// character is not handled consistently (JRASERVER-23558). The backslash itself cannot be escaped,
// as "\\" is a forced line break (JRASERVER-9258), so it is written as the HTML entity &#92;, the
// workaround Atlassian documents; ":" is written as &#58; for the same reason, which also stops
// emoticons such as :D, and "&" as &amp; so an entity in a value is shown literally.
func JiraWiki(body string, links []ports.RenderedLink) (string, error) {
	checked, err := checkLinks(links)
	if err != nil {
		return "", err
	}
	var parts []string
	for _, block := range msgmarkdown.Parse(body).Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			parts = append(parts, wikiInlines(v.Inlines))
		case msgmarkdown.List:
			lines := make([]string, 0, len(v.Items))
			for _, item := range v.Items {
				lines = append(lines, "* "+wikiInlines(item))
			}
			parts = append(parts, strings.Join(lines, "\n"))
		}
	}
	if len(checked) > 0 {
		lines := make([]string, len(checked))
		for i, l := range checked {
			lines[i] = "[" + escapeWiki(l.label) + "|" + wikiURL(l.url) + "]"
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	return strings.Join(parts, "\n\n"), nil
}

// wikiURL percent-encodes brackets so a URL cannot end the link early; checkLinks already refuses
// "|".
func wikiURL(value string) string {
	return strings.NewReplacer("[", "%5B", "]", "%5D").Replace(value)
}

// wikiSpecial is every character with a meaning in Jira wiki markup that a backslash escapes. The
// backslash, the colon and the ampersand are written as entities instead.
const wikiSpecial = "*_-+^~?{}[]|!#()"

func escapeWiki(value string) string {
	var b strings.Builder
	b.Grow(len(value) + len(value)/4)
	for _, r := range value {
		switch {
		case r == '\\':
			b.WriteString("&#92;")
		case r == '&':
			b.WriteString("&amp;")
		case r == ':':
			b.WriteString("&#58;")
		case r < 128 && strings.ContainsRune(wikiSpecial, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func wikiInlines(inlines []msgmarkdown.Inline) string {
	var b strings.Builder
	for _, n := range inlines {
		switch v := n.(type) {
		case msgmarkdown.Text:
			b.WriteString(escapeWiki(v.Value))
		case msgmarkdown.Strong:
			b.WriteString("*" + wikiInlines(v.Children) + "*")
		case msgmarkdown.Emphasis:
			b.WriteString("_" + wikiInlines(v.Children) + "_")
		case msgmarkdown.Code:
			b.WriteString("{{" + escapeWiki(v.Value) + "}}")
		case msgmarkdown.LineBreak:
			b.WriteByte('\n')
		}
	}
	return b.String()
}
