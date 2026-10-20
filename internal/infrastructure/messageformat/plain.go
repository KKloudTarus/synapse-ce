package messageformat

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
)

// PlainText renders the message Markdown subset for a plain-text provider field.
// Escaped data stays literal, emphasis markers disappear, and paragraph/list
// boundaries remain visible. Trusted links are appended separately by the caller.
func PlainText(body string) string {
	doc := msgmarkdown.Parse(body)
	parts := make([]string, 0, len(doc.Blocks))
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
	return strings.Join(parts, "\n\n")
}
