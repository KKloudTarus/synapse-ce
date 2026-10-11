package msgmarkdown

import "strings"

// render prints a tree compactly so cases read like CommonMark's HTML examples: <p>, <li>, <strong>,
// <em>, <code> and <br> for a line break. Text is printed as is.
func render(doc Document) string {
	var b strings.Builder
	for _, block := range doc.Blocks {
		switch v := block.(type) {
		case Paragraph:
			b.WriteString("<p>")
			renderInlines(&b, v.Inlines)
			b.WriteString("</p>")
		case List:
			b.WriteString("<ul>")
			for _, item := range v.Items {
				b.WriteString("<li>")
				renderInlines(&b, item)
				b.WriteString("</li>")
			}
			b.WriteString("</ul>")
		}
	}
	return b.String()
}

func renderInlines(b *strings.Builder, inlines []Inline) {
	for _, n := range inlines {
		switch v := n.(type) {
		case Text:
			b.WriteString(v.Value)
		case Strong:
			b.WriteString("<strong>")
			renderInlines(b, v.Children)
			b.WriteString("</strong>")
		case Emphasis:
			b.WriteString("<em>")
			renderInlines(b, v.Children)
			b.WriteString("</em>")
		case Code:
			b.WriteString("<code>" + v.Value + "</code>")
		case LineBreak:
			b.WriteString("<br>")
		}
	}
}
