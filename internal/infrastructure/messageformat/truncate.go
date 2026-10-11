package messageformat

import (
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
)

// ellipsis marks content cut to fit a channel limit.
const ellipsis = "…"

// truncateDocument keeps at most limit runes of visible text, counting text and code values, and
// ends a shortened document with an ellipsis. Channels with a hard text limit (Telegram 4096,
// Discord embed description 4096) are given content that fits instead of a rejected request.
// Markup is not counted: each channel's own markers are few and are covered by the margin its
// caller leaves.
func truncateDocument(doc msgmarkdown.Document, limit int) msgmarkdown.Document {
	budget := limit
	var out msgmarkdown.Document
	for _, block := range doc.Blocks {
		if budget <= 0 {
			break
		}
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			out.Blocks = append(out.Blocks, msgmarkdown.Paragraph{Inlines: truncateInlines(v.Inlines, &budget)})
		case msgmarkdown.List:
			var items [][]msgmarkdown.Inline
			for _, item := range v.Items {
				if budget <= 0 {
					break
				}
				items = append(items, truncateInlines(item, &budget))
			}
			out.Blocks = append(out.Blocks, msgmarkdown.List{Items: items})
		}
	}
	return out
}

func truncateInlines(inlines []msgmarkdown.Inline, budget *int) []msgmarkdown.Inline {
	var out []msgmarkdown.Inline
	for _, n := range inlines {
		if *budget <= 0 {
			break
		}
		switch v := n.(type) {
		case msgmarkdown.Text:
			out = append(out, msgmarkdown.Text{Value: cut(v.Value, budget)})
		case msgmarkdown.Code:
			out = append(out, msgmarkdown.Code{Value: cut(v.Value, budget)})
		case msgmarkdown.Strong:
			out = append(out, msgmarkdown.Strong{Children: truncateInlines(v.Children, budget)})
		case msgmarkdown.Emphasis:
			out = append(out, msgmarkdown.Emphasis{Children: truncateInlines(v.Children, budget)})
		case msgmarkdown.LineBreak:
			*budget--
			out = append(out, v)
		}
	}
	return out
}

// cut spends the budget on value; when the value does not fit it keeps what does, replacing the
// last rune with the ellipsis, and exhausts the budget.
func cut(value string, budget *int) string {
	n := utf8.RuneCountInString(value)
	if n <= *budget {
		*budget -= n
		return value
	}
	runes := []rune(value)
	keep := max(*budget-1, 0)
	*budget = 0
	return string(runes[:keep]) + ellipsis
}

// fitRendered renders doc and, while the output is longer than limit runes, renders a shorter
// truncation of it. It serves channels that count their limit on the raw text, escapes and markers
// included, such as Discord.
func fitRendered(doc msgmarkdown.Document, limit int, render func(msgmarkdown.Document) string) string {
	out := render(doc)
	budget := visibleRunes(doc)
	for utf8.RuneCountInString(out) > limit && budget > 0 {
		budget = budget * limit / utf8.RuneCountInString(out)
		if budget > 1 {
			budget--
		}
		out = render(truncateDocument(doc, budget))
	}
	return out
}

// escapedPrefix returns the longest prefix of value whose escaped form fits in limit runes, with an
// ellipsis when it was cut.
func escapedPrefix(value string, limit int, escape func(string) string) string {
	if utf8.RuneCountInString(escape(value)) <= limit {
		return value
	}
	runes := []rune(value)
	for n := len(runes) - 1; n >= 0; n-- {
		if candidate := string(runes[:n]) + ellipsis; utf8.RuneCountInString(escape(candidate)) <= limit {
			return candidate
		}
	}
	return ""
}

func visibleRunes(doc msgmarkdown.Document) int {
	n := 0
	for _, block := range doc.Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			n += inlineRunes(v.Inlines)
		case msgmarkdown.List:
			for _, item := range v.Items {
				n += inlineRunes(item)
			}
		}
	}
	return n
}

func inlineRunes(inlines []msgmarkdown.Inline) int {
	n := 0
	for _, in := range inlines {
		switch v := in.(type) {
		case msgmarkdown.Text:
			n += utf8.RuneCountInString(v.Value)
		case msgmarkdown.Code:
			n += utf8.RuneCountInString(v.Value)
		case msgmarkdown.Strong:
			n += inlineRunes(v.Children)
		case msgmarkdown.Emphasis:
			n += inlineRunes(v.Children)
		case msgmarkdown.LineBreak:
			n++
		}
	}
	return n
}
