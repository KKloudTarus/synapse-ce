package messageformat

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JiraADF renders a ticket body as an Atlassian Document Format document for Jira Cloud (API v3).
// ADF is a JSON tree, so text needs no escaping: every value is the "text" of a text node, and
// formatting and links exist only as marks the renderer adds. Two ADF rules shape the output: a
// text node must not be empty, and the code mark combines only with link, so code inside bold or
// italic carries the code mark alone.
func JiraADF(body string, links []ports.RenderedLink) (map[string]any, error) {
	checked, err := checkLinks(links)
	if err != nil {
		return nil, err
	}
	content := []any{}
	for _, block := range msgmarkdown.Parse(body).Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			content = append(content, adfParagraph(adfInlines(v.Inlines, nil)))
		case msgmarkdown.List:
			items := make([]any, 0, len(v.Items))
			for _, item := range v.Items {
				items = append(items, map[string]any{"type": "listItem", "content": []any{adfParagraph(adfInlines(item, nil))}})
			}
			if len(items) > 0 {
				content = append(content, map[string]any{"type": "bulletList", "content": items})
			}
		}
	}
	if len(checked) > 0 {
		var inline []any
		for i, l := range checked {
			if i > 0 {
				inline = append(inline, adfText(" · ", nil))
			}
			inline = append(inline, adfText(l.label, []any{map[string]any{"type": "link", "attrs": map[string]any{"href": l.url}}}))
		}
		content = append(content, adfParagraph(inline))
	}
	return map[string]any{"type": "doc", "version": 1, "content": content}, nil
}

func adfParagraph(inline []any) map[string]any {
	if inline == nil {
		inline = []any{}
	}
	return map[string]any{"type": "paragraph", "content": inline}
}

func adfInlines(inlines []msgmarkdown.Inline, marks []string) []any {
	var out []any
	for _, n := range inlines {
		switch v := n.(type) {
		case msgmarkdown.Text:
			if v.Value != "" {
				out = append(out, adfText(v.Value, adfMarks(marks)))
			}
		case msgmarkdown.Strong:
			out = append(out, adfInlines(v.Children, appendMark(marks, "strong"))...)
		case msgmarkdown.Emphasis:
			out = append(out, adfInlines(v.Children, appendMark(marks, "em"))...)
		case msgmarkdown.Code:
			if v.Value != "" {
				out = append(out, adfText(v.Value, adfMarks([]string{"code"})))
			}
		case msgmarkdown.LineBreak:
			out = append(out, map[string]any{"type": "hardBreak"})
		}
	}
	return out
}

func adfText(text string, marks []any) map[string]any {
	node := map[string]any{"type": "text", "text": text}
	if len(marks) > 0 {
		node["marks"] = marks
	}
	return node
}

// appendMark adds a mark once; nested emphasis inside emphasis keeps a single em mark, as ADF
// allows each mark type once per node.
func appendMark(marks []string, mark string) []string {
	for _, m := range marks {
		if m == mark {
			return marks
		}
	}
	return append(append([]string(nil), marks...), mark)
}

func adfMarks(marks []string) []any {
	out := make([]any, len(marks))
	for i, m := range marks {
		out[i] = map[string]any{"type": m}
	}
	return out
}
