package msgmarkdown

import "strings"

// Parse parses a message body in the Markdown subset. It never fails: anything outside the subset
// is kept as literal text.
func Parse(source string) Document {
	var doc Document
	var paragraph []string
	var items [][]Inline
	flushParagraph := func() {
		if len(paragraph) > 0 {
			doc.Blocks = append(doc.Blocks, Paragraph{Inlines: parseInlines(strings.Join(paragraph, "\n"))})
			paragraph = nil
		}
	}
	flushList := func() {
		if len(items) > 0 {
			doc.Blocks = append(doc.Blocks, List{Items: items})
			items = nil
		}
	}
	for _, line := range splitLines(source) {
		if isBlank(line) {
			flushParagraph()
			flushList()
			continue
		}
		if content, ok := bulletItem(line); ok {
			flushParagraph()
			items = append(items, parseInlines(content))
			continue
		}
		flushList()
		paragraph = append(paragraph, strings.TrimLeft(line, " \t"))
	}
	flushParagraph()
	flushList()
	return doc
}

// isBlank is the CommonMark blank line: only spaces and tabs. Other Unicode spaces, such as a
// no-break space from a value, are content.
func isBlank(line string) bool {
	return strings.Trim(line, " \t") == ""
}

// splitLines splits on LF, treating CRLF and a lone CR as line endings too.
func splitLines(source string) []string {
	source = strings.ReplaceAll(source, "\r\n", "\n")
	source = strings.ReplaceAll(source, "\r", "\n")
	return strings.Split(source, "\n")
}

// bulletItem recognizes "- item", "* item" and "+ item" after at most three spaces, and returns the
// item's content. A marker must be followed by a space or end the line, so "-1" and "**bold**" are
// not items. A line whose content would be only a marker run such as "***" is a thematic break in
// CommonMark; the subset has none, so it stays paragraph text.
func bulletItem(line string) (string, bool) {
	indent := len(line) - len(strings.TrimLeft(line, " "))
	if indent > 3 {
		return "", false
	}
	rest := line[indent:]
	if rest == "" || strings.IndexByte("-*+", rest[0]) < 0 {
		return "", false
	}
	if len(rest) > 1 && rest[1] != ' ' && rest[1] != '\t' {
		return "", false
	}
	if isThematicBreak(rest) {
		return "", false
	}
	return strings.TrimLeft(rest[1:], " \t"), true
}

// isThematicBreak reports a line of three or more of one of -, *, _ with only spaces between.
func isThematicBreak(line string) bool {
	var marker byte
	count := 0
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == ' ' || c == '\t':
		case marker == 0 && (c == '-' || c == '*' || c == '_'):
			marker = c
			count++
		case c == marker:
			count++
		default:
			return false
		}
	}
	return count >= 3
}
