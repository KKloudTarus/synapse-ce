package msgmarkdown

import (
	"strings"
	"unicode/utf8"
)

// asciiPunctuation is what a backslash may escape, as in CommonMark and msgtemplate.EscapeMarkdown.
const asciiPunctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// parseInlines scans text into literal runs, code spans, line breaks and emphasis delimiter runs,
// then resolves the delimiter runs into Strong and Emphasis.
func parseInlines(text string) []Inline {
	list := &elementList{}
	var literal strings.Builder
	flush := func() {
		if literal.Len() > 0 {
			list.push(&element{kind: textElement, text: literal.String()})
			literal.Reset()
		}
	}
	for i := 0; i < len(text); {
		switch c := text[i]; {
		case c == '\\':
			if i+1 < len(text) && strings.IndexByte(asciiPunctuation, text[i+1]) >= 0 {
				literal.WriteByte(text[i+1])
				i += 2
				continue
			}
			if i+1 < len(text) && text[i+1] == '\n' {
				flush()
				list.push(&element{kind: nodeElement, node: LineBreak{}})
				i += 2
				continue
			}
			literal.WriteByte(c)
			i++
		case c == '\n':
			flush()
			list.push(&element{kind: nodeElement, node: LineBreak{}})
			i++
		case c == '`':
			span, end, ok := codeSpan(text, i)
			if !ok {
				literal.WriteString(text[i:end])
				i = end
				continue
			}
			flush()
			list.push(&element{kind: nodeElement, node: Code{Value: span}})
			i = end
		case c == '*' || c == '_':
			flush()
			end := i
			for end < len(text) && text[end] == c {
				end++
			}
			list.push(newDelimiter(text, i, end))
			i = end
		default:
			_, size := utf8.DecodeRuneInString(text[i:])
			literal.WriteString(text[i : i+size])
			i += size
		}
	}
	flush()
	processEmphasis(list)
	return list.inlines(list.head, nil)
}

// codeSpan matches a backtick run at start with the next run of the same length. It returns the
// span's content, the index after the closing run, and whether a closing run exists; when none
// does, end is the index after the opening run, which is then literal text.
func codeSpan(text string, start int) (string, int, bool) {
	open := start
	for open < len(text) && text[open] == '`' {
		open++
	}
	width := open - start
	for i := open; i < len(text); {
		if text[i] != '`' {
			i++
			continue
		}
		j := i
		for j < len(text) && text[j] == '`' {
			j++
		}
		if j-i == width {
			return normalizeCode(text[open:i]), j, true
		}
		i = j
	}
	return "", open, false
}

// normalizeCode applies the CommonMark code span rules: line endings become spaces, and one space
// is stripped from each end when both ends have one and the content is not only spaces.
func normalizeCode(content string) string {
	content = strings.ReplaceAll(content, "\n", " ")
	if len(content) >= 2 && content[0] == ' ' && content[len(content)-1] == ' ' && strings.Trim(content, " ") != "" {
		content = content[1 : len(content)-1]
	}
	return content
}
