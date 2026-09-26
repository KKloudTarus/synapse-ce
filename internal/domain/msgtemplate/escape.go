package msgtemplate

import "strings"

// inlineSpecial lists the characters the Markdown subset (and the chat syntaxes built on it) treat
// as markup anywhere in a line.
const inlineSpecial = "\\*_`[]<>~|"

// blockSpecial lists the characters that start a block (bullet, heading, quote) at the beginning of
// a line.
const blockSpecial = "-+#"

// EscapeMarkdown backslash-escapes a value so that the Markdown subset treats it as literal text.
// The value must already be sanitized, so it holds no line break and can only begin a line at its
// first character. Formatters that consume the subset unescape a backslash followed by any ASCII
// punctuation.
func EscapeMarkdown(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 8)
	rest := escapeBlockStart(&b, value)
	for i := 0; i < len(rest); i++ {
		if strings.IndexByte(inlineSpecial, rest[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(rest[i])
	}
	return b.String()
}

// escapeBlockStart writes the leading spaces and escapes a block marker that would start a bullet,
// a heading or an ordered list if the value began a line. It returns the rest of the value.
// Escaping only at the start keeps values such as CVE-2024-1 readable.
func escapeBlockStart(b *strings.Builder, value string) string {
	start := len(value) - len(strings.TrimLeft(value, " "))
	b.WriteString(value[:start])
	rest := value[start:]
	if rest != "" && strings.IndexByte(blockSpecial, rest[0]) >= 0 {
		b.WriteByte('\\')
		b.WriteByte(rest[0])
		return rest[1:]
	}
	digits := len(rest) - len(strings.TrimLeft(rest, "0123456789"))
	if digits > 0 && digits < len(rest) && (rest[digits] == '.' || rest[digits] == ')') {
		b.WriteString(rest[:digits])
		b.WriteByte('\\')
		b.WriteByte(rest[digits])
		return rest[digits+1:]
	}
	return rest
}
