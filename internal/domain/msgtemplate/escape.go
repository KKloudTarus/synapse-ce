package msgtemplate

import "strings"

// asciiPunctuation is every character CommonMark allows a backslash to escape. Every piece of
// CommonMark and GFM syntax is built from these characters: emphasis, code spans, links, images,
// autolinks, entity references, HTML, headings (ATX and setext), thematic breaks, block quotes, list
// markers, fences, tables and strikethrough. Escaping all of them, rather than a hand-picked subset,
// leaves nothing to forget; the bare URL, www and email autolinks of GFM stop matching because their
// ":", "." and "@" are escaped.
const asciiPunctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// EscapeMarkdown makes a value literal text in the message Markdown subset.
//
// The subset is an intermediate CommonMark representation, not a chat syntax: the per-channel
// formatters parse it, honouring backslash escapes, and emit each channel's own escaping (for
// example &lt; &gt; &amp; for Slack mrkdwn). The escaping is correct in text, emphasis and list
// context. It is not correct inside a code span, where CommonMark shows backslashes literally, so
// the validator rejects an action written between backticks.
//
// The value must already be sanitized, so it holds no line break. Leading spaces are dropped: four
// of them would start an indented code block, and they carry no meaning in an inline value.
func EscapeMarkdown(value string) string {
	value = strings.TrimLeft(value, " ")
	var b strings.Builder
	b.Grow(len(value) + len(value)/4)
	for i := 0; i < len(value); i++ {
		if strings.IndexByte(asciiPunctuation, value[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(value[i])
	}
	return b.String()
}
