package msgtemplate

import "strings"

// Sanitize removes characters that can reorder, hide or break rendered text: C0 and C1 controls,
// bidirectional controls, zero-width and other invisible characters. Line breaks and tabs become a
// single space, so an interpolated value can never start a new Markdown block. Invalid UTF-8 is
// replaced with U+FFFD.
func Sanitize(value string) string {
	value = strings.ToValidUTF8(value, string(rune(0xfffd)))
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case lineBreak(r):
			b.WriteByte(' ')
		case forbiddenRune(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// lineBreak reports runes that break a line or indent it; Sanitize turns them into a space.
func lineBreak(r rune) bool {
	return r == '\n' || r == '\r' || r == '\t' || r == 0x2028 || r == 0x2029
}

// forbiddenRune reports every rune that is invisible or changes how surrounding text renders. Tab,
// CR and LF are reported too; callers that allow them check for them first.
func forbiddenRune(r rune) bool {
	return controlRune(r) || bidiControl(r) || invisibleRune(r)
}

// controlRune reports C0 controls, DEL and C1 controls.
func controlRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// bidiControl reports the embedding, override and isolate controls and the directional marks.
func bidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
		r == 0x200e || r == 0x200f || r == 0x061c
}

// invisibleRune reports characters that render as nothing and can hide text: zero-width
// characters, the word joiner, the byte order mark, the soft hyphen, the Mongolian vowel separator,
// invisible math operators, interlinear annotation controls and tag characters.
func invisibleRune(r rune) bool {
	return (r >= 0x200b && r <= 0x200d) || r == 0x2060 || r == 0xfeff ||
		r == 0x00ad || r == 0x180e || (r >= 0x2061 && r <= 0x2064) ||
		(r >= 0xfff9 && r <= 0xfffb) || (r >= 0xe0000 && r <= 0xe007f)
}
