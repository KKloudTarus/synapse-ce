package msgtemplate

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/textsafety"
)

// Sanitize removes characters that can reorder, hide or break rendered text. Line breaks and tabs
// become a single space, so an interpolated value can never start a new Markdown block. Invalid
// UTF-8 is replaced with U+FFFD.
//
// The control, bidirectional and invisible-separator classes come from package textsafety, the
// definition SARIF ingest also uses, so a stored title and the same title in a message agree. In
// particular the zero-width joiner and non-joiner are kept, because Persian, Devanagari and emoji
// sequences need them.
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
	return textsafety.IsControl(r) || textsafety.IsBidiControl(r) ||
		textsafety.IsInvisibleSeparator(r) || hiddenInMessage(r)
}

// hiddenInMessage reports characters that render as nothing and can hide text in a message sent to
// an external channel: the word joiner, invisible math operators, the soft hyphen, the Mongolian
// vowel separator, interlinear annotation controls and tag characters. Tag characters are the
// carrier of "ASCII smuggling"; the cost of removing them is that a subdivision flag such as
// Scotland's shows as a plain black flag.
//
// These go further than textsafety because a stored value is shown in the console, where the
// reader can inspect it, while a message is read in a client Synapse does not control.
func hiddenInMessage(r rune) bool {
	return r == 0x2060 || (r >= 0x2061 && r <= 0x2064) || r == 0x00ad || r == 0x180e ||
		(r >= 0xfff9 && r <= 0xfffb) || (r >= 0xe0000 && r <= 0xe007f)
}
