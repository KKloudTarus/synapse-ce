// Package textsafety classifies runes that can make untrusted text read as something other than
// what it is. It is the single definition shared by every path that cleans such text: SARIF ingest
// cleans it before storing it, and the message template engine cleans it again before sending it to
// an external channel. Keeping one definition makes the stored copy and the sent copy agree.
package textsafety

// IsControl reports C0 controls, DEL and C1 controls, which carry terminal escapes and introducers.
// Tab, CR and LF are included; callers that allow them check for them first.
func IsControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// IsBidiControl reports the directional embeddings, overrides and isolates and the directional
// marks. They can make a stored path or a title read as a different one.
func IsBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
		r == 0x200e || r == 0x200f || r == 0x061c
}

// IsInvisibleSeparator reports the zero-width space and the byte order mark, which split a word
// without showing anything.
//
// Zero-width JOINER and NON-JOINER (U+200C, U+200D) are deliberately not reported: Persian,
// Devanagari and emoji sequences need them to render correctly, and removing them would silently
// change legitimate non-ASCII text.
func IsInvisibleSeparator(r rune) bool {
	return r == 0x200b || r == 0xfeff
}
