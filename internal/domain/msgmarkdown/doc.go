// Package msgmarkdown parses the message Markdown subset that internal/domain/msgtemplate renders
// into a small syntax tree, so every channel formatter works from the same structure instead of
// re-parsing text with its own rules (EPIC #1327 D5).
//
// # The subset
//
// Blocks are paragraphs and single-level bullet lists. A bullet item is a line that starts with up
// to three spaces, then "-", "*" or "+", then a space (or nothing). A blank line ends a paragraph
// or a list; any other line that is not an item ends a list and starts a paragraph. A line break
// inside a paragraph is kept as a LineBreak, because a message author who writes two lines means
// two lines.
//
// Inlines are strong and emphasis (with "*" or "_", following the CommonMark delimiter-run rules),
// code spans, and backslash escapes of ASCII punctuation, which msgtemplate uses to make every
// interpolated value literal.
//
// Everything else CommonMark defines is plain text on purpose: headings, block quotes, fences,
// thematic breaks, tables, HTML, entity references, autolinks, and inline links and images. In
// particular, "[label](url)" never becomes a link. A link in a message is a typed Link, built
// server-side from the configured base URL and passed next to the content, never parsed out of it.
//
// The package performs no I/O and imports only the standard library.
package msgmarkdown
