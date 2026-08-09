package sarifingest

import (
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
)

// This file holds the two security-critical transformations applied to untrusted tool output: turning a
// SARIF artifact URI into a repository-relative path, and making tool text safe to STORE. They are kept
// apart from the JSON walk because they are what a reviewer needs to read closely.

// Per-field bounds. Text from an external tool is stored, so it is capped and stripped of control
// characters HERE rather than trusted to every future renderer to handle safely.
const (
	maxTitleBytes      = 4 << 10
	maxMessageBytes    = 4 << 10
	maxIdentifierBytes = 512
	maxPathBytes       = 4096
	// maxVersionEcho bounds how much of an attacker-controlled version string is reflected in an error.
	maxVersionEcho = 32
)

// normalizeArtifactURI converts a SARIF artifact URI into a repository-relative path, or returns the
// refusal code that explains why it cannot be used.
//
// SARIF requires `artifactLocation.uri` to be a URI reference, i.e. percent-ENCODED. The value is
// therefore decoded BEFORE the traversal and absolute-path checks — checking the encoded form would let
// `%2e%2e%2f` walk straight past every guard — and a value that still carries an escape after one decode
// is refused, so double encoding cannot survive to a consumer that decodes again.
//
// Note the consequence for `file:` URIs: an authority is refused, and an empty authority leaves an
// absolute path, so a tool that emits `file:///abs/path` has every result refused rather than
// reinterpreted. That is a large behavioural cliff, but it is a DISCLOSED one — each result appears in
// the refusal list with its own code — and the alternative is guessing which prefix of an absolute path
// corresponds to the scanned tree.
func normalizeArtifactURI(uri string) (string, importedfinding.RefusalCode) {
	if strings.IndexByte(uri, 0) >= 0 || len(uri) > maxPathBytes {
		return "", importedfinding.RefusalInvalidLocation
	}

	rest := uri
	if i := strings.Index(rest, "://"); i >= 0 {
		if !strings.EqualFold(rest[:i], "file") {
			return "", importedfinding.RefusalUnsupportedURI
		}
		parsedURI, err := url.Parse(rest)
		if err != nil {
			return "", importedfinding.RefusalInvalidLocation
		}
		// A file URI with a remote authority is not a local directory: file://evil.example/etc/passwd
		// must never be reinterpreted as the relative path "evil.example/etc/passwd".
		if host := parsedURI.Host; host != "" && !strings.EqualFold(host, "localhost") {
			return "", importedfinding.RefusalUnsupportedURI
		}
		rest = parsedURI.EscapedPath()
		if strings.HasPrefix(rest, "/") {
			return "", importedfinding.RefusalAbsolutePath
		}
	} else if code := refuseBareScheme(rest); code != "" {
		return "", code
	}

	decoded, err := url.PathUnescape(rest)
	if err != nil {
		return "", importedfinding.RefusalInvalidLocation
	}
	if containsPercentEscape(decoded) {
		return "", importedfinding.RefusalInvalidLocation
	}
	if strings.IndexByte(decoded, 0) >= 0 || !utf8.ValidString(decoded) || containsControlOrBidi(decoded) {
		return "", importedfinding.RefusalInvalidLocation
	}
	// Decoding can reveal a scheme or a Windows volume the encoded form hid.
	if code := refuseBareScheme(decoded); code != "" {
		return "", code
	}

	cleaned := strings.ReplaceAll(decoded, "\\", "/")
	if strings.HasPrefix(cleaned, "/") {
		return "", importedfinding.RefusalAbsolutePath
	}
	cleaned = path.Clean(cleaned)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", importedfinding.RefusalPathTraversal
	}
	if cleaned == "." || cleaned == "" {
		return "", importedfinding.RefusalInvalidLocation
	}
	return strings.TrimPrefix(cleaned, "./"), ""
}

// refuseBareScheme rejects anything that is not a plain relative path: a bare scheme such as "mailto:x"
// or a Windows volume such as "C:\...".
//
// There is deliberately NO exemption for a leading "./". An ordinary relative path contains no colon and
// is already accepted by the first test, so an exemption would buy nothing while letting
// `./https%3A%2F%2Fevil.example%2Fx` and `./C%3A%5CWindows` through as "repository-relative" paths.
func refuseBareScheme(p string) importedfinding.RefusalCode {
	if !strings.Contains(p, ":") {
		return ""
	}
	if looksLikeWindowsVolume(p) {
		return importedfinding.RefusalAbsolutePath
	}
	return importedfinding.RefusalUnsupportedURI
}

func looksLikeWindowsVolume(p string) bool {
	return len(p) >= 2 && p[1] == ':' &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

func containsPercentEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			return true
		}
	}
	return false
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// repositoryRootBase reports whether a uriBaseId denotes the root of the scanned tree. Anything else is
// refused rather than assumed.
func repositoryRootBase(base string) bool {
	switch strings.ToUpper(strings.Trim(strings.TrimSpace(base), "%")) {
	case "", "SRCROOT", "PROJECTROOT", "REPOROOT", "WORKSPACEROOT", "ROOTPATH":
		return true
	}
	return false
}

// sanitizeText makes untrusted tool text safe to STORE, not merely safe to render.
//
// The report path is templated from stored data and the UI, the CSV export and the CLI all read the same
// row, so normalizing once at ingest is the only place the guarantee holds for every consumer. Control
// characters (which carry terminal escapes), C1 introducers and bidi overrides (which can make a stored
// path read as a different path) are dropped; the result is capped, and the caller records a truncation
// as a coverage issue rather than presenting a shortened value as the tool's own words.
//
// Zero-width JOINER and NON-JOINER (U+200C/U+200D) are deliberately KEPT: they are required for correct
// Persian, Devanagari and emoji-sequence rendering, and dropping them would silently alter legitimate
// non-ASCII text without disclosing the change. Only the directional overrides — which can make a stored
// path read as a different path — and the zero-width space/BOM are removed.
func sanitizeText(in string, limit int, allowNewlines bool) (string, bool) {
	trimmed := strings.TrimSpace(in)
	if trimmed == "" {
		return "", false
	}
	var b strings.Builder
	b.Grow(min(len(trimmed), limit))
	truncated := false
	for _, r := range trimmed {
		if b.Len()+utf8.RuneLen(r) > limit {
			truncated = true
			break
		}
		switch {
		case r == '\t':
			b.WriteRune(r)
		case r == '\r':
			// Dropped: paired with \n it would double the line break, alone it is a cursor control.
		case r == '\n':
			if allowNewlines {
				b.WriteRune('\n')
			} else {
				b.WriteRune(' ')
			}
		case r < 0x20 || r == 0x7f:
		case r >= 0x80 && r <= 0x9f:
		case isBidiOrZeroWidth(r):
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String()), truncated
}

func containsControlOrBidi(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiOrZeroWidth(r) {
			return true
		}
	}
	return false
}

// isBidiOrZeroWidth reports whether r can make stored text read as something other than what it is.
// U+200C and U+200D are excluded on purpose — see sanitizeText.
func isBidiOrZeroWidth(r rune) bool {
	switch r {
	case 0x061C, 0x200B, 0x200E, 0x200F, 0xFEFF:
		return true
	}
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}
