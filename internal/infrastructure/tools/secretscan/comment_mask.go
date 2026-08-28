package secretscan

import (
	"path/filepath"
	"strings"
)

// maskComments blanks comment regions of a source file BEFORE the secret rules run, so a secret that
// lives only in a comment (a commented-out config line, an example key in a doc block, dead code) does
// not surface as a live finding. Like maskVBComments it preserves every byte offset and newline — it
// overwrites comment bytes with spaces — so reported line numbers and match offsets stay exact.
//
// It is deliberately CONSERVATIVE to avoid false NEGATIVES (masking a real secret in live code): a
// marker inside a string literal is never treated as a comment, and a `#` is only a comment when it
// starts a line or follows whitespace (the YAML/shell/Python/Ruby/TOML rule — so `url#frag` or
// `a#b` is left intact and still scanned).
func maskComments(rel string, data []byte) []byte {
	switch {
	case strings.EqualFold(filepath.Ext(rel), ".vb"):
		return maskVBComments(data)
	case hashCommentFile(rel):
		return maskLineComments(data, "#", true)
	case slashCommentFile(rel):
		return maskBlockComments(maskLineComments(data, "//", false))
	}
	return data
}

// hashCommentExts are file types whose line comments start with '#'.
var hashCommentExts = map[string]bool{
	".yaml": true, ".yml": true, ".sh": true, ".bash": true, ".zsh": true, ".ksh": true,
	".py": true, ".rb": true, ".toml": true, ".tf": true, ".tfvars": true, ".ini": true,
	".cfg": true, ".conf": true, ".env": true, ".pl": true, ".pm": true, ".r": true,
	".ps1": true, ".psm1": true, ".mk": true,
}

// hashCommentBases are extension-less files whose line comments start with '#'.
var hashCommentBases = map[string]bool{
	"dockerfile": true, "makefile": true, ".gitlab-ci.yml": true, ".env": true,
}

// slashCommentExts are file types with '//' line comments and '/* */' block comments.
var slashCommentExts = map[string]bool{
	".go": true, ".c": true, ".h": true, ".cpp": true, ".cc": true, ".cxx": true, ".hpp": true,
	".java": true, ".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true,
	".cs": true, ".kt": true, ".kts": true, ".rs": true, ".scala": true, ".swift": true, ".php": true,
	".css": true, ".scss": true, ".less": true, ".dart": true, ".proto": true,
}

func hashCommentFile(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	if hashCommentBases[base] || strings.HasPrefix(base, "dockerfile") {
		return true
	}
	return hashCommentExts[strings.ToLower(filepath.Ext(rel))]
}

func slashCommentFile(rel string) bool {
	return slashCommentExts[strings.ToLower(filepath.Ext(rel))]
}

// maskLineComments blanks each line from an unquoted comment marker to end-of-line, preserving offsets.
// A marker inside a "…", '…' or `…` string is ignored (its opening quote is tracked, with backslash
// escapes). When requireBoundary is set (the '#' family), the marker only starts a comment at line start
// or after whitespace, matching those languages' rules so `key=val#frag` is not mistaken for a comment.
// Quote state resets at each newline (single-line string semantics), which errs toward NOT masking.
func maskLineComments(data []byte, marker string, requireBoundary bool) []byte {
	out := append([]byte(nil), data...)
	m0 := marker[0]
	twoChar := len(marker) > 1
	for start := 0; start < len(out); {
		end := start
		for end < len(out) && out[end] != '\n' {
			end++
		}
		var quote byte // 0 = outside any string literal
		atBoundary := true
		for i := start; i < end; i++ {
			c := out[i]
			if quote != 0 {
				if c == '\\' && i+1 < end {
					i++
					continue
				}
				if c == quote {
					quote = 0
				}
				atBoundary = false
				continue
			}
			if c == '"' || c == '\'' || c == '`' {
				quote = c
				atBoundary = false
				continue
			}
			if c == m0 && (!twoChar || (i+1 < end && out[i+1] == marker[1])) && (!requireBoundary || atBoundary) {
				for j := i; j < end; j++ {
					out[j] = ' '
				}
				break
			}
			atBoundary = c == ' ' || c == '\t'
		}
		start = end + 1
	}
	return out
}

// maskBlockComments blanks C-style /* … */ block comments (which may span lines), preserving newlines and
// byte offsets. A /* opening inside a string literal is ignored. Quote state resets at newline so an
// unterminated single-line string cannot hide a block comment on a later line.
func maskBlockComments(data []byte) []byte {
	out := append([]byte(nil), data...)
	var quote byte
	for i := 0; i < len(out); i++ {
		c := out[i]
		if c == '\n' {
			quote = 0
			continue
		}
		if quote != 0 {
			if c == '\\' && i+1 < len(out) && out[i+1] != '\n' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			quote = c
			continue
		}
		if c == '/' && i+1 < len(out) && out[i+1] == '*' {
			j := i + 2
			for j+1 < len(out) && !(out[j] == '*' && out[j+1] == '/') {
				j++
			}
			blankEnd := j + 2
			if blankEnd > len(out) {
				blankEnd = len(out)
			}
			for k := i; k < blankEnd; k++ {
				if out[k] != '\n' {
					out[k] = ' '
				}
			}
			i = blankEnd - 1
		}
	}
	return out
}
