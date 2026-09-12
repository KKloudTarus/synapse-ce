// Package ownership models explainable team routing without granting access to findings.
package ownership

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	ParserVersion  = "github-codeowners-v1"
	MaxSourceBytes = 3_000_000
	MaxPatterns    = 20_000
	MaxOwners      = 100
	MaxPathBytes   = 4096
	MaxPaths       = 128
	MaxMatchWork   = 20_000_000 // bounded input bytes times compiled patterns
)

type Diagnostic struct {
	Line int    `json:"line"`
	Code string `json:"code"`
}

type Pattern struct {
	Line   int      `json:"line"`
	Text   string   `json:"pattern"`
	Owners []string `json:"owners"`
	match  *regexp.Regexp
}

type Codeowners struct {
	Patterns    []Pattern    `json:"patterns"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// SelectFile implements GitHub's first-existing-file rule, including an empty file.
// Capture adapters must independently enforce file and symlink safety.
func SelectFile(files map[string]string) (string, string, bool) {
	for _, name := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
		if content, ok := files[name]; ok {
			return name, content, true
		}
	}
	return "", "", false
}

func ContentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// PinnedRevision excludes moving branch names. Acquisition adapters supply a
// resolved Git object ID or the digest of the exact imported archive.
func PinnedRevision(value string) bool {
	kind, digest, ok := strings.Cut(value, ":")
	if !ok || kind != "git" && kind != "sha256" || kind == "git" && len(digest) != 40 && len(digest) != 64 || kind == "sha256" && len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil && digest == strings.ToLower(digest)
}

func ValidOwner(token string) bool {
	if len(token) == 0 || len(token) > 320 || strings.ContainsAny(token, "\x00\r\n\t #") {
		return false
	}
	if strings.HasPrefix(token, "@") {
		parts := strings.Split(token[1:], "/")
		if len(parts) > 2 {
			return false
		}
		for _, part := range parts {
			if part == "" {
				return false
			}
			for _, r := range part {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
					return false
				}
			}
		}
		return true
	}
	address, err := mail.ParseAddress(token)
	return err == nil && address.Address == token && address.Name == ""
}

// NormalizePath accepts repository-relative scanner paths, never an OS filename.
// Traversal is rejected rather than cleaned, including Windows drive/UNC paths.
func NormalizePath(value string) (string, error) {
	if value == "" || len(value) > MaxPathBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n:") {
		return "", fmt.Errorf("%w: invalid ownership path", shared.ErrValidation)
	}
	value = strings.ReplaceAll(value, "\\", "/")
	if strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("%w: absolute ownership path", shared.ErrValidation)
	}
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("%w: non-canonical ownership path", shared.ErrValidation)
		}
	}
	return value, nil
}

// ParseCodeowners skips invalid lines with stable diagnostics. Resource-limit
// violations reject the whole document: a truncated document could change owners.
func ParseCodeowners(content string) (Codeowners, error) {
	out := Codeowners{Patterns: []Pattern{}, Diagnostics: []Diagnostic{}}
	if len(content) > MaxSourceBytes || !utf8.ValidString(content) || strings.ContainsRune(content, '\x00') {
		return out, fmt.Errorf("%w: invalid CODEOWNERS document", shared.ErrValidation)
	}
	for index, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(out.Patterns)+len(out.Diagnostics) >= MaxPatterns {
			return out, fmt.Errorf("%w: too many CODEOWNERS entries", shared.ErrValidation)
		}
		fields, err := ownerFields(line)
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, Diagnostic{index + 1, "invalid_escape"})
			continue
		}
		if len(fields) == 0 {
			continue
		}
		matcher, err := compilePattern(fields[0])
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, Diagnostic{index + 1, "unsupported_pattern"})
			continue
		}
		if len(fields)-1 > MaxOwners {
			return out, fmt.Errorf("%w: too many CODEOWNERS owners", shared.ErrValidation)
		}
		valid := true
		for _, token := range fields[1:] {
			if !ValidOwner(token) {
				valid = false
				break
			}
		}
		if !valid {
			out.Diagnostics = append(out.Diagnostics, Diagnostic{index + 1, "invalid_owner"})
			continue
		}
		out.Patterns = append(out.Patterns, Pattern{Line: index + 1, Text: fields[0], Owners: append([]string{}, fields[1:]...), match: matcher})
		if len(out.Patterns) > MaxPatterns {
			return out, fmt.Errorf("%w: too many CODEOWNERS patterns", shared.ErrValidation)
		}
	}
	return out, nil
}

// ownerFields preserves escaped spaces within a pattern, but deliberately rejects
// escaped leading '#', negation, and character classes (not CODEOWNERS syntax).
func ownerFields(line string) ([]string, error) {
	var fields []string
	var token strings.Builder
	escaped := false
	for _, r := range line {
		if escaped {
			if r != ' ' {
				return nil, fmt.Errorf("unsupported escape")
			}
			token.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '#' {
			break
		}
		if unicode.IsSpace(r) {
			if token.Len() > 0 {
				fields = append(fields, token.String())
				token.Reset()
			}
		} else {
			token.WriteRune(r)
		}
	}
	if escaped {
		return nil, fmt.Errorf("unterminated escape")
	}
	if token.Len() > 0 {
		fields = append(fields, token.String())
	}
	return fields, nil
}

func compilePattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" || len(pattern) > MaxPathBytes || strings.HasPrefix(pattern, "!") || strings.ContainsAny(pattern, "[]\\\x00\r\n") {
		return nil, fmt.Errorf("%w: unsupported ownership pattern", shared.ErrValidation)
	}
	anchored := strings.HasPrefix(pattern, "/")
	pattern = strings.TrimPrefix(pattern, "/")
	directory := strings.HasSuffix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return nil, fmt.Errorf("%w: empty pattern", shared.ErrValidation)
	}
	parts := strings.Split(pattern, "/")
	var expression strings.Builder
	if anchored || len(parts) > 1 {
		expression.WriteString("^")
	} else {
		expression.WriteString("(?:^|/)")
	}
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("%w: invalid pattern segment", shared.ErrValidation)
		}
		if part == "**" {
			if index < len(parts)-1 {
				expression.WriteString("(?:[^/]+/)*")
			} else {
				expression.WriteString(".*")
			}
			continue
		}
		for _, r := range part {
			switch r {
			case '*':
				expression.WriteString("[^/]*")
			case '?':
				expression.WriteString("[^/]")
			default:
				expression.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		if index < len(parts)-1 {
			expression.WriteString("/")
		}
	}
	if directory {
		expression.WriteString("/.+$")
	} else if strings.ContainsAny(parts[len(parts)-1], "*?") {
		expression.WriteString("$")
	} else {
		expression.WriteString("(?:/.*)?$")
	}
	return regexp.Compile(expression.String())
}

func (c Codeowners) Match(path string) (Pattern, bool) {
	for i := len(c.Patterns) - 1; i >= 0; i-- {
		p := c.Patterns[i]
		if p.match != nil && p.match.MatchString(path) {
			p.Owners = append([]string{}, p.Owners...)
			return p, true
		}
	}
	return Pattern{}, false
}
