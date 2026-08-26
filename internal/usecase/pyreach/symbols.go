package pyreach

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const pythonSymbolSubjectLimit = 1_024

// SymbolSubject binds an advisory-provided Python symbol to the exact PyPI component identity from the
// scan SBOM. Tier-1 package subjects and Tier-2 symbol subjects therefore cannot be confused.
func SymbolSubject(purl, symbol string) (string, bool) {
	if _, _, ok := parsePyPURL(purl); !ok || !validAffectedSymbol(symbol) || strings.Contains(purl, "#") {
		return "", false
	}
	subject := purl + "#" + symbol
	return subject, len(subject) <= pythonSymbolSubjectLimit
}

// ParseSymbolSubject is the strict inverse of SymbolSubject.
func ParseSymbolSubject(raw string) (purl, symbol string, ok bool) {
	if len(raw) > pythonSymbolSubjectLimit {
		return "", "", false
	}
	hash := strings.LastIndexByte(raw, '#')
	if hash <= 0 || hash == len(raw)-1 {
		return "", "", false
	}
	purl, symbol = raw[:hash], raw[hash+1:]
	if _, _, ok := parsePyPURL(purl); !ok || !validAffectedSymbol(symbol) {
		return "", "", false
	}
	return purl, symbol, true
}

func parsePyPURL(raw string) (name, version string, ok bool) {
	const prefix = "pkg:pypi/"
	if raw != strings.TrimSpace(raw) || !strings.HasPrefix(strings.ToLower(raw), prefix) {
		return "", "", false
	}
	body := raw[len(prefix):]
	if at := strings.IndexByte(body, '?'); at >= 0 {
		body = body[:at]
	}
	at := strings.LastIndexByte(body, '@')
	if at <= 0 || at == len(body)-1 {
		return "", "", false
	}
	name, version = body[:at], body[at+1:]
	if !validDistributionName(name) || !validPURLVersion(version) {
		return "", "", false
	}
	return name, version, true
}

func validDistributionName(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func validPURLVersion(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '#' || r == '?' {
			return false
		}
	}
	return true
}

func validAffectedSymbol(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	if strings.HasPrefix(value, "python:") {
		module, qualified, ok := splitCanonicalPythonID(value)
		return ok && validPythonDotted(module) && validPythonDotted(qualified)
	}
	if strings.Count(value, ":") > 1 {
		return false
	}
	normalized := strings.Replace(value, ":", ".", 1)
	return validPythonDotted(normalized)
}

func validPythonDotted(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 128 {
		return false
	}
	for _, part := range parts {
		if !validPythonIdentifier(part) {
			return false
		}
	}
	return true
}

func validPythonIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if r == '_' || unicode.IsLetter(r) || i > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

func splitCanonicalPythonID(value string) (module, qualified string, ok bool) {
	if !strings.HasPrefix(value, "python:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(value, "python:")
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 || colon == len(rest)-1 || strings.Contains(rest[colon+1:], ":") {
		return "", "", false
	}
	return rest[:colon], rest[colon+1:], true
}

func normalizeDistribution(value string) string {
	value = strings.ToLower(value)
	var out strings.Builder
	separator := false
	for _, r := range value {
		if r == '-' || r == '_' || r == '.' {
			separator = true
			continue
		}
		if separator && out.Len() > 0 {
			out.WriteByte('-')
		}
		separator = false
		out.WriteRune(r)
	}
	return out.String()
}
