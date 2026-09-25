// Package gobinsubject encodes a version-bound Go affected-symbol query for binary reachability.
package gobinsubject

import (
	"go/token"
	"strings"
)

const maxSubjectLength = 4096

// PURL is the canonical Go module identity carried by a binary-reachability query.
type PURL struct {
	Raw     string
	Module  string
	Version string
}

// ParsePURL accepts only a canonical, versioned Go package URL. Qualifiers, fragments, escapes, and
// whitespace are rejected so the encoded form has exactly one identity.
func ParsePURL(raw string) (PURL, bool) {
	const prefix = "pkg:golang/"
	if len(raw) == 0 || len(raw) > maxSubjectLength || !strings.HasPrefix(raw, prefix) || strings.ContainsAny(raw, " \t\r\n?#%") {
		return PURL{}, false
	}
	body := strings.TrimPrefix(raw, prefix)
	at := strings.LastIndexByte(body, '@')
	if at <= 0 || at == len(body)-1 {
		return PURL{}, false
	}
	module, version := body[:at], body[at+1:]
	if !validModule(module) || !validVersion(version) {
		return PURL{}, false
	}
	return PURL{Raw: raw, Module: module, Version: version}, true
}

// Encode binds a full Go symbol to its exact canonical module PURL. A symbol must identify a member of the
// stated module; otherwise a matching function name in an unrelated binary package could raise a finding.
func Encode(purl, symbol string) (string, bool) {
	parsed, ok := ParsePURL(purl)
	if !ok || !OwnsSymbol(parsed.Module, symbol) {
		return "", false
	}
	query := purl + "#" + symbol
	if len(query) > maxSubjectLength {
		return "", false
	}
	return query, true
}

// Parse verifies an encoded query and returns its identity and full symbol.
func Parse(query string) (PURL, string, bool) {
	if len(query) == 0 || len(query) > maxSubjectLength || strings.Count(query, "#") != 1 {
		return PURL{}, "", false
	}
	purl, symbol, _ := strings.Cut(query, "#")
	parsed, ok := ParsePURL(purl)
	if !ok || !OwnsSymbol(parsed.Module, symbol) {
		return PURL{}, "", false
	}
	return parsed, symbol, true
}

func validModule(module string) bool {
	if module == "" || strings.HasPrefix(module, "/") || strings.HasSuffix(module, "/") || strings.Contains(module, "//") {
		return false
	}
	for _, part := range strings.Split(module, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(".-_~+", r)) {
				return false
			}
		}
	}
	return true
}

func validVersion(version string) bool {
	for _, r := range version {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(".-_+", r)) {
			return false
		}
	}
	return true
}

// OwnsSymbol accepts a subpackage member or an unambiguous free function in the module root.
func OwnsSymbol(module, symbol string) bool {
	if symbol == "" || strings.ContainsAny(symbol, " \t\r\n#[]") || module == "stdlib" {
		return false
	}
	if strings.HasPrefix(symbol, module+"/") {
		return true
	}
	name, ok := strings.CutPrefix(symbol, module+".")
	return ok && token.IsIdentifier(name)
}
