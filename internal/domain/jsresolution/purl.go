package jsresolution

import "strings"

// npm package URLs are the join key between a source import, an SBOM component and a reachability
// subject. Because three separate layers compare those strings, the encoding rules live here rather than
// being re-derived in each: a builder and a parser that disagree would not fail loudly, they would return
// zero matches, and "no match" is indistinguishable from "the dependency is unused".

// NPMPURLPrefix is the package-URL type prefix for the npm ecosystem.
const NPMPURLPrefix = "pkg:npm/"

// NPMPURL builds the canonical npm package URL for name@version. A scoped package's leading "@" is
// percent-encoded as %40, while the "/" separating scope from name and the "@" before the version stay
// literal. It is the exact inverse of ParseNPMPURL.
func NPMPURL(name, version string) string {
	encoded := name
	if strings.HasPrefix(encoded, "@") {
		encoded = "%40" + encoded[1:]
	}
	return NPMPURLPrefix + encoded + "@" + version
}

// ParseNPMPURL extracts the package name and version from an npm package URL, returning ok=false for any
// other ecosystem or a malformed identity.
//
// The name is returned with the component's OWN casing rather than normalized: npm hosts distinct
// packages whose names differ only in case (JSONStream and jsonstream are not the same package), so
// folding here would let one package's identity be attached to another's import. The name is still
// VALIDATED through NormalizePackageName so a malformed purl cannot become an identity.
func ParseNPMPURL(raw string) (string, string, bool) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) <= len(NPMPURLPrefix) || !strings.HasPrefix(strings.ToLower(trimmed), NPMPURLPrefix) {
		return "", "", false
	}
	body := trimmed[len(NPMPURLPrefix):]

	// Qualifiers and subpaths are not part of a component's identity.
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	// The version follows the LAST "@": a scoped name's own "@" is percent-encoded, so any literal "@"
	// that remains is the version separator.
	at := strings.LastIndex(body, "@")
	if at <= 0 || at == len(body)-1 {
		return "", "", false
	}
	name, version := purlDecodeName(body[:at]), body[at+1:]
	if name == "" || version == "" {
		return "", "", false
	}
	if _, err := NormalizePackageName(name); err != nil {
		return "", "", false
	}
	return name, version, true
}

// CanonicalNPMPURL rewrites an npm package URL into the canonical encoding, so two spellings of the same
// identity ("pkg:npm/@scope/p@1.0.0" and "pkg:npm/%40scope/p@1.0.0") compare equal. It returns ok=false
// when raw is not a usable npm identity.
//
// Comparing canonical forms is what stops an encoding difference between the SBOM producer and the
// caller from being read as "this package is not imported".
func CanonicalNPMPURL(raw string) (string, bool) {
	name, version, ok := ParseNPMPURL(raw)
	if !ok {
		return "", false
	}
	return NPMPURL(name, version), true
}

// purlDecodeName percent-decodes a package URL name segment. Only well-formed escapes are decoded; an
// unrecognized escape is left intact so the name fails validation rather than silently naming a
// different package.
func purlDecodeName(raw string) string {
	if !strings.Contains(raw, "%") {
		return raw
	}
	var sb strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] == '%' && i+2 < len(raw) {
			hi, hiOK := hexValue(raw[i+1])
			lo, loOK := hexValue(raw[i+2])
			if hiOK && loOK {
				sb.WriteByte(hi<<4 | lo)
				i += 3
				continue
			}
		}
		sb.WriteByte(raw[i])
		i++
	}
	return sb.String()
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// IsRuntimeImport reports whether an import resolution is evidence that a package is loaded at RUNTIME.
//
// A type-only relationship does not survive compilation, so it can never make a package reachable: an
// `import type` clause, an entirely type-only binding list, and any import written in a declaration-only
// module (.d.ts) all describe types rather than a loaded package. A literal dynamic import DOES count,
// because the package is explicitly named in the source.
//
// This lives in the domain because it is a fact about TypeScript rather than a policy of any one
// consumer: a second, divergent copy elsewhere would be a false negative.
func IsRuntimeImport(imp ImportResolution, declarationOnlyModules map[string]bool) bool {
	if imp.TypeOnly || imp.DeclarationOnly {
		return false
	}
	return !declarationOnlyModules[imp.From]
}

// A Tier-2 subject names both a component and one of its exports, because "is this package used" and
// "is this export reached" are different questions with different answers. The fragment form keeps the
// component PURL intact and appends the symbol, so a Tier-1 subject and a Tier-2 subject can never be
// mistaken for one another and neither can be silently reinterpreted as the other.

// NPMSymbolSubject renders the Tier-2 subject for one export of one component.
func NPMSymbolSubject(purl, symbol string) string {
	return purl + "#" + symbol
}

// ParseNPMSymbolSubject splits a Tier-2 subject back into its component PURL and export name.
//
// It is strict: the PURL half must itself be a valid npm component PURL and the symbol half must be
// non-empty and free of the separator. A subject that does not round-trip is REFUSED rather than
// half-interpreted, because a subject whose symbol was misread would be compared against export names it
// can never equal and would come back not-reachable for every package.
func ParseNPMSymbolSubject(raw string) (string, string, bool) {
	hash := strings.LastIndexByte(raw, '#')
	if hash <= 0 || hash == len(raw)-1 {
		return "", "", false
	}
	purl, symbol := raw[:hash], raw[hash+1:]
	if strings.ContainsAny(symbol, "#") || strings.TrimSpace(symbol) != symbol {
		return "", "", false
	}
	if _, _, ok := ParseNPMPURL(purl); !ok {
		return "", "", false
	}
	return purl, symbol, true
}
