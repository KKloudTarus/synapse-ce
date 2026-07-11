package ownadvisory

import "strings"

// cpeToEcosystem bridges a CPE 2.3 product identifier to the OSV (ecosystem, package) key the owned matcher
// uses. CSAF and NVD identify products by CPE – a vendor/product/version tuple plus a
// `target_sw` platform – NOT by the PURL ecosystem+package the SBOM side keys on. There is no general,
// lossless CPE↔PURL mapping, so this is a deliberately CONSERVATIVE best-effort bridge:
//
// it maps ONLY when the CPE part is "a" (application) AND `target_sw` names a language ecosystem the
// owned matcher has a version comparator for; anything else returns ok=false and the caller skips+logs
// it (a wrong ecosystem key would silently mis-attribute a CVE – far worse than a miss);
// the package name is the CPE product (canonicalized). The allow-list (targetSWEcosystem) is restricted
// to ecosystems where the CPE product IS the package key, so the name is faithful; ecosystems whose key
// is NOT the CPE product (Maven groupId:artifactId, Go module path) are excluded there rather than
// mapped to a name that could never match. Where a name is nonetheless imperfect it FAILS to match – the
// exact (ecosystem, package) key in advisory.Match means it never matches the WRONG package.
//
// Net: this yields true matches for the common language-ecosystem case and fails closed everywhere else,
// rather than fabricating ecosystem keys. The matching value therefore depends on the SBOM carrying
// CPE-derivable components; this is the documented limitation of CPE-keyed advisory feeds.
//
// It also returns the CPE's version component (unescaped, verbatim – "*"=ANY, "-"=NA, else a concrete
// version) so the caller can map a CSAF/NVD product binding onto an explicit affected version.
func cpeToEcosystem(cpe string) (ecosystem, pkg, version string, ok bool) {
	c, parsed := parseCPE23(cpe)
	if !parsed || c.part != "a" {
		return "", "", "", false
	}
	eco, mapped := targetSWEcosystem[strings.ToLower(c.targetSW)]
	if !mapped {
		return "", "", "", false
	}
	product := unescapeCPE(c.product)
	if product == "" || product == "*" || product == "-" {
		return "", "", "", false
	}
	return eco, canonicalName(eco, product), unescapeCPE(c.version), true
}

// targetSWEcosystem maps a CPE 2.3 `target_sw` value to the OSV ecosystem. It is intentionally limited to
// ecosystems where BOTH hold: (1) the owned matcher has a version comparator (advisory.schemeFor – so an
// "all versions" open range can actually match), AND (2) the CPE product IS the package key (a simple
// lowercase name equal to the OSV/SBOM key after canonicalName). Others are DELIBERATELY EXCLUDED because a
// mapping there would be inert or mis-keyed – better to skip+log than fabricate a key:
// Maven (key is groupId:artifactId) and Go (key is the module path): the CPE product can never equal
// the stored key, so it would never match – and for Go, comparator-backed open ranges could even
// amplify a coincidental mis-key (security review HIGH);
// RubyGems / NuGet: no ECOSYSTEM-range comparator yet (open ranges would be silently inert), and NuGet's
// PascalCase id does not fold to a lowercase CPE product.
//
// Add an ecosystem here only once both conditions hold. An unlisted / ANY("*") / NA("-") target_sw is ok=false.
var targetSWEcosystem = map[string]string{
	"python":  "PyPI",
	"node.js": "npm",
	"nodejs":  "npm",
	"node":    "npm",
	"rust":    "crates.io",
	"cargo":   "crates.io",
}

// cpe23 is the subset of a CPE 2.3 formatted-string binding the bridge reads.
type cpe23 struct {
	part     string // a (application) | o (os) | h (hardware)
	vendor   string
	product  string
	version  string
	targetSW string
}

// parseCPE23 parses a CPE 2.3 formatted-string binding:
//
//	cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//
// (13 colon-separated components, ':' escaped as "\:" inside a component). It fails closed (ok=false) on
// anything that is not a well-formed cpe:2.3 string with exactly 13 components.
func parseCPE23(s string) (cpe23, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "cpe:2.3:") {
		return cpe23{}, false
	}
	parts := splitCPE(s)
	if len(parts) != 13 {
		return cpe23{}, false
	}
	return cpe23{
		part:     parts[2],
		vendor:   parts[3],
		product:  parts[4],
		version:  parts[5],
		targetSW: parts[10], // index: 0 cpe,1 2.3,2 part,3 vendor,4 product,5 version,...,10 target_sw
	}, true
}

// splitCPE splits a CPE 2.3 formatted string on UNESCAPED colons (a backslash escapes the next rune, so
// "\:" stays within a component). The escapes are preserved in each component; unescapeCPE removes them.
func splitCPE(s string) []string {
	var out []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune('\\')
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if escaped { // a trailing lone backslash – keep it rather than drop a rune
		b.WriteRune('\\')
	}
	out = append(out, b.String())
	return out
}

// unescapeCPE removes CPE 2.3 backslash escapes from a component ("django\-rest" → "django-rest").
func unescapeCPE(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
