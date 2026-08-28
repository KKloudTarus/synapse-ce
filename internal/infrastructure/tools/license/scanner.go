// Package license adapts license classification + policy to the LicenseScanner
// port. It classifies SPDX ids/expressions into categories and evaluates them
// against a configurable policy (default M1). Pure Go, no external tool.
package license

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Policy maps a license category to a verdict.
type Policy map[sbom.LicenseCategory]ports.LicenseVerdict

// DefaultPolicy is the M1 default: allow permissive, warn weak-copyleft + unknown,
// deny strong-copyleft + proprietary.
func DefaultPolicy() Policy {
	return Policy{
		sbom.LicensePermissive:   ports.LicenseAllow,
		sbom.LicenseWeakCopyleft: ports.LicenseWarn,
		sbom.LicenseCopyleft:     ports.LicenseDeny,
		sbom.LicenseProprietary:  ports.LicenseDeny,
		sbom.LicenseUnknown:      ports.LicenseWarn,
	}
}

func (p Policy) verdict(c sbom.LicenseCategory) ports.LicenseVerdict {
	if v, ok := p[c]; ok {
		return v
	}
	return ports.LicenseWarn
}

// Scanner classifies component licenses and applies a policy.
type Scanner struct{ policy Policy }

// New returns a scanner with the default M1 policy.
func New() *Scanner { return &Scanner{policy: DefaultPolicy()} }

// NewWithPolicy returns a scanner with a custom policy.
func NewWithPolicy(p Policy) *Scanner { return &Scanner{policy: p} }

var _ ports.LicenseScanner = (*Scanner)(nil)

// Scan groups each distinct license across components, classifies it, and applies
// the policy — yielding a license report with the components per license.
func (s *Scanner) Scan(_ context.Context, doc *sbom.SBOM) ([]ports.LicenseFinding, error) {
	if doc == nil {
		return nil, nil
	}
	type agg struct {
		category sbom.LicenseCategory
		comps    map[string]bool
	}
	byLicense := map[string]*agg{}
	var order []string
	for ci := range doc.Components {
		entries := normalizeComponentLicenses(doc.Components[ci].Licenses)
		doc.Components[ci].Licenses = entries
		for _, l := range entries {
			key := licenseKey(l)
			if key == "" {
				continue
			}
			category := classify(key)
			a, ok := byLicense[key]
			if !ok {
				a = &agg{category: category, comps: map[string]bool{}}
				byLicense[key] = a
				order = append(order, key)
			}
			if doc.Components[ci].Name != "" {
				a.comps[doc.Components[ci].Name] = true
			}
		}
	}
	out := make([]ports.LicenseFinding, 0, len(order))
	for _, key := range order {
		a := byLicense[key]
		comps := make([]string, 0, len(a.comps))
		for name := range a.comps {
			comps = append(comps, name)
		}
		sort.Strings(comps)
		risk, severity := RiskOf(key)
		options, recommendedChoice, policyRuleID, selectionReason := licensePolicy(key)
		out = append(out, ports.LicenseFinding{
			License:           key,
			Category:          a.category,
			Verdict:           s.policy.verdict(a.category),
			RiskCategory:      string(risk),
			Severity:          severity,
			Components:        comps,
			PolicyRuleID:      policyRuleID,
			RecommendedChoice: recommendedChoice,
			SelectionReason:   selectionReason,
			Options:           options,
		})
	}
	return out, nil
}

func licenseKey(l sbom.License) string {
	if strings.TrimSpace(l.SPDXID) != "" {
		return strings.TrimSpace(l.SPDXID)
	}
	return strings.TrimSpace(l.Name)
}

func normalizeComponentLicenses(in []sbom.License) []sbom.License {
	if len(in) == 0 {
		return nil
	}
	type entry struct {
		lic      sbom.License
		category sbom.LicenseCategory
	}
	entries := make([]entry, 0, len(in))
	hasResolved := false
	seen := map[string]bool{}
	for _, l := range in {
		raw := licenseKey(l)
		if raw == "" {
			continue
		}
		// A bare list of licenses (no SPDX operator) — e.g. a Maven <licenses> block — means
		// the recipient MAY choose any one (OR), so list them SEPARATELY (one entry each)
		// rather than fabricating an "AND" that wrongly inflates the obligation/severity.
		parts := []string{raw}
		if list := splitLicenseList(raw); len(list) > 1 {
			parts = list
		}
		for _, part := range parts {
			key := canonicalLicenseKey(part)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			category := classify(key)
			if category != sbom.LicenseUnknown {
				hasResolved = true
			}
			rawValue := strings.TrimSpace(l.RawValue)
			if rawValue == "" {
				rawValue = raw
			}
			entries = append(entries, entry{lic: sbom.License{SPDXID: key, Name: key, RawValue: rawValue, Category: category}, category: category})
		}
	}
	if len(entries) == 0 {
		return nil
	}
	out := make([]sbom.License, 0, len(entries))
	for _, e := range entries {
		if hasResolved && e.category == sbom.LicenseUnknown {
			continue
		}
		out = append(out, e.lic)
	}
	return out
}

func canonicalLicenseKey(raw string) string {
	key := licenseValueWithoutMetadata(raw)
	if key == "" {
		return ""
	}
	// A locator URL from a known license host → its EXACT SPDX id, exception preserved
	// (e.g. GPL-2.0-with-classpath-exception, which must not collapse to GPL-2.0). spdxFromURL
	// matches only a single clean URL, so a comma/semicolon LIST falls through to the split below.
	if id, ok := spdxFromURL(canonicalizeLicenseURL(key)); ok {
		return id
	}
	norm := normalizeSPDX(key)
	if _, ok := spdxCategory[norm]; ok {
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if strings.Contains(lowerKey, "-or-later") || strings.Contains(lowerKey, "-only") || strings.Contains(lowerKey, " with ") || strings.Contains(lowerKey, "-with-") || strings.HasSuffix(lowerKey, "+") {
			return strings.TrimSpace(key) // preserve -or-later/-only/+ and the license exception (e.g. GPL-2.0-with-classpath-exception)
		}
		return canonicalSPDXID(norm)
	}
	// Mechanical family+version normalization (GPLv3 / GPL 3.0 / LGPL v2.1 / MPL 2.0 → canonical id),
	// so abbreviated forms don't each need a hand alias and don't leak a raw "GPLv3" into the display.
	nameKey := normalizeName(key)
	if id, ok := spdxFromAbbreviatedFamily(nameKey); ok {
		return id
	}
	// A verbose human name ("GNU Lesser General Public License v3.0") → its canonical SPDX id for a
	// consistent display, mirroring the category path (classifySingle) that already consults these.
	if id, ok := licenseAliases[nameKey]; ok {
		return canonicalSPDXID(id)
	}
	if parts := splitLicenseList(key); len(parts) > 1 {
		var out []string
		seen := map[string]bool{}
		for _, p := range parts {
			p = canonicalLicenseKey(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
		if len(out) == 0 {
			return ""
		}
		if len(out) == 1 {
			return out[0]
		}
		// A bare license list is a CHOICE (OR) per Maven/SPDX convention — never AND.
		return strings.Join(out, " OR ")
	}
	return key
}

func licensePolicy(expression string) ([]ports.LicensePolicyOption, string, string, string) {
	expression = stripOuterParens(strings.TrimSpace(expression))
	parts := splitTopLevel(expression, "OR")
	chooseLowest := len(parts) > 1
	if !chooseLowest {
		parts = splitTopLevel(expression, "AND")
	}
	options := make([]ports.LicensePolicyOption, 0, len(parts))
	selected := ""
	selectedRisk := RiskUnknown
	for index, part := range parts {
		part = strings.TrimSpace(part)
		risk, severity := RiskOf(part)
		options = append(options, ports.LicensePolicyOption{License: part, Severity: severity, PolicyRuleID: policyRuleID(part)})
		if index == 0 || (chooseLowest && riskRank(risk) < riskRank(selectedRisk)) || (!chooseLowest && riskRank(risk) > riskRank(selectedRisk)) {
			selected = part
			selectedRisk = risk
		}
	}
	if selected == "" {
		selected = expression
	}
	recommendedChoice := ""
	reason := "Single detected license"
	if len(options) > 1 && chooseLowest {
		recommendedChoice = selected
		reason = "Lowest-risk valid OR option"
	} else if len(options) > 1 {
		reason = "Highest-risk mandatory AND option"
	}
	return options, recommendedChoice, policyRuleID(selected), reason
}

var policyRuleSanitizer = regexp.MustCompile(`[^A-Za-z0-9]+`)

func policyRuleID(license string) string {
	value := strings.Trim(policyRuleSanitizer.ReplaceAllString(strings.ToUpper(strings.TrimSpace(license)), "-"), "-")
	if value == "" {
		value = "UNKNOWN"
	}
	if len(value) > 48 {
		value = value[:48]
	}
	return "LIC-" + value
}

// classify resolves an SPDX id or expression to a category, respecting SPDX
// operator precedence (WITH > AND > OR) and parentheses. "A OR B" picks the most
// permissive operand; "A AND B" the most restrictive; " WITH <exc>" keeps the base.
func classify(expr string) sbom.LicenseCategory {
	expr = stripOuterParens(strings.TrimSpace(expr))
	if expr == "" {
		return sbom.LicenseUnknown
	}
	if c := classifySingle(expr); c != sbom.LicenseUnknown {
		return c
	}
	if parts := splitLicenseList(expr); len(parts) > 1 {
		worst := sbom.LicensePermissive
		for _, p := range parts {
			if c := classify(p); catRank(c) > catRank(worst) {
				worst = c
			}
		}
		return worst
	}
	// OR is the lowest-precedence operator → split it at the top level first.
	if ors := splitTopLevel(expr, "OR"); len(ors) > 1 {
		best := sbom.LicenseUnknown
		for _, p := range ors {
			if c := classify(p); catRank(c) < catRank(best) {
				best = c
			}
		}
		return best
	}
	if ands := splitTopLevel(expr, "AND"); len(ands) > 1 {
		worst := sbom.LicensePermissive
		for _, p := range ands {
			if c := classify(p); catRank(c) > catRank(worst) {
				worst = c
			}
		}
		return worst
	}
	if withs := splitTopLevel(expr, "WITH"); len(withs) > 1 {
		expr = withs[0] // the exception binds to the base license; classify the base
	}
	return classifySingle(expr)
}

func classifySingle(s string) sbom.LicenseCategory {
	norm := normalizeSPDX(s)
	if cat, ok := spdxCategory[norm]; ok {
		return cat
	}
	// Free-text license NAME → SPDX id. Registries and JAR pom <licenses> / MANIFEST
	// Bundle-License often carry a human name ("Apache License, Version 2.0") rather than
	// an SPDX id; without this they fall through to unknown.
	name := normalizeName(s)
	if id, ok := licenseAliases[name]; ok {
		if cat, ok := spdxCategory[id]; ok {
			return cat
		}
	}
	// Retry the id table on the name-normalized form too (e.g. "The Unlicense" → "unlicense").
	if cat, ok := spdxCategory[name]; ok {
		return cat
	}
	// Mechanical family+version normalization catches abbreviated forms (GPLv3, LGPL v2.1, MPL 2.0)
	// that a hand alias would otherwise have to enumerate one-by-one.
	if id, ok := spdxFromAbbreviatedFamily(name); ok {
		if cat, ok := spdxCategory[normalizeSPDX(id)]; ok {
			return cat
		}
	}
	if strings.Contains(norm, "permission is hereby granted") {
		return sbom.LicensePermissive
	}
	// Deterministic SPDX-family fallback: covers the long tail of the SPDX License List
	// (and future ids) the curated table doesn't enumerate, instead of defaulting to unknown.
	if fam := familyOf(norm); fam != famUnknown {
		return fam.category()
	}
	return sbom.LicenseUnknown
}

// normalizeName folds a human license name to a comparison key: lowercased, punctuation
// and hyphens collapsed to single spaces, a leading "the " dropped. Dots are kept so a
// version like "2.0" survives ("Apache License, Version 2.0" → "apache license version
// 2.0"). Used only for the free-text alias lookup, never for SPDX-id matching.
func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "custom license:")
	s = strings.Map(func(r rune) rune {
		switch r {
		case ',', ';', ':', '(', ')', '/', '\\', '"', '\'', '-', '_':
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ") // collapse runs of space + trim
	s = strings.TrimPrefix(s, "the ")
	return s
}

func normalizeSPDX(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Trim(s, `"'`)
	if i := strings.Index(s, `";link="`); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, "; see:"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, ".html")
	s = strings.TrimSuffix(s, ".txt")
	// Host-pattern URL → SPDX id first (generalizes over URL variants); the curated table is
	// the fallback for non-host oddball locators (jsoup, flyway, oracle cddl+gpl, …).
	if id, ok := spdxFromURL(canonicalizeLicenseURL(s)); ok {
		s = strings.ToLower(id)
	} else if alias, ok := rawLicenseAliases[s]; ok {
		s = alias
	}
	s = strings.TrimPrefix(s, "custom license:")
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " with ", " WITH ")
	if withs := splitTopLevel(s, "WITH"); len(withs) > 1 {
		s = strings.TrimSpace(withs[0])
	}
	s = strings.ReplaceAll(s, "-with-autoconf-exception", "")
	s = strings.ReplaceAll(s, "-with-bison-exception", "")
	s = strings.ReplaceAll(s, "-with-libtool-exception", "")
	s = strings.ReplaceAll(s, "-with-classpath-exception", "")
	s = strings.ReplaceAll(s, "-with-gcc-exception", "")
	s = strings.ReplaceAll(s, "-with-font-exception", "")
	s = strings.ReplaceAll(s, " with exception", "")
	s = strings.ReplaceAll(s, " with openssh-linking exception", "")
	s = strings.TrimSuffix(s, "+")
	s = strings.TrimSuffix(s, "-only")
	s = strings.TrimSuffix(s, "-or-later")
	s = strings.TrimSuffix(s, "+")
	s = strings.TrimSuffix(s, "-only")
	s = strings.TrimSuffix(s, "-or-later")
	s = strings.TrimSpace(s)
	return s
}

// catRank orders categories from most permissive (0) to unknown (4): OR picks the
// minimum (most permissive), AND the maximum (most restrictive).
func catRank(c sbom.LicenseCategory) int {
	switch c {
	case sbom.LicensePermissive:
		return 0
	case sbom.LicenseWeakCopyleft:
		return 1
	case sbom.LicenseCopyleft:
		return 2
	case sbom.LicenseProprietary:
		return 3
	default:
		return 4
	}
}

// stripOuterParens repeatedly removes a balanced enclosing paren pair.
func stripOuterParens(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && outerMatched(s) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// outerMatched reports whether the leading '(' is closed by the trailing ')'.
func outerMatched(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(s)-1 {
				return false // closed before the end → not an enclosing pair
			}
		}
	}
	return depth == 0
}

// splitTopLevel splits s on the case-insensitive word operator (" OR ", " AND ",
// " WITH ") only at parenthesis depth 0.
func splitTopLevel(s, op string) []string {
	sep := " " + op + " "
	up := strings.ToUpper(s)
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && i+len(sep) <= len(s) && up[i:i+len(sep)] == sep {
			parts = append(parts, strings.TrimSpace(s[start:i]))
			i += len(sep) - 1
			start = i + 1
		}
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}

func splitLicenseList(s string) []string {
	if splitTopLevel(s, "AND")[0] != s || splitTopLevel(s, "OR")[0] != s {
		return nil
	}
	for _, sep := range []byte{',', ';'} {
		depth, start := 0, 0
		var quote byte
		parts := []string{}
		for i := 0; i < len(s); i++ {
			if quote != 0 {
				if s[i] == quote && (i == 0 || s[i-1] != '\\') {
					quote = 0
				}
				continue
			}
			switch s[i] {
			case '\'', '"':
				quote = s[i]
			case '(':
				depth++
			case ')':
				if depth > 0 {
					depth--
				}
			case sep:
				if depth == 0 {
					parts = append(parts, strings.TrimSpace(s[start:i]))
					start = i + 1
				}
			}
		}
		if len(parts) > 0 {
			parts = append(parts, strings.TrimSpace(s[start:]))
			return parts
		}
	}
	return nil
}

func licenseValueWithoutMetadata(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		for index := 1; index < len(value); index++ {
			if value[index] != quote || value[index-1] == '\\' {
				continue
			}
			rest := strings.TrimSpace(value[index+1:])
			if rest == "" || isLicenseMetadataSuffix(rest) {
				return strings.TrimSpace(value[1:index])
			}
			break
		}
	}
	var quote byte
	depth := 0
	for index := 0; index < len(value); index++ {
		if quote != 0 {
			if value[index] == quote && value[index-1] != '\\' {
				quote = 0
			}
			continue
		}
		switch value[index] {
		case '\'', '"':
			quote = value[index]
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 && isLicenseMetadataSuffix(value[index:]) {
				return strings.TrimSpace(value[:index])
			}
		}
	}
	return value
}

func isLicenseMetadataSuffix(value string) bool {
	value = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), ";")))
	return strings.HasPrefix(value, "link=") || strings.HasPrefix(value, "url=") || strings.HasPrefix(value, "href=") || strings.HasPrefix(value, "see:")
}

func canonicalSPDXID(norm string) string {
	if id, ok := canonicalSPDX[norm]; ok {
		return id
	}
	return norm
}

// canonicalizeLicenseURL folds a license URL to a bare "host/path" key: it lowercases,
// then strips the scheme, a leading "www.", a trailing slash, and a documentation
// extension (.html/.htm/.php/.txt/.md). A non-URL string comes back lowercased & trimmed
// (spdxFromURL then matches nothing). It deliberately does NOT split on ';' — a ';'-joined
// LIST must reach spdxFromURL intact so its list-guard rejects it (splitting here would let
// a "permissive-url;forbidden-url" pair collapse to the permissive head — a downgrade).
func canonicalizeLicenseURL(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Trim(s, `"'`)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "www.")
	s = strings.TrimRight(s, "/")
	for _, ext := range []string{".html", ".htm", ".php", ".txt", ".md"} {
		s = strings.TrimSuffix(s, ext)
	}
	return strings.TrimSpace(s)
}

// gnuLicenseRe captures a GNU-family license id + version anywhere in a path, e.g.
// "lgpl-2.1", "gpl-3.0", "agpl-3.0", "gfdl-1.3" (optional 'v'/separator, bare major ok).
var gnuLicenseRe = regexp.MustCompile(`(agpl|lgpl|gpl|gfdl|fdl)[-_]?v?(\d+(?:\.\d+)?)`)

// abbrevFamilyRe matches a SHORT family+version license token as a WHOLE string, e.g. "gplv3",
// "gpl 3.0", "gpl 3", "lgplv2.1", "lgpl v2.1", "mpl 2.0", "apache 2.0" — operating on the normalizeName
// output (lowercased, punctuation→space, dots kept). Anchored so it never fires on a longer sentence.
var abbrevFamilyRe = regexp.MustCompile(`^(agpl|lgpl|gpl|gfdl|mpl|epl|cddl|apache)\s*v?\s*(\d+(?:\.\d+)?)$`)

// spdxFromAbbreviatedFamily maps a short "<family><version>" token to its canonical SPDX id
// MECHANICALLY, so surface variants (GPLv3 / GPL 3.0 / GPL-3 / LGPL v2.1 / MPL 2.0 …) resolve WITHOUT a
// per-variant hand alias — the normalize-before-lookup technique that keeps the curated table small
// (mirrors Trivy's standardizeKeyAndSuffix + versionSuffixRegexp). Input is a normalizeName key. ok only
// for a version we actually classify (an unknown version like "gplv4" stays unresolved, never invented).
func spdxFromAbbreviatedFamily(nameKey string) (string, bool) {
	m := abbrevFamilyRe.FindStringSubmatch(nameKey) // input is a normalizeName key (already trimmed/collapsed)
	if m == nil {
		return "", false
	}
	fam, ver := m[1], m[2]
	if !strings.Contains(ver, ".") {
		ver += ".0" // SPDX uses the X.0 form: "gpl 3" → GPL-3.0, "apache 2" → Apache-2.0
	}
	id := fam + "-" + ver
	if !spdxKnown(id) {
		return "", false
	}
	return canonicalSPDXID(id), true
}

// ccLicenseRe captures a Creative Commons variant + version, e.g. "by-sa/4.0", "by/4.0".
var ccLicenseRe = regexp.MustCompile(`(by(?:-nc)?(?:-sa|-nd)?)[-/](\d+(?:\.\d+)?)`)

// spdxFromURL maps a canonicalized license URL (see canonicalizeLicenseURL) to an SPDX
// display id by recognizing KNOWN license-hosting domains and their URL grammar — a
// host-pattern engine that replaces a brittle, ever-growing per-URL alias table. It
// PRESERVES a license exception (e.g. the GNU Classpath exception) so the shown id is
// exact (this is what keeps "GPL-2.0-with-classpath-exception" from collapsing to
// "GPL-2.0"). ok is false for anything that is not a single URL on a recognized host —
// so it never attributes a license to an unrelated component.
//
// Per-host URL schemes are public + stable; ids are SPDX License List short ids:
//
//	apache.org/licenses/LICENSE-2.0 · eclipse.org/legal/{epl-2.0,epl-v10,edl-v10} ·
//	gnu.org|fsf.org/…/{a,l,}gpl|gfdl-N[.N] (+ classpath exception) · mozilla.org/MPL/2.0 ·
//	creativecommons.org/{licenses/by-sa/4.0,publicdomain/zero/1.0} ·
//	spdx.org/licenses/<id> · opensource.org/license[s]/<id>.
func spdxFromURL(u string) (string, bool) {
	// Only a single, clean URL token — never a comma/semicolon/space-separated LIST. A list
	// must fall through so the caller splits it into separate licenses; resolving the first
	// element here would drop the rest (e.g. a forbidden license hidden behind a permissive
	// one) — a silent downgrade. ';' is a list separator (see splitLicenseList), so reject it.
	if u == "" || !strings.Contains(u, "/") || strings.ContainsAny(u, ",; \t\n") {
		return "", false
	}
	switch {
	case hostIs(u, "apache.org"):
		switch {
		case strings.Contains(u, "1.1"):
			return "Apache-1.1", true
		case strings.Contains(u, "2.0") || strings.HasSuffix(u, "/licenses"):
			return "Apache-2.0", true
		}
	case hostIs(u, "eclipse.org"):
		switch {
		case strings.Contains(u, "epl-2.0"):
			return "EPL-2.0", true
		case strings.Contains(u, "epl-v10") || strings.Contains(u, "epl-1.0"):
			return "EPL-1.0", true
		case strings.Contains(u, "edl-v10") || strings.Contains(u, "edl-1.0"):
			return "EDL-1.0", true
		}
	case hostIs(u, "gnu.org"), hostIs(u, "fsf.org"):
		if strings.Contains(u, "classpath") {
			return "GPL-2.0-with-classpath-exception", true
		}
		if m := gnuLicenseRe.FindStringSubmatch(u); m != nil {
			return gnuSPDX(m[1], m[2])
		}
	case hostIs(u, "mozilla.org"):
		switch {
		case strings.Contains(u, "mpl") && strings.Contains(u, "2.0"):
			return "MPL-2.0", true
		case strings.Contains(u, "mpl") && strings.Contains(u, "1.1"):
			return "MPL-1.1", true
		}
	case hostIs(u, "creativecommons.org"):
		if strings.Contains(u, "publicdomain/zero") {
			return "CC0-1.0", true
		}
		if m := ccLicenseRe.FindStringSubmatch(u); m != nil {
			if id := "CC-" + strings.ToUpper(m[1]) + "-" + m[2]; spdxKnown(strings.ToLower(id)) {
				return id, true
			}
		}
	case hostIs(u, "spdx.org"), hostIs(u, "opensource.org"):
		return spdxFromLicensesPath(u)
	case hostIs(u, "bouncycastle.org"):
		return "Bouncy-Castle", true // Bouncy Castle's MIT-style licence (permissive; classifies via the name fallback)
	case hostIs(u, "oracle.com"):
		// Oracle's Free Use Terms and Conditions — a proprietary free-use licence, no SPDX id (matches Trivy's LicenseRef).
		if strings.Contains(u, "oracle-free-license") || strings.Contains(u, "/futc") {
			return "LicenseRef-Oracle-Free-Use-Terms-and-Conditions-FUTC", true
		}
	}
	return "", false
}

// hostIs reports whether the canonicalized URL u is on host h (h itself or h/…).
func hostIs(u, h string) bool { return u == h || strings.HasPrefix(u, h+"/") }

// gnuSPDX builds a GNU-family SPDX id from the regex captures, returning ok only for an id
// we actually classify (so an unknown version is left unresolved rather than invented).
func gnuSPDX(family, version string) (string, bool) {
	prefix := map[string]string{"agpl": "AGPL", "lgpl": "LGPL", "gpl": "GPL", "gfdl": "GFDL", "fdl": "GFDL"}[family]
	if prefix == "" {
		return "", false
	}
	if !strings.Contains(version, ".") {
		version += ".0" // SPDX uses the X.0 form (gpl-3 → GPL-3.0)
	}
	id := prefix + "-" + version
	if !spdxKnown(strings.ToLower(id)) {
		return "", false
	}
	return id, true
}

// spdxFromLicensesPath resolves an spdx.org / opensource.org license page where the LAST
// path segment IS the SPDX id; ok only for an id we classify (avoids inventing ids).
func spdxFromLicensesPath(u string) (string, bool) {
	seg := u
	if i := strings.LastIndexByte(u, '/'); i >= 0 {
		seg = u[i+1:]
	}
	seg = strings.TrimSuffix(seg, "-license") // opensource.org/licenses/mit-license
	if seg == "" || !spdxKnown(seg) {
		return "", false
	}
	return canonicalSPDXID(seg), true
}

// spdxKnown reports whether a normalized (lowercase) SPDX id is one we classify.
func spdxKnown(lowerID string) bool { _, ok := spdxCategory[lowerID]; return ok }

// spdxCategory maps common SPDX ids (normalized, lowercase) to a category.
// Unlisted ids fall back to unknown (→ warn under the default policy).
var spdxCategory = map[string]sbom.LicenseCategory{
	// permissive
	"mit": sbom.LicensePermissive, "mit-0": sbom.LicensePermissive,
	"apache-2.0": sbom.LicensePermissive, "apache-1.1": sbom.LicensePermissive,
	"bsd-2-clause": sbom.LicensePermissive, "bsd-3-clause": sbom.LicensePermissive,
	"bsd-unspecified":     sbom.LicensePermissive,
	"bsd-4-clause":        sbom.LicensePermissive,
	"bsd-2-clause-netbsd": sbom.LicensePermissive,
	"bsd-3-clause-clear":  sbom.LicensePermissive, "0bsd": sbom.LicensePermissive,
	"isc": sbom.LicensePermissive, "zlib": sbom.LicensePermissive,
	"unlicense": sbom.LicensePermissive, "bsl-1.0": sbom.LicensePermissive,
	"cc0-1.0": sbom.LicensePermissive, "python-2.0": sbom.LicensePermissive,
	"beerware": sbom.LicensePermissive, "bzip2-1.0.6": sbom.LicensePermissive,
	"curl": sbom.LicensePermissive, "hpnd": sbom.LicensePermissive,
	"openssl": sbom.LicensePermissive,
	// OFL-1.1 (SIL Open Font License) has a weak font-copyleft clause (rename + no standalone
	// sale of modified fonts) → weak-copyleft per ScanCode, not bare permissive.
	"ofl-1.1": sbom.LicenseWeakCopyleft,
	"sax-pd":  sbom.LicensePermissive, "w3c": sbom.LicensePermissive,
	"bouncycastle": sbom.LicensePermissive,
	"psf-2":        sbom.LicensePermissive,
	"postgresql":   sbom.LicensePermissive, "ncsa": sbom.LicensePermissive,
	"libpng": sbom.LicensePermissive, "x11": sbom.LicensePermissive,
	"wtfpl": sbom.LicensePermissive, "unicode-dfs-2016": sbom.LicensePermissive,
	"upl-1.0": sbom.LicensePermissive,
	"regcomp": sbom.LicensePermissive, "gap": sbom.LicensePermissive,
	"unicode": sbom.LicensePermissive, "rfc-reference": sbom.LicensePermissive,
	// weak copyleft
	"mpl-2.0": sbom.LicenseWeakCopyleft, "mpl-1.1": sbom.LicenseWeakCopyleft,
	"lgpl-2.0": sbom.LicenseWeakCopyleft, "lgpl-2.1": sbom.LicenseWeakCopyleft,
	"lgpl-3.0": sbom.LicenseWeakCopyleft, "epl-1.0": sbom.LicenseWeakCopyleft,
	"epl-2.0": sbom.LicenseWeakCopyleft, "edl-1.0": sbom.LicensePermissive,
	"cddl-1.0": sbom.LicenseWeakCopyleft,
	"cddl-1.1": sbom.LicenseWeakCopyleft, "ms-pl": sbom.LicenseWeakCopyleft,
	"cpl-1.0": sbom.LicenseWeakCopyleft,
	// OSL + EUPL are STRONG (whole-work / network) copyleft per FSF — matching their
	// riskByLicense=restricted entries (previously mis-listed here as weak-copyleft).
	"eupl-1.1": sbom.LicenseCopyleft, "eupl-1.2": sbom.LicenseCopyleft,
	"osl-3.0": sbom.LicenseCopyleft, "artistic-1": sbom.LicenseWeakCopyleft,
	"artistic-2": sbom.LicenseWeakCopyleft, "artistic-2.0": sbom.LicenseWeakCopyleft,
	// strong copyleft
	"gpl-1.0": sbom.LicenseCopyleft, "gpl-2": sbom.LicenseCopyleft,
	"gpl-2.0": sbom.LicenseCopyleft, "gpl-3": sbom.LicenseCopyleft,
	"gpl-3.0": sbom.LicenseCopyleft, "agpl-1.0": sbom.LicenseCopyleft,
	"agpl-3.0": sbom.LicenseCopyleft, "gfdl-1.2": sbom.LicenseCopyleft,
	"gfdl-1.3":     sbom.LicenseCopyleft,
	"sleepycat":    sbom.LicenseCopyleft,
	"cc-by-sa-3.0": sbom.LicenseCopyleft, "cc-by-sa-4.0": sbom.LicenseCopyleft,
	// proprietary
	"commercial": sbom.LicenseProprietary, "proprietary": sbom.LicenseProprietary,
	"licenseref-oracle-free-use-terms-and-conditions-futc": sbom.LicenseProprietary,
}

// licenseAliases maps a normalized free-text license NAME (see normalizeName) to a
// canonical SPDX id from spdxCategory. Curated + LLM-free. Where a family name is
// version-ambiguous (e.g. a bare "BSD License"), it maps to the variant whose POLICY
// CATEGORY is the same across versions, so the policy verdict is correct even if the
// exact id is the most-common variant.
var licenseAliases = map[string]string{
	// MIT
	"mit license": "mit",
	// Apache
	"apache license 2.0": "apache-2.0", "apache license version 2.0": "apache-2.0",
	"apache license v2.0":         "apache-2.0",
	"apache software license 2.0": "apache-2.0", "apache software license version 2.0": "apache-2.0",
	"apache public license 2.0": "apache-2.0",
	"apache license 1.1":        "apache-1.1", "apache software license 1.1": "apache-1.1",
	// BSD (all permissive — exact clause count doesn't change the verdict)
	"bsd license": "bsd-unspecified", "bsd": "bsd-unspecified",
	"new bsd license": "bsd-3-clause", "modified bsd license": "bsd-3-clause",
	"bsd 3 clause license": "bsd-3-clause", "bsd 3 clause": "bsd-3-clause", "3 clause bsd license": "bsd-3-clause",
	"simplified bsd license": "bsd-2-clause", "bsd 2 clause license": "bsd-2-clause",
	"bsd 2 clause": "bsd-2-clause", "2 clause bsd license": "bsd-2-clause",
	// ISC / zlib
	"isc license": "isc", "zlib license": "zlib",
	// GPL (abbreviated "GPLv3"/"GPL 3.0"/"GPL 3" forms are handled mechanically by
	// spdxFromAbbreviatedFamily — only the VERBOSE names need an alias here).
	"gnu general public license version 3.0": "gpl-3.0", "gnu general public license v3.0": "gpl-3.0",
	"gnu general public license v3":          "gpl-3.0",
	"gnu general public license version 2.0": "gpl-2.0", "gnu general public license v2.0": "gpl-2.0",
	// LGPL (weak-copyleft across versions)
	"gnu lesser general public license version 3.0": "lgpl-3.0", "gnu lesser general public license v3.0": "lgpl-3.0",
	"gnu lesser general public license":             "lgpl-3.0",
	"gnu lesser general public license version 2.1": "lgpl-2.1",
	// Affero
	"gnu affero general public license version 3.0": "agpl-3.0", "gnu affero general public license v3.0": "agpl-3.0",
	// MPL / EPL / CDDL (abbreviated "MPL 2.0" handled mechanically)
	"mozilla public license 2.0": "mpl-2.0", "mozilla public license version 2.0": "mpl-2.0",
	"eclipse public license 2.0": "epl-2.0", "eclipse public license version 2.0": "epl-2.0",
	"eclipse public license 1.0": "epl-1.0", "eclipse public license version 1.0": "epl-1.0",
	"common development and distribution license": "cddl-1.0",
	"eclipse distribution license v 1.0":          "edl-1.0",
	"eclipse public license v 1.0":                "epl-1.0",
	"cpl":                                         "cpl-1.0",
	"bouncy castle":                               "bouncycastle",
	"bouncy castle licence":                       "bouncycastle",
	"bouncy castle license":                       "bouncycastle",
	"psf or zpl":                                  "python-2.0",
	// Oracle Free Use Terms and Conditions (proprietary free-use; name path, mirrors the URL mapping).
	"oracle free use terms and conditions futc": "licenseref-oracle-free-use-terms-and-conditions-futc",
	"oracle free use terms and conditions":      "licenseref-oracle-free-use-terms-and-conditions-futc",
}

var rawLicenseAliases = map[string]string{
	"apache":                                             "apache-2.0",
	"http://apache.org/licenses/license-2.0":             "apache-2.0",
	"http://www.apache.org/licenses":                     "apache-2.0",
	"http://www.apache.org/licenses/license-2.0":         "apache-2.0",
	"https://www.apache.org/licenses/license-2.0":        "apache-2.0",
	"http://www.opensource.org/licenses/mit-license.php": "mit",
	"http://www.opensource.org/licenses/bsd-license.php": "bsd-unspecified",
	"http://opensource.org/licenses/bsd-2-clause":        "bsd-2-clause",
	"https://opensource.org/licenses/bsd-2-clause":       "bsd-2-clause",
	"http://opensource.org/licenses/bsd-3-clause":        "bsd-3-clause",
	"https://opensource.org/licenses/bsd-3-clause":       "bsd-3-clause",
	"public-domain": "cc0-1.0",
	"public domain": "cc0-1.0",
	"pd":            "cc0-1.0",
	"pd-debian":     "cc0-1.0",
	"bzip":          "bzip2-1.0.6",
	"https://creativecommons.org/publicdomain/zero/1.0":                  "cc0-1.0",
	"http://creativecommons.org/publicdomain/zero/1.0":                   "cc0-1.0",
	"http://www.eclipse.org/legal/epl-2.0":                               "epl-2.0",
	"https://www.eclipse.org/legal/epl-2.0":                              "epl-2.0",
	"http://www.eclipse.org/org/documents/epl-v10.php":                   "epl-1.0",
	"http://www.eclipse.org/legal/epl-v10":                               "epl-1.0", // logback's EPL-1.0 URL form
	"https://www.eclipse.org/legal/epl-v10":                              "epl-1.0",
	"https://www.mozilla.org/en-us/mpl/2.0":                              "mpl-2.0",
	"http://www.gnu.org/licenses/lgpl-2.1":                               "lgpl-2.1",
	"https://www.gnu.org/licenses/old-licenses/lgpl-2.1":                 "lgpl-2.1",
	"http://www.gnu.org/licenses/old-licenses/lgpl-2.1":                  "lgpl-2.1", // http variant (logback)
	"https://www.gnu.org/software/classpath/license":                     "gpl-2.0-with-classpath-exception",
	"http://www.gnu.org/software/classpath/license":                      "gpl-2.0-with-classpath-exception",
	"http://www.fsf.org/licensing/licenses/agpl-3.0":                     "agpl-3.0",
	"https://jsoup.org/license":                                          "mit",
	"https://flywaydb.org/licenses/flyway-community":                     "apache-2.0",
	"https://oss.oracle.com/licenses/cddl+gpl-1.1":                       "cddl-1.1",
	"https://raw.githubusercontent.com/threeten/threetenbp/main/license": "bsd-3-clause",
}

var canonicalSPDX = map[string]string{
	"agpl-3.0":         "AGPL-3.0",
	"apache-1.1":       "Apache-1.1",
	"apache-2.0":       "Apache-2.0",
	"artistic-2.0":     "Artistic-2.0",
	"beerware":         "Beerware",
	"bsd-2-clause":     "BSD-2-Clause",
	"bsd-3-clause":     "BSD-3-Clause",
	"bsd-unspecified":  "BSD-UNSPECIFIED",
	"bsl-1.0":          "BSL-1.0",
	"bzip2-1.0.6":      "bzip2-1.0.6",
	"bouncycastle":     "Bouncy-Castle",
	"cddl-1.0":         "CDDL-1.0",
	"cddl-1.1":         "CDDL-1.1",
	"cc0-1.0":          "CC0-1.0",
	"cpl-1.0":          "CPL-1.0",
	"curl":             "curl",
	"edl-1.0":          "EDL-1.0",
	"epl-1.0":          "EPL-1.0",
	"epl-2.0":          "EPL-2.0",
	"gfdl-1.2":         "GFDL-1.2",
	"gfdl-1.3":         "GFDL-1.3",
	"gpl-1.0":          "GPL-1.0",
	"gpl-2.0":          "GPL-2.0",
	"gpl-3.0":          "GPL-3.0",
	"isc":              "ISC",
	"lgpl-2.0":         "LGPL-2.0",
	"lgpl-2.1":         "LGPL-2.1",
	"lgpl-3.0":         "LGPL-3.0",
	"mit":              "MIT",
	"mpl-1.1":          "MPL-1.1",
	"mpl-2.0":          "MPL-2.0",
	"ofl-1.1":          "OFL-1.1",
	"openssl":          "OpenSSL",
	"python-2.0":       "Python-2.0",
	"sax-pd":           "SAX-PD",
	"unicode-dfs-2016": "Unicode-DFS-2016",
	"w3c":              "W3C",
	"zlib":             "Zlib",
}
