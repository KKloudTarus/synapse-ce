package license

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// RiskCategory is an industry-standard license RISK bucket — finer than the policy
// LicenseCategory (permissive/weak-copyleft/copyleft/proprietary/unknown). It is ADDITIVE:
// the policy Verdict (allow/warn/deny) is unchanged; this adds the granular category +
// a severity label so a consumer sees the same detail Trivy/FOSSA show, plus our verdict.
//
// The category assignments are DERIVED (not copied) from two public upstreams:
// the SPDX License List — https://spdx.org/licenses
// Google's licenseclassifier categorization —
// https://github.com/google/licenseclassifier (license_type.go), the same canonical
// source other scanners (e.g. Trivy) port from.
//
// We re-derive our own table so Synapse owns the data, and extend it with modern
// source-available licenses (SSPL/BUSL) the legacy categorization predates.
type RiskCategory string

const (
	RiskForbidden    RiskCategory = "forbidden"    // non-commercial / network-copyleft / source-available bans
	RiskRestricted   RiskCategory = "restricted"   // strong copyleft (GPL/LGPL/OSL): mandatory source distribution
	RiskReciprocal   RiskCategory = "reciprocal"   // weak/file-level copyleft (MPL/EPL/CDDL)
	RiskNotice       RiskCategory = "notice"       // permissive WITH attribution (MIT/Apache/BSD)
	RiskPermissive   RiskCategory = "permissive"   // permissive without an attribution clause
	RiskUnencumbered RiskCategory = "unencumbered" // public-domain-equivalent (CC0/Unlicense/0BSD)
	RiskUnknown      RiskCategory = "unknown"      // unrecognized — review manually
)

// RiskSeverity maps a category to a severity label, following the industry convention
// (Forbidden→critical, Restricted→high, Reciprocal→medium, Notice/Permissive/Unencumbered→low).
func RiskSeverity(c RiskCategory) string {
	switch c {
	case RiskForbidden:
		return "critical"
	case RiskRestricted:
		return "high"
	case RiskReciprocal:
		return "medium"
	case RiskNotice, RiskPermissive, RiskUnencumbered:
		return "low"
	}
	return "unknown"
}

// riskRank orders categories by severity for expression resolution (low→high), with
// unknown highest so OR avoids it (a known operand is electable) and AND selects it (an
// unknown obligation must be reviewed) — mirroring classify()'s catRank semantics.
func riskRank(c RiskCategory) int {
	switch c {
	case RiskPermissive, RiskUnencumbered, RiskNotice:
		return 0
	case RiskReciprocal:
		return 1
	case RiskRestricted:
		return 2
	case RiskForbidden:
		return 3
	}
	return 4 // unknown
}

// RiskOf resolves an SPDX id or expression to a (category, severity). It reuses the SAME
// operator-precedence engine as classify(): OR picks the least-risky operand (you may
// elect it), AND the most-risky, WITH keeps the base; an unrecognized license → unknown.
func RiskOf(license string) (RiskCategory, string) {
	c := classifyRisk(license)
	return c, RiskSeverity(c)
}

func classifyRisk(expr string) RiskCategory {
	expr = stripOuterParens(strings.TrimSpace(expr))
	if expr == "" {
		return RiskUnknown
	}
	if c := classifyRiskSingle(expr); c != RiskUnknown {
		return c
	}
	// Comma/semicolon-separated list (non-SPDX) → treat as AND (most-restrictive wins).
	if parts := splitLicenseList(expr); len(parts) > 1 {
		worst := RiskPermissive
		for _, p := range parts {
			if c := classifyRisk(p); riskRank(c) > riskRank(worst) {
				worst = c
			}
		}
		return worst
	}
	if ors := splitTopLevel(expr, "OR"); len(ors) > 1 {
		best := RiskUnknown
		for _, p := range ors {
			if c := classifyRisk(p); riskRank(c) < riskRank(best) {
				best = c
			}
		}
		return best
	}
	if ands := splitTopLevel(expr, "AND"); len(ands) > 1 {
		worst := RiskPermissive
		for _, p := range ands {
			if c := classifyRisk(p); riskRank(c) > riskRank(worst) {
				worst = c
			}
		}
		return worst
	}
	if withs := splitTopLevel(expr, "WITH"); len(withs) > 1 {
		expr = withs[0] // the exception binds to the base license; classify the base
	}
	return classifyRiskSingle(expr)
}

// classifyRiskSingle resolves one license token, reusing the normalizer + alias tables
// that classify() already uses (SPDX-id form, then free-text-name form).
func classifyRiskSingle(s string) RiskCategory {
	norm := normalizeSPDX(s)
	if c, ok := riskByLicense[norm]; ok {
		return c
	}
	name := normalizeName(s)
	if id, ok := licenseAliases[name]; ok {
		if c, ok := riskByLicense[id]; ok {
			return c
		}
	}
	if c, ok := riskByLicense[name]; ok {
		return c
	}
	// Coverage bridge: if the policy table classifies this id but the risk table has no entry,
	// derive the risk from the category so an id known only to spdxCategory still reads a
	// consistent severity (rather than falling through to the family rules, which might infer a
	// different one). This is a COVERAGE guarantee, not strict lockstep: where BOTH tables list
	// an id, the risk table may be intentionally finer than the policy category — e.g. LGPL is
	// weak-copyleft policy (warn) but restricted risk (high), the additive split of policy vs risk.
	if cat, ok := spdxCategory[norm]; ok {
		return riskFromCategory(cat)
	}
	// Deterministic SPDX-family fallback (same engine as classify()'s) so the long tail of
	// the SPDX License List carries a real risk severity instead of unknown/review-manually.
	if fam := familyOf(norm); fam != famUnknown {
		return fam.risk()
	}
	return RiskUnknown
}

// riskFromCategory maps a policy category to its corresponding risk bucket — the coarse
// default used when only the policy table knows an id (notice is the conservative choice
// for permissive, since the category can't distinguish notice/permissive/unencumbered).
func riskFromCategory(c sbom.LicenseCategory) RiskCategory {
	switch c {
	case sbom.LicensePermissive:
		return RiskNotice
	case sbom.LicenseWeakCopyleft:
		return RiskReciprocal
	case sbom.LicenseCopyleft:
		return RiskRestricted
	case sbom.LicenseProprietary:
		return RiskForbidden
	}
	return RiskUnknown
}

// riskByLicense maps a normalized (lowercase, suffix-stripped — see normalizeSPDX) SPDX id
// to its risk category. Keys mirror the spdxCategory table's normalized form. Derived from
// SPDX + Google licenseclassifier categorization (see the type doc); unlisted ids → unknown.
var riskByLicense = map[string]RiskCategory{
	// Forbidden — network copyleft, non-commercial, or source-available bans.
	"agpl-1.0": RiskForbidden, "agpl-3.0": RiskForbidden,
	"cc-by-nc-1.0": RiskForbidden, "cc-by-nc-2.0": RiskForbidden, "cc-by-nc-2.5": RiskForbidden,
	"cc-by-nc-3.0": RiskForbidden, "cc-by-nc-4.0": RiskForbidden,
	"cc-by-nc-nd-3.0": RiskForbidden, "cc-by-nc-nd-4.0": RiskForbidden,
	"cc-by-nc-sa-3.0": RiskForbidden, "cc-by-nc-sa-4.0": RiskForbidden,
	"commons-clause": RiskForbidden,
	"sspl-1.0":       RiskForbidden, "busl-1.1": RiskForbidden, // modern source-available; extend beyond the legacy list
	// Restricted — strong copyleft (mandatory source distribution).
	"gpl-1.0": RiskRestricted, "gpl-2": RiskRestricted, "gpl-2.0": RiskRestricted,
	"gpl-3": RiskRestricted, "gpl-3.0": RiskRestricted,
	"lgpl-2.0": RiskRestricted, "lgpl-2.1": RiskRestricted, "lgpl-3.0": RiskRestricted,
	"osl-1.0": RiskRestricted, "osl-1.1": RiskRestricted, "osl-2.0": RiskRestricted,
	"osl-2.1": RiskRestricted, "osl-3.0": RiskRestricted,
	"cc-by-sa-3.0": RiskRestricted, "cc-by-sa-4.0": RiskRestricted,
	"cc-by-nd-3.0": RiskRestricted, "cc-by-nd-4.0": RiskRestricted,
	"sleepycat": RiskRestricted, "npl-1.0": RiskRestricted, "npl-1.1": RiskRestricted,
	"qpl-1.0": RiskRestricted, "eupl-1.1": RiskRestricted, "eupl-1.2": RiskRestricted,
	"gfdl-1.1": RiskRestricted, "gfdl-1.2": RiskRestricted, "gfdl-1.3": RiskRestricted,
	"cdla-sharing-1.0": RiskRestricted,
	// Reciprocal — weak/file-level copyleft.
	"mpl-1.0": RiskReciprocal, "mpl-1.1": RiskReciprocal, "mpl-2.0": RiskReciprocal,
	"epl-1.0": RiskReciprocal, "epl-2.0": RiskReciprocal,
	"cddl-1.0": RiskReciprocal, "cddl-1.1": RiskReciprocal,
	"cpl-1.0": RiskReciprocal, "ipl-1.0": RiskReciprocal,
	"apsl-1.0": RiskReciprocal, "apsl-1.1": RiskReciprocal, "apsl-1.2": RiskReciprocal, "apsl-2.0": RiskReciprocal,
	"ms-rl": RiskReciprocal, "ruby": RiskReciprocal,
	"ms-pl": RiskReciprocal, // Microsoft Public License — weak copyleft (FSF), matches spdxCategory
	// Notice — permissive with an attribution/notice clause.
	"mit": RiskNotice, "mit-0": RiskNotice,
	"apache-1.0": RiskNotice, "apache-1.1": RiskNotice, "apache-2.0": RiskNotice,
	"bsd-1-clause": RiskNotice, "bsd-2-clause": RiskNotice, "bsd-3-clause": RiskNotice, "bsd-4-clause": RiskNotice,
	"bsd-unspecified":     RiskNotice,
	"bsd-2-clause-netbsd": RiskNotice, "bsd-3-clause-clear": RiskNotice,
	"edl-1.0": RiskNotice, // Eclipse Distribution License — a BSD-3-Clause variant (permissive)
	"isc":     RiskNotice, "afl-2.1": RiskNotice, "afl-3.0": RiskNotice,
	// Artistic is weak-copyleft in spdxCategory (FSF: the clauses are copyleft-ish) → reciprocal,
	// so RiskOf agrees with classify() rather than reading the laxer notice.
	"artistic-1.0": RiskReciprocal, "artistic-2.0": RiskReciprocal, "artistic-2": RiskReciprocal,
	"zlib": RiskNotice, "libpng": RiskNotice, "ncsa": RiskNotice,
	"python-2.0": RiskNotice, "psf-2": RiskNotice, "php-3.0": RiskNotice, "php-3.01": RiskNotice,
	"openssl": RiskNotice, "x11": RiskNotice, "ftl": RiskNotice, "w3c": RiskNotice, "zend-2.0": RiskNotice,
	"bsl-1.0": RiskNotice, "upl-1.0": RiskNotice, "unicode-dfs-2016": RiskNotice, "postgresql": RiskNotice,
	"cc-by-3.0": RiskNotice, "cc-by-4.0": RiskNotice,
	// Unencumbered — public-domain-equivalent.
	"cc0-1.0": RiskUnencumbered, "unlicense": RiskUnencumbered, "0bsd": RiskUnencumbered,
	"public-domain": RiskUnencumbered, "pd": RiskUnencumbered, "blessing": RiskUnencumbered,
	"wtfpl": RiskUnencumbered, // "do what the f*** you want" — public-domain-equivalent, NOT a legal ban
}
