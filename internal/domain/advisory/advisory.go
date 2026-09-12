package advisory

import "github.com/KKloudTarus/synapse-ce/internal/domain/shared"

// Advisory is one normalized vulnerability advisory in the OWNED store: a stable id, cross-feed
// aliases, severity, and the affected packages each with their version ranges / explicit versions. It is
// the feed-agnostic shape an OSV/CSAF/NVD ingester normalizes into, and the unit the owned matcher +
// DetectionSource query – so detection runs against our store, not a third-party service.
type Advisory struct {
	ID         string            // the advisory's primary id (e.g. "GHSA-…" or "CVE-…")
	Aliases    []string          // cross-feed ids (CVE/GHSA/…), for reconciliation + reporting
	Summary    string            // short description (rendered, not LLM-authored)
	CVSSVector string            // primary CVSS vector when known
	CVSSScore  float64           // computed base score
	Affected   []AffectedPackage // the packages this advisory affects
	CPEs       []CPEMatch        // NVD/CSAF product applicability retained for CPE correlation
	// Withdrawn marks an advisory the upstream feed retracted (OSV "withdrawn", NVD REJECTED). A
	// withdrawn advisory is a guaranteed false positive, so the matcher must never emit a finding for
	// it. omitempty keeps it out of existing stored blobs. Set by the parser (ownadvisory.ParseOSV)
	// and by the materializer projection from the canonical Status.
	Withdrawn bool `json:"Withdrawn,omitempty"`
	// Severity is a curated qualitative band carried from the feed (GHSA/OSV
	// database_specific.severity, an NVD/distro label) for advisories that have no CVSS vector to
	// score. omitempty; the matcher prefers a score-derived band and falls back to this, mirroring the
	// live OSV adapter where a curated label overrides the computed band. Set by ownadvisory.ParseOSV.
	Severity shared.Severity `json:"Severity,omitempty"`

	// Risk-priority signals projected from the canonical advisory so an OFFLINE scan can order findings by
	// exploitability without the live risk enricher's network fetch (CISA KEV / FIRST EPSS): KEV (actively
	// exploited, ranks above all else), EPSS (0..1 exploit-prediction probability) and its percentile, and
	// PublicExploit (a public exploit exists). The materializer sets these from the canonical merge; the
	// owned matcher carries KEV/EPSS onto the finding. omitempty keeps them out of existing stored blobs and
	// out of an advisory that carries no risk signal. The online risk enricher still runs and only RAISES
	// these, so it refreshes them when the network is available and never lowers a corpus value.
	KEV            bool    `json:"KEV,omitempty"`
	EPSS           float64 `json:"EPSS,omitempty"`
	EPSSPercentile float64 `json:"EPSSPercentile,omitempty"`
	PublicExploit  bool    `json:"PublicExploit,omitempty"`

	// CWEs are the weakness ids the feed assigns (e.g. "CWE-79"), and References are the advisory's reference
	// URLs, carried verbatim from the source feed (GHSA today) so a report can cite the weakness class and the
	// upstream links the OSV mirror drops. Both are unioned across feeds by the materializer. omitempty keeps
	// them out of existing stored blobs and out of an advisory that carries neither.
	CWEs       []string `json:"CWEs,omitempty"`
	References []string `json:"References,omitempty"`
}

type CPEMatch struct {
	Criteria              string
	Vulnerable            bool
	VersionStartIncluding string
	VersionStartExcluding string
	VersionEndIncluding   string
	VersionEndExcluding   string
}

// AffectedPackage is one advisory→package binding: which ecosystem+package, and the affected version
// ranges + explicit version enumeration (OSV's `affected[]` model). FixedVersion is the first fix.
type AffectedPackage struct {
	Ecosystem    string   // OSV ecosystem ("Go", "npm", "PyPI", "crates.io", "Maven", "RubyGems", "NuGet")
	Package      string   // ecosystem package name (matches the SBOM component name)
	Ranges       []Range  // SEMVER/ECOSYSTEM/GIT version ranges
	Versions     []string // explicit affected versions (OSV affected[].versions)
	FixedVersion string   // first fixed version, for the finding's remediation hint
	// AffectedSymbols are the specific vulnerable functions/symbols this advisory marks for this package, as
	// "importPath.Symbol" (the form the Go vuln DB publishes via ecosystem_specific.imports and the form the
	// reachability engine matches against a call graph). Carried on the OWNED store so an OFFLINE scan drives
	// symbol-level Tier-2 reachability, not only the live OSV path. omitempty keeps it out of stored blobs
	// that carry none.
	AffectedSymbols []string `json:"AffectedSymbols,omitempty"`
}

// AffectedSymbolsFor returns the deduplicated affected symbols this advisory marks for (ecosystem, name),
// aggregated across every name-matching affected block REGARDLESS of version. It answers "what symbols does
// this advisory list for this package anywhere", so it is version-agnostic. Do NOT use it to attach symbols
// to a version-specific finding: use MatchDetails, which restricts symbols to the blocks that actually match
// the component's version (unioning across versions here would attach another version's symbols and seed a
// false reachable-symbol claim). Empty when the advisory carries no symbol data for that package (the common
// case outside the Go vuln DB and RustSec).
func (a Advisory) AffectedSymbolsFor(ecosystem, name string) []string {
	var out []string
	for _, aff := range a.Affected {
		if aff.Ecosystem == ecosystem && aff.Package == name {
			out = append(out, aff.AffectedSymbols...)
		}
	}
	return uniqueSorted(out)
}

// FixedVersions returns the deduplicated, non-empty "fixed" versions an affected package declares — the
// explicit FixedVersion plus every range's fixed event — as remediation-fix candidates.
func FixedVersions(affected AffectedPackage) []string {
	values := []string{affected.FixedVersion}
	for _, current := range affected.Ranges {
		for _, event := range current.Events {
			values = append(values, event.Fixed)
		}
	}
	return uniqueSorted(values)
}

// Match reports whether the advisory affects (ecosystem, name) at version, and returns the matched block's
// fixed version. It runs the owned matcher (Affected = explicit-versions OR semver-range) against every
// affected block for that exact ecosystem+package – so it is a deterministic, third-party-free verdict.
func (a Advisory) Match(ecosystem, name, version string) (bool, string) {
	matched, fixed, _ := a.MatchDetails(ecosystem, name, version)
	return matched, fixed
}

// MatchDetails is the version-correct match: it reports whether the advisory affects (ecosystem, name) at
// version and returns the first matching block's fixed version TOGETHER with the affected symbols drawn ONLY
// from the affected blocks whose range actually includes version. This is the atomic replacement for calling
// Match and AffectedSymbolsFor separately. OSV permits the same package in several affected[] blocks (distinct
// version ranges, each carrying its own ecosystem_specific symbols), so unioning symbols across every
// name-matching block — as AffectedSymbolsFor does — can attach a symbol that belongs to a DIFFERENT version
// to this finding, which would seed a false "reachable vulnerable symbol" for a version the symbol does not
// apply to. Restricting symbols to the version-matching blocks removes that false-evidence path (a #1-bar
// no-false-positive requirement before symbol-level reachability runs on any ecosystem). Symbols are
// deduplicated and sorted; fixed matches Match (the first version-matching block's FixedVersion).
func (a Advisory) MatchDetails(ecosystem, name, version string) (matched bool, fixed string, symbols []string) {
	var syms []string
	for _, aff := range a.Affected {
		if aff.Ecosystem != ecosystem || aff.Package != name {
			continue
		}
		if Affected(aff.Ecosystem, version, aff.Ranges, aff.Versions) {
			if !matched {
				matched, fixed = true, aff.FixedVersion
			}
			syms = append(syms, aff.AffectedSymbols...)
		}
	}
	return matched, fixed, uniqueSorted(syms)
}
