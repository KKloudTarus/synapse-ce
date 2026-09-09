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
// aggregated across every matching affected block. Empty when the advisory carries no symbol data for that
// package (the common case outside the Go vuln DB). The caller keys with the same ecosystem-canonical name it
// used to match the package, so the symbol lookup meets the same stored key.
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
	for _, aff := range a.Affected {
		if aff.Ecosystem != ecosystem || aff.Package != name {
			continue
		}
		if Affected(aff.Ecosystem, version, aff.Ranges, aff.Versions) {
			return true, aff.FixedVersion
		}
	}
	return false, ""
}
