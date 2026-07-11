package advisory

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
}

// AffectedPackage is one advisory→package binding: which ecosystem+package, and the affected version
// ranges + explicit version enumeration (OSV's `affected[]` model). FixedVersion is the first fix.
type AffectedPackage struct {
	Ecosystem    string   // OSV ecosystem ("Go", "npm", "PyPI", "crates.io", "Maven", "RubyGems", "NuGet")
	Package      string   // ecosystem package name (matches the SBOM component name)
	Ranges       []Range  // SEMVER/ECOSYSTEM/GIT version ranges
	Versions     []string // explicit affected versions (OSV affected[].versions)
	FixedVersion string   // first fixed version, for the finding's remediation hint
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
