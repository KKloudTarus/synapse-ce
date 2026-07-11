package ownadvisory

import (
	"regexp"
	"strings"
)

// pep503Sep collapses runs of - _. per PyPI's PEP 503 normalization.
var pep503Sep = regexp.MustCompile(`[-_.]+`)

// canonicalName normalizes a package name to the ECOSYSTEM-CANONICAL form used as the advisory-store key,
// applied on BOTH sides of the match – when the ingester stores an advisory's package name AND when the
// DetectionSource looks a component up – so they meet at the same key regardless of how either side spelled
// it. This closes the silent-missed-CVE gap where OSV PyPI advisories carry a non-normalized name (e.g.
// "Django", "ruamel.yaml") while the SBOM component name is PEP 503-normalized ("django", "ruamel-yaml").
//
// PyPI: PEP 503 (lower-case + collapse -_. to a single -). Other ecosystems are already canonical from both
// producers today (npm @scope/name verbatim, Go module path, Maven groupId:artifactId, Cargo crate id), so
// they pass through unchanged; add a case here if a future ecosystem needs folding.
func canonicalName(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI":
		return strings.ToLower(pep503Sep.ReplaceAllString(name, "-"))
	}
	return name
}
