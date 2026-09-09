package ownadvisory

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// resolveLanguagePURL resolves a CSAF product's LANGUAGE-ecosystem PURL (pkg:npm / pypi / maven / golang /
// gem / nuget / cargo) to the (ecosystem, package, version) key the owned matcher uses. It reuses
// sbom.IdentityFromComponent, the SAME purl -> key logic the SBOM producer applies to a scanned component,
// so a CSAF advisory resolved this way keys IDENTICALLY to the component it must match (Maven groupId:
// artifactId, a Go module path, an npm @scope/name, a PEP 503-folded PyPI name). PURLs are unambiguous, so
// unlike the CPE bridge this is a faithful, not a best-effort, mapping.
//
// It returns ok=false, fail-closed, for:
//   - an rpm PURL (pkg:rpm/...), which is resolved through the RedHat product_tree relationship bridge
//     (resolveProductPURL), not here — an rpm PURL has no distro qualifier in CSAF and would not resolve;
//   - any PURL that does not carry a concrete version, or whose ecosystem the owned matcher has no
//     comparator-backed, faithful key for (IdentityFromComponent returns a non-resolved status).
//
// The version is the concrete version the PURL names; the caller treats it as an explicit affected or fixed
// version, exactly as it does a CPE-resolved version.
func resolveLanguagePURL(purlByProduct map[string]string, productID string) (eco, pkg, version string, ok bool) {
	purl := strings.TrimSpace(purlByProduct[productID])
	if purl == "" || strings.HasPrefix(purl, "pkg:rpm/") {
		return "", "", "", false
	}
	id := sbom.IdentityFromComponent(sbom.Component{PURL: purl})
	if id.Status != sbom.IdentityResolved {
		return "", "", "", false // no concrete version, or an ecosystem without a faithful owned key
	}
	return id.Ecosystem, id.Package, id.Version, true
}
