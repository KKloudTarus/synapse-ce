package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ComponentIdentity is the canonical package key used by advisory matching.
// Status is "resolved" for matchable package identities and "unsupported" or
// "ambiguous" when the source does not provide enough trustworthy information.
type ComponentIdentity struct {
	Ecosystem   string
	Package     string
	Version     string
	Fingerprint string
	Status      string
	Reason      string
}

const (
	IdentityResolved    = "resolved"
	IdentityUnsupported = "unsupported"
	IdentityAmbiguous   = "ambiguous"
)

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// IdentityFromComponent derives the exact ecosystem/package contract consumed by
// advisory.Advisory.Match. It fails closed for malformed or unsupported PURLs.
func IdentityFromComponent(component Component) ComponentIdentity {
	identity := ComponentIdentity{Version: strings.TrimSpace(component.Version), Status: IdentityUnsupported}
	purl := strings.TrimSpace(component.PURL)
	if !strings.HasPrefix(purl, "pkg:") {
		identity.Reason = "missing_or_malformed_purl"
		return identity
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 || slash == len(rest)-1 {
		identity.Reason = "malformed_purl"
		return identity
	}
	typ := strings.ToLower(rest[:slash])
	body := rest[slash+1:]
	base := body
	if i := strings.IndexAny(base, "?#"); i >= 0 {
		base = base[:i]
	}
	at := strings.LastIndexByte(base, '@')
	if at < 0 || at == len(base)-1 {
		identity.Reason = "missing_purl_version"
		return identity
	}
	rawName := base[:at]
	purlVersion, err := url.PathUnescape(base[at+1:])
	decodedName, nameErr := url.PathUnescape(rawName)
	if err != nil || nameErr != nil || strings.TrimSpace(decodedName) == "" {
		identity.Reason = "malformed_purl_encoding"
		return identity
	}
	if identity.Version == "" {
		identity.Version = purlVersion
	}
	if identity.Version != purlVersion {
		identity.Status = IdentityAmbiguous
		identity.Reason = "component_and_purl_versions_differ"
		return identity
	}

	switch typ {
	case "maven":
		parts := strings.Split(decodedName, "/")
		if len(parts) < 2 || parts[len(parts)-1] == "" {
			identity.Reason = "maven_coordinate_incomplete"
			return identity
		}
		identity.Ecosystem = "Maven"
		identity.Package = strings.Join(parts[:len(parts)-1], ".") + ":" + parts[len(parts)-1]
	case "golang":
		identity.Ecosystem = "Go"
		identity.Package = decodedName
	case "npm":
		identity.Ecosystem = "npm"
		identity.Package = decodedName
	case "pypi":
		identity.Ecosystem = "PyPI"
		identity.Package = pypiSeparators.ReplaceAllString(strings.ToLower(decodedName), "-")
	case "cargo":
		identity.Ecosystem = "crates.io"
		identity.Package = decodedName
	case "gem":
		identity.Ecosystem = "RubyGems"
		identity.Package = decodedName
	case "nuget":
		identity.Ecosystem = "NuGet"
		identity.Package = decodedName
	case "hex":
		// Elixir Hex: OSV ecosystem "Hex", package is the bare hex name. The range comparator for Hex is
		// already wired (advisory.schemeFor), so resolving the identity makes the match reachable end to end.
		identity.Ecosystem = "Hex"
		identity.Package = decodedName
	case "composer":
		// PHP Composer -> OSV ecosystem "Packagist"; the package is "vendor/name" (OSV keys Packagist that way).
		identity.Ecosystem = "Packagist"
		identity.Package = decodedName
	case "pub":
		// Dart Pub: OSV ecosystem "Pub", package is the bare pub name.
		identity.Ecosystem = "Pub"
		identity.Package = decodedName
	case "deb", "apk", "rpm":
		identity.Ecosystem = distroEcosystem(typ, purl, component.verifiedRPMOrigin)
		identity.Package = decodedName[strings.LastIndexByte(decodedName, '/')+1:]
		if identity.Ecosystem == "" {
			identity.Reason = "distro_release_missing_or_unsupported"
			return identity
		}
	default:
		identity.Reason = "unsupported_purl_type"
		return identity
	}
	if identity.Ecosystem == "" || identity.Package == "" || !IsResolvedVersion(identity.Version) {
		identity.Status = IdentityAmbiguous
		if identity.Reason == "" {
			identity.Reason = "package_or_version_unresolved"
		}
		return identity
	}
	identity.Status = IdentityResolved
	identity.Fingerprint = ComponentFingerprint(identity, purl)
	return identity
}

// ComponentFingerprint is stable across SBOM snapshots for the same package,
// version, and PURL-qualified identity.
func ComponentFingerprint(identity ComponentIdentity, purl string) string {
	canonical := strings.Join([]string{identity.Ecosystem, identity.Package, identity.Version, strings.TrimSpace(purl)}, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

// distroEcosystem reads the distro qualifier from an OS-package PURL and maps it to the advisory ecosystem via
// the shared DistroEcosystem, so this inventory identity and the scan-side matcher key a component identically.
func distroEcosystem(typ, purl, verifiedOrigin string) string {
	qualifiers := ""
	if i := strings.IndexByte(purl, '?'); i >= 0 {
		qualifiers = purl[i+1:]
	}
	values, err := url.ParseQuery(qualifiers)
	if err != nil {
		return ""
	}
	return DistroEcosystemWithOrigin(typ, values.Get("distro"), verifiedOrigin)
}

// DistroEcosystem maps an OS package's PURL type and its Syft "distro" qualifier (e.g. "rpm", "amzn-2") to the
// advisory ecosystem key ("Amazon Linux:2"), the exact key the owned distro feed writes and the matcher keys
// on. The inventory identity and scan-side matcher share this mapping through
// DistroEcosystemForComponent, which also accepts scanner-local CentOS 7 origin. The
// qualifier is lowercased first (Syft emits lowercase; a case-variant keys the same). An unmapped distro
// (CentOS Stream / CentOS >=8, openSUSE Tumbleweed) or a malformed qualifier returns "" (cataloged for
// inventory, never keyed to an advisory ecosystem, so never a false match). CentOS Linux 7 needs a separate
// RHEL-base provenance assertion and therefore stays unmapped here.
func DistroEcosystem(purlType, distro string) string {
	return DistroEcosystemWithOrigin(purlType, distro, "")
}

// WithVerifiedRPMOrigin records scanner-local provenance after cryptographic
// verification. It is intentionally not encoded in a PURL, so imported SBOM
// content cannot assert an origin and unlock a distro approximation.
func WithVerifiedRPMOrigin(component Component, origin string) Component {
	component.verifiedRPMOrigin = strings.ToLower(strings.TrimSpace(origin))
	return component
}

// VerifiedRPMOrigin is process-local evidence carried by a cataloged RPM. It is
// never populated from serialized SBOM fields or a PURL qualifier.
func VerifiedRPMOrigin(component Component) string {
	return component.verifiedRPMOrigin
}

// TransferVerifiedRPMOrigin preserves the earlier producer's SBOM metadata when
// the rootfs catalog later proves the same CentOS 7 package's origin. A mismatch
// cannot promote the earlier component into the RHEL-derived advisory scope.
func TransferVerifiedRPMOrigin(existing, cataloged Component) Component {
	if existing.Name != cataloged.Name || existing.Version != cataloged.Version || existing.PURL != cataloged.PURL ||
		cataloged.verifiedRPMOrigin != "rhel-base" ||
		DistroEcosystemForComponent(cataloged) != "Red Hat:7" ||
		distroEcosystem(purlTypeFromPURL(existing.PURL), existing.PURL, "rhel-base") != "Red Hat:7" {
		return existing
	}
	existing.verifiedRPMOrigin = "rhel-base"
	return existing
}

// DistroEcosystemForComponent derives the matching ecosystem while honoring
// process-local provenance. Callers receiving an imported PURL get no origin.
func DistroEcosystemForComponent(component Component) string {
	return distroEcosystem(purlTypeFromPURL(component.PURL), component.PURL, component.verifiedRPMOrigin)
}

func purlTypeFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}

// DistroEcosystemWithOrigin applies the same mapping when the producer can also
// prove package origin. CentOS Linux 7 is a RHEL-derived approximation only for
// a base package carrying the exact rhel-base assertion. A distro label and an
// RPM name/version alone are insufficient: third-party RPMs can collide with a
// RHEL package identity. Any absent or different origin remains unsupported.
func DistroEcosystemWithOrigin(purlType, distro, origin string) string {
	distro = strings.ToLower(distro)
	origin = strings.ToLower(strings.TrimSpace(origin))
	if distro == "" {
		return ""
	}
	// openSUSE Leap carries a two-segment id (Syft distro=opensuse-leap-15.6), which the id/ver Cut below
	// mis-splits, so key it explicitly: "openSUSE:<major.minor>", the key the owned openSUSE Leap OVAL feed writes.
	if purlType == "rpm" {
		if v := strings.TrimPrefix(distro, "opensuse-leap-"); v != distro && v != "" {
			p := strings.SplitN(v, ".", 3)
			if len(p) >= 2 && p[0] != "" && p[1] != "" {
				return "openSUSE:" + p[0] + "." + p[1]
			}
			return "openSUSE:" + v
		}
		// SUSE Linux Enterprise (Syft distro=sles-15.6): key "SUSE:<major>.<sp>" per service pack, the key the
		// owned SLE OVAL feed writes. Keying by bare major would conflate service packs — a SP6 fixed NEVR must
		// not match a SP5 package — so the minor is preserved, exactly like openSUSE Leap above.
		if v := strings.TrimPrefix(distro, "sles-"); v != distro && v != "" {
			p := strings.SplitN(v, ".", 3)
			if len(p) >= 2 && p[0] != "" && p[1] != "" {
				return "SUSE:" + p[0] + "." + p[1]
			}
			return "SUSE:" + v
		}
	}
	// Wolfi and Chainguard are rolling apk distros with no release version, so the whole family name is the key
	// (matching the owned secdb feed and the apk comparator). Handle both a bare "wolfi" and a "wolfi-<date>"
	// qualifier before the id/ver Cut, which would otherwise reject the version-less form.
	if purlType == "apk" {
		fam := distro
		if id, _, ok := strings.Cut(distro, "-"); ok {
			fam = id
		}
		switch fam {
		case "wolfi":
			return "Wolfi"
		case "chainguard":
			return "Chainguard"
		}
	}
	id, ver, ok := strings.Cut(distro, "-")
	if !ok || id == "" || ver == "" {
		return ""
	}
	major := ver
	if i := strings.IndexByte(ver, '.'); i >= 0 {
		major = ver[:i]
	}
	switch purlType {
	case "deb":
		switch id {
		case "debian":
			if major != "" {
				return "Debian:" + major
			}
		case "ubuntu":
			// Ubuntu OVAL keys by release major.minor; tolerate a point release (ubuntu-22.04.1) by keying on
			// major.minor, and fall back to the raw version for an unexpected shape.
			p := strings.SplitN(ver, ".", 3)
			if len(p) >= 2 && p[0] != "" && p[1] != "" {
				return "Ubuntu:" + p[0] + "." + p[1]
			}
			return "Ubuntu:" + ver
		}
	case "apk":
		if id == "alpine" {
			p := strings.SplitN(ver, ".", 3)
			if len(p) >= 2 && p[0] != "" && p[1] != "" {
				return "Alpine:v" + p[0] + "." + p[1]
			}
		}
	case "rpm":
		if major == "" {
			return ""
		}
		// The rpm distros key "<Name>:<major>". SUSE Linux Enterprise (sles-*) is keyed by the major.minor
		// branch above. Each mapped id keys the ecosystem its own feed writes.
		switch id {
		case "rhel", "redhat":
			return "Red Hat:" + major
		case "rocky":
			return "Rocky Linux:" + major
		case "almalinux", "alma":
			return "AlmaLinux:" + major
		case "ol", "oracle":
			return "Oracle Linux:" + major
		case "amzn", "amazon":
			return "Amazon Linux:" + major
		case "fedora":
			return "Fedora:" + major
		case "centos":
			// CentOS Linux 7 is a RHEL-derived approximation only for a base RPM
			// whose producer supplied rhel-base provenance. A third-party package can
			// reuse a RHEL name and NEVR, so the distro label alone cannot establish
			// coverage. CentOS >=8 remains unsupported because Stream and the retired
			// CentOS Linux 8 share this identity and Stream runs ahead of RHEL.
			if major == "7" && origin == "rhel-base" {
				return "Red Hat:7"
			}
		}
	}
	return ""
}

// SortIdentities gives deterministic ordering for inventory and reconciliation.
func SortIdentities(values []ComponentIdentity) {
	sort.Slice(values, func(i, j int) bool {
		left := values[i].Ecosystem + "\x00" + values[i].Package + "\x00" + values[i].Version + "\x00" + values[i].Fingerprint
		right := values[j].Ecosystem + "\x00" + values[j].Package + "\x00" + values[j].Version + "\x00" + values[j].Fingerprint
		return left < right
	})
}
