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
	case "deb", "apk", "rpm":
		identity.Ecosystem = distroEcosystem(typ, purl)
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

func distroEcosystem(typ, purl string) string {
	qualifiers := ""
	if i := strings.IndexByte(purl, '?'); i >= 0 {
		qualifiers = purl[i+1:]
	}
	values, err := url.ParseQuery(qualifiers)
	if err != nil {
		return ""
	}
	distro := values.Get("distro")
	id, version, ok := strings.Cut(strings.ToLower(distro), "-")
	if !ok || id == "" || version == "" {
		return ""
	}
	parts := strings.Split(version, ".")
	switch typ {
	case "deb":
		switch id {
		case "debian":
			return "Debian:" + parts[0]
		case "ubuntu":
			if len(parts) >= 2 {
				return "Ubuntu:" + parts[0] + "." + parts[1]
			}
		}
	case "apk":
		if id == "alpine" && len(parts) >= 2 {
			return "Alpine:v" + parts[0] + "." + parts[1]
		}
	case "rpm":
		major := parts[0]
		switch id {
		case "rocky":
			return "Rocky Linux:" + major
		case "almalinux", "alma":
			return "AlmaLinux:" + major
		case "ol", "oracle":
			return "Oracle Linux:" + major
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
