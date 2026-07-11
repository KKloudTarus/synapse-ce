// Package ownadvisory is the OWNED advisory DetectionSource: it matches an SBOM
// against Synapse's own normalized advisory store using the owned matcher (internal/domain/advisory),
// producing the same vulnerability.RawFinding the OSV/Grype adapters do – but WITHOUT querying any
// third-party service. It is the detection-independence counterpart to the owned SBOM producer:
// live OSV + Grype stay wired as a cross-check, but a scan can run fully offline against the owned store.
package ownadvisory

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// sourceName identifies this detection source in RawFinding provenance + the correlator.
const sourceName = "advisory-store"

// Source matches SBOM components against the owned advisory store.
type Source struct {
	store ports.AdvisoryStore
}

// New returns a detection source over the given owned advisory store.
func New(store ports.AdvisoryStore) *Source { return &Source{store: store} }

var _ ports.DetectionSource = (*Source)(nil)

// Name identifies the source.
func (s *Source) Name() string { return sourceName }

// Scan matches every component with a resolvable version against the owned store and emits a RawFinding
// per affected advisory. A component whose PURL ecosystem is unmapped, or with no resolvable version, is
// skipped (it can't be soundly matched) – never a false hit. A store error fails the WHOLE scan (the SCA
// pipeline aborts; live OSV/Grype, when also wired, are the cross-check across scans, not a within-scan
// fallback). NOTE (no-silent-gap): an offline-only deployment should surface skipped-component
// coverage via the pipeline's Completeness; that rides on the offline-mode composition-root wiring.
func (s *Source) Scan(ctx context.Context, doc *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	if s.store == nil {
		return nil, fmt.Errorf("%w: advisory store not configured", shared.ErrValidation) // fail loud, never a silent nil-deref
	}
	if doc == nil {
		return nil, nil
	}
	var out []vulnerability.RawFinding
	for _, c := range doc.Components {
		eco := osvEcosystem(purlType(c.PURL))
		if eco == "" {
			// OS-package PURL (deb/apk/rpm): derive the release-versioned OSV ecosystem
			// ("Debian:9", "Alpine:v3.18") from the distro qualifier (Epic B).
			eco = osDistroEcosystem(c.PURL)
		}
		if eco == "" || c.Name == "" || !sbom.IsResolvedVersion(c.Version) {
			continue
		}
		// Normalize to the ecosystem-canonical key on the lookup side too, so a component name that isn't
		// already normalized (e.g. a Syft-produced PyPI name) still meets the stored advisory key.
		name := canonicalName(eco, c.Name)
		advs, err := s.store.ByPackage(ctx, eco, name)
		if err != nil {
			return nil, err
		}
		for _, a := range advs {
			affected, fixed := a.Match(eco, name, c.Version)
			if !affected {
				continue
			}
			out = append(out, rawFinding(a, c, fixed))
		}
	}
	return out, nil
}

// rawFinding builds the normalized finding from a matched advisory + component.
func rawFinding(a advisory.Advisory, c sbom.Component, fixed string) vulnerability.RawFinding {
	rf := vulnerability.RawFinding{
		Source:       sourceName,
		AdvisoryID:   preferCVE(a.ID, a.Aliases),
		Aliases:      append([]string{a.ID}, a.Aliases...),
		Component:    c.Name,
		Version:      c.Version,
		Severity:     shared.SeverityUnknown,
		CVSSVector:   a.CVSSVector,
		CVSSScore:    a.CVSSScore,
		FixedVersion: fixed,
		Description:  a.Summary,
	}
	// Severity from the score; if the store has the vector but no precomputed score, derive it (an ingester
	// may store only the vector) – mirrors the OSV adapter so a vuln found by both correlates to one band.
	score := a.CVSSScore
	if score == 0 && a.CVSSVector != "" {
		if s, ok := shared.CVSSv3BaseScore(a.CVSSVector); ok {
			score = s
			rf.CVSSScore = s
		}
	}
	if score > 0 {
		rf.Severity = shared.SeverityFromScore(score)
	}
	return rf
}

// preferCVE returns a CVE id when one is present (the id or an alias), else the primary id – mirroring the
// OSV adapter so the owned source's AdvisoryID dedupes against the live sources in Correlate.
func preferCVE(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return id
}

// purlType extracts the PURL type from "pkg:<type>/…" (the segment after "pkg:" up to the first "/").
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}

// purlQualifier extracts a PURL qualifier value (the "?k=v&…" part), e.g. distro from
// "pkg:deb/debian/openssl@1.1?arch=amd64&distro=debian-9" → "debian-9". Returns "" if absent.
func purlQualifier(purl, key string) string {
	i := strings.IndexByte(purl, '?')
	if i < 0 {
		return ""
	}
	for _, kv := range strings.Split(purl[i+1:], "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// osDistroEcosystem derives the release-versioned ecosystem key for an OS-package PURL from its "distro"
// qualifier (Syft emits e.g. distro=debian-9 / ubuntu-22.04 / alpine-3.18.12). Debian keys by major
// ("Debian:<major>", from OSV); Alpine by "Alpine:v<major>.<minor>" (OSV); Ubuntu by its full VERSION_ID
// ("Ubuntu:<version>") – the canonical key the OWNED Ubuntu OVAL feed writes, which sidesteps OSV's
// awkward :LTS/:Pro variants because we own both the feed and this mapping. The RPM distros stay deferred
// (return "" → skip → never a false match), though their comparators exist for any future bridge.
func osDistroEcosystem(purl string) string {
	distro := purlQualifier(purl, "distro")
	if distro == "" {
		return ""
	}
	id, ver, ok := strings.Cut(distro, "-")
	if !ok || ver == "" {
		return ""
	}
	switch purlType(purl) {
	case "deb":
		if id == "debian" {
			major := ver
			if i := strings.IndexByte(ver, '.'); i >= 0 {
				major = ver[:i]
			}
			if major != "" {
				return "Debian:" + major
			}
		}
		if id == "ubuntu" {
			// Ubuntu OVAL keys by the release major.minor (e.g. "Ubuntu:22.04"), matching ParseUbuntuOVAL.
			// Tolerate a point-release qualifier (ubuntu-22.04.1) by keying on major.minor so it can't
			// desync from the feed's key.
			parts := strings.SplitN(ver, ".", 3)
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				return "Ubuntu:" + parts[0] + "." + parts[1]
			}
			return "Ubuntu:" + ver
		}
	case "apk":
		if id == "alpine" {
			parts := strings.SplitN(ver, ".", 3)
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				return "Alpine:v" + parts[0] + "." + parts[1]
			}
		}
	case "rpm":
		// The rpm distros OSV keys by "<Name>:<major>". RHEL/CentOS/Fedora use module-qualified or uncertain
		// keys (e.g. "Red Hat:enterprise_linux:9::baseos"), so they are intentionally NOT mapped here – the
		// cataloger flags them DistroResolved=false so an unmatched OS-package set is surfaced, never silent.
		major := ver
		if i := strings.IndexByte(ver, '.'); i >= 0 {
			major = ver[:i]
		}
		if major == "" {
			return ""
		}
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

// osvEcosystem maps a PURL type to the OSV ecosystem the store is keyed by. Unmapped → "" (skip – never a
// false match). Covers the ecosystems the owned SBOM producer emits.
func osvEcosystem(purlType string) string {
	switch purlType {
	case "golang":
		return "Go"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "cargo":
		return "crates.io"
	case "maven":
		return "Maven"
	case "gem":
		return "RubyGems"
	case "nuget":
		return "NuGet"
	case "hex":
		return "Hex" // Elixir/Erlang; OSV has a Hex ecosystem. Explicit-version matches today –
		// Hex range ordering (a comparator in advisory.schemeFor) is a follow-up, so ranges are skipped (safe).
	}
	return ""
}
