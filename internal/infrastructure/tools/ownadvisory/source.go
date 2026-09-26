// Package ownadvisory is the OWNED advisory DetectionSource: it matches an SBOM
// against Synapse's own normalized advisory store using the owned matcher (internal/domain/advisory),
// producing the same vulnerability.RawFinding the OSV/Grype adapters do – but WITHOUT querying any
// third-party service. It is the detection-independence counterpart to the owned SBOM producer:
// live OSV + Grype stay wired as a cross-check, but a scan can run fully offline against the owned store.
package ownadvisory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

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
	store   ports.AdvisoryStore
	overlay SymbolOverlay
	mu      sync.Mutex // guards provDB (written during Scan, read by Provenance)
	provDB  string     // "<count> advisories@<date>" corpus-freshness marker, captured during the last Scan
}

// New returns a detection source over the given owned advisory store.
func New(store ports.AdvisoryStore) *Source { return &Source{store: store} }

// WithSymbolOverlay attaches a curated advisory-id -> affected-symbols overlay, merged onto each finding's
// AffectedSymbols so advisories whose feed carries no symbols (non-Go, NVD/CSAF-only) can still drive
// symbol-level reachability. nil disables it. Returns the Source for chaining.
func (s *Source) WithSymbolOverlay(o SymbolOverlay) *Source { s.overlay = o; return s }

// overlaySymbols returns the curated overlay symbols for an advisory, looked up by its primary id and every
// alias (so an overlay keyed by the CVE reaches a finding whose primary id is the GHSA, and vice versa).
func (s *Source) overlaySymbols(a advisory.Advisory) []string {
	if s.overlay == nil {
		return nil
	}
	var out []string
	out = append(out, s.overlay.symbolsFor(a.ID)...)
	for _, alias := range a.Aliases {
		out = append(out, s.overlay.symbolsFor(alias)...)
	}
	return out
}

var _ ports.DetectionSource = (*Source)(nil)

// Name identifies the source.
func (s *Source) Name() string { return sourceName }

// Provenance reports the owned source's corpus-freshness marker (D1.7). The version is empty (there is no
// tool binary, this is an in-process matcher); the db marker is "<count> advisories@<date>" from the last
// Scan, which the SCA freshness policy parses (the trailing "@<date>") to warn when the corpus is stale and
// which the report lists as this feed's provenance. Empty when the store cannot report freshness or is
// empty, so no false freshness claim is made. Implements ports.SourceProvenance.
func (s *Source) Provenance() (version, dbVersion string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return "", s.provDB
}

// CoveredEcosystems reports the distinct ecosystems the owned advisory store has any advisory for, so the SCA
// detection-readiness guard can tell whether an OS-package's distro is genuinely covered by the owned corpus
// or is a silent gap (the check that lets Grype leave the default detection set without turning an unsynced
// distro feed into a false clean posture). ok is false when the backing store cannot report coverage (the
// file store), so the guard falls back to its coarse any-source-has-data check.
func (s *Source) CoveredEcosystems(ctx context.Context) (covered map[string]bool, ok bool, err error) {
	c, capable := s.store.(ports.AdvisoryEcosystemCoverage)
	if !capable {
		return nil, false, nil
	}
	covered, err = c.CoveredEcosystems(ctx)
	if err != nil {
		return nil, false, err
	}
	return covered, true, nil
}

// captureFreshness queries the store's corpus freshness (if it supports it) and records the marker. A store
// that does not implement the capability, an error, or an empty corpus leaves the marker empty (no false
// freshness). It runs once per Scan; the query is a single indexed MAX/COUNT, cheap on the scan path.
func (s *Source) captureFreshness(ctx context.Context) {
	fr, ok := s.store.(ports.AdvisoryCorpusFreshness)
	if !ok {
		return
	}
	latest, count, err := fr.AdvisoryFreshness(ctx)
	marker := ""
	if err == nil && count > 0 && !latest.IsZero() {
		marker = fmt.Sprintf("%d advisories@%s", count, latest.UTC().Format("2006-01-02"))
	}
	s.mu.Lock()
	s.provDB = marker
	s.mu.Unlock()
}

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
	s.captureFreshness(ctx) // record the corpus-freshness marker so a stale owned store warns (D1.7)
	// A withdrawn advisory is a guaranteed false positive; skip it on every path.
	// cpeStore is the same store when it also serves NVD/CSAF CPE applicability (the Postgres repo does).
	cpeStore, hasCPE := s.store.(ports.CPEAdvisoryStore)
	var out []vulnerability.RawFinding
	emitted := map[string]struct{}{}
	emit := func(a advisory.Advisory, c sbom.Component, fixed string, symbols []string, matched *sbom.ComponentIdentity) {
		key := a.ID + "\x00" + c.PURL // one finding per (advisory, component), so package + CPE hits don't double
		if _, done := emitted[key]; done {
			return
		}
		emitted[key] = struct{}{}
		if ov := s.overlaySymbols(a); len(ov) > 0 {
			symbols = dedupSymbols(append(append([]string(nil), symbols...), ov...))
		}
		out = append(out, rawFinding(a, c, fixed, symbols, matched))
	}
	for _, c := range doc.Components {
		// 1) Package-key matching against OSV/distro ecosystems.
		eco := osvEcosystem(purlType(c.PURL))
		if eco == "" {
			// OS-package PURL (deb/apk/rpm): derive the release-versioned OSV ecosystem
			// ("Debian:9", "Alpine:v3.18") from the distro qualifier (Epic B).
			eco = sbom.DistroEcosystemForComponent(c)
		}
		// For rpm components, fold the PURL "epoch=" qualifier into the version and percent-decode it so it
		// matches the feed's canonical EVR (the RedHat CSAF feed does the same). Decoding is idempotent for an
		// already-decoded version and guards against a producer that carries the encoded PURL version verbatim
		// (e.g. a module build's "%2B"). An AppStream module build's stream is a parallel version line, so it is
		// excluded from the linear-range distro matcher (the feed emits no modular range either); it can still
		// match via CPE below. Other ecosystems compare the version as-is.
		matchVersion := c.Version
		distroPackageMatchable := true
		if purlType(c.PURL) == "rpm" {
			matchVersion = rpmCanonicalEVR(decodePURLSegment(c.Version), decodePURLSegment(purlQualifier(c.PURL, "epoch")))
			if isModularEVR(matchVersion) {
				distroPackageMatchable = false
			}
		}
		if distroPackageMatchable && eco != "" && c.Name != "" && sbom.IsResolvedVersion(c.Version) {
			// The component's own architecture, from the PURL "arch=" qualifier. It is decoded for the same
			// reason the version is, and it gates architecture-scoped affected blocks in MatchDetails. An
			// absent qualifier stays empty, which cannot satisfy an architecture-scoped block: we would be
			// unable to prove the installed package is inside the vendor's architecture set, and assuming it
			// is would reintroduce the cross-architecture over-match. Architecture-blind sources carry no
			// constraint at all and keep matching exactly as before.
			componentArch := decodePURLSegment(purlQualifier(c.PURL, "arch"))
			// matchName queries the store for (ecosystem, name) and emits any advisory that hits version.
			matchName := func(lookupEco, name, version string) error {
				advs, err := s.store.ByPackage(ctx, lookupEco, name)
				if err != nil {
					return err
				}
				for _, a := range advs {
					if a.Withdrawn {
						continue
					}
					// MatchDetails (not Match + AffectedSymbolsFor) so the finding carries ONLY the symbols of the
					// affected blocks that actually match this version.
					if affected, fixed, symbols := a.MatchDetails(lookupEco, name, version, componentArch); affected {
						emit(a, c, fixed, symbols, &sbom.ComponentIdentity{Ecosystem: lookupEco, Package: name, Version: version})
					}
				}
				return nil
			}
			lookupEcosystems := []string{eco}
			if exact := redHatMinorEcosystem(c.PURL); exact != "" && exact != eco {
				// Red Hat VEX relationships can be minor-scoped even though the normal distro ecosystem remains
				// major-scoped. Query the exact release first, then the major key for compatible bounded data.
				lookupEcosystems = append([]string{exact}, lookupEcosystems...)
			}
			for _, lookupEco := range lookupEcosystems {
				name := canonicalName(lookupEco, c.Name)
				if lookupEco == "Maven" {
					purlIdentity, coherent := coherentPURLIdentity(c)
					if !coherent || purlIdentity.Ecosystem != "Maven" {
						continue
					}
					name = purlIdentity.Package
				}
				if err := matchName(lookupEco, name, matchVersion); err != nil {
					return nil, err
				}
			}
			// A Debian/Ubuntu security advisory is keyed by the SOURCE package (one openssl advisory covers
			// the libssl1.1, libcrypto1.1, … binaries built from it), so a binary package never matches it by
			// its own name. Also match the binary by its source-package name, which Syft records in the deb
			// PURL "upstream=" qualifier as "<source>" or "<source>@<version>". Match against the SOURCE
			// version when the qualifier carries one: a binNMU gives the binary a "<src>+bN" version while the
			// source stays "<src>", and the advisory ranges are in source-version space, so using the binary
			// version could cross a nonzero introduced/fixed boundary the source does not (a false result).
			// Fall back to the binary version only for a name-only upstream (Syft omits the version when they
			// are equal). The emit map dedups a binary+source double hit.
			//
			// apk is the same shape: Alpine's secdb is keyed by the ORIGIN package (one openssl advisory
			// covers libcrypto3 and libssl3), the apk DB records it in the "o" field, and the origin carries no
			// separate version because every subpackage of an origin ships the origin's version. Not rpm: its
			// upstream is a source-RPM filename needing NEVRA parsing, and the owned RedHat CSAF feed is
			// binary-keyed.
			if t := purlType(c.PURL); t == "deb" || t == "apk" {
				name := canonicalName(eco, c.Name)
				// Decode the qualifier BEFORE splitting: PURL encodes the name/version "@" separator as %40
				// (and an epoch ":" as %3A), so "openssl%401.1.1k" decodes to "openssl@1.1.1k" first.
				upstreamName, upstreamVer, _ := strings.Cut(decodePURLSegment(purlQualifier(c.PURL, "upstream")), "@")
				if src := canonicalName(eco, strings.TrimSpace(upstreamName)); src != "" && src != name {
					srcVersion := matchVersion
					if v := strings.TrimSpace(upstreamVer); v != "" {
						srcVersion = v // the source version, in the space the source-keyed advisory ranges use
					}
					if err := matchName(eco, src, srcVersion); err != nil {
						return nil, err
					}
				}
			}
		}
		// 2) CPE matching against NVD/CSAF applicability. Runs for ANY component carrying a CPE,
		// independent of the package-ecosystem gate, so an NVD-only CVE on a system/OS library that the
		// OSV feeds do not key by package is still found on the default scan (the single largest recall
		// gap vs Grype's NVD matcher). Shares the fuzzy comparator via advisory.CPEMatches.
		if hasCPE && c.CPE != "" {
			componentCPE, err := sbom.ParseCPE23(c.CPE)
			if err != nil {
				continue // an unparseable component CPE can't be soundly matched; never a false hit
			}
			advs, err := cpeStore.ByCPE(ctx, componentCPE.Part, componentCPE.Vendor, componentCPE.Product)
			if err != nil {
				return nil, err
			}
			for _, a := range advs {
				if a.Withdrawn {
					continue
				}
				// An advisory is a hit only when the component matches a VULNERABLE applicability
				// statement AND no NON-vulnerable one. NVD lists explicit non-vulnerable configurations
				// (a fixed build, an unaffected edition); matching one of those excludes the component,
				// so honoring exclusions avoids a false positive.
				vulnerable, excluded := false, false
				fixedHint := ""
				for _, current := range a.CPEs {
					criteria, perr := sbom.ParseCPE23(current.Criteria)
					if perr != nil {
						continue
					}
					if matched, _, _ := advisory.CPEMatches(criteria, componentCPE, current); matched {
						if current.Vulnerable {
							if !vulnerable {
								fixedHint = current.VersionEndExcluding
								vulnerable = true
							}
						} else {
							excluded = true
						}
					}
				}
				if vulnerable && !excluded {
					emit(a, c, fixedHint, nil, nil)
				}
			}
		}
	}
	return out, nil
}

// rawFinding builds the normalized finding from a matched advisory + component.
func rawFinding(a advisory.Advisory, c sbom.Component, fixed string, symbols []string, matched *sbom.ComponentIdentity) vulnerability.RawFinding {
	identity := sbom.IdentityFromComponent(c)
	purlIdentity, coherentPURL := coherentPURLIdentity(c)
	remediationIdentity := sbom.ComponentIdentity{}
	if matched != nil {
		if coherentPURL {
			remediationIdentity = *matched
			if identity.Ecosystem == "" {
				identity.Ecosystem = matched.Ecosystem
			}
		}
	} else if coherentPURL {
		remediationIdentity = purlIdentity
		if identity.Ecosystem == "" {
			identity.Ecosystem = purlIdentity.Ecosystem
		}
	}
	componentArch := decodePURLSegment(purlQualifier(c.PURL, "arch"))
	fixedVersions, rejectedFixedVersions := ownedFixedVersions(a, remediationIdentity, componentArch, fixed)
	rf := vulnerability.RawFinding{
		Source:                sourceName,
		AdvisoryID:            preferCVE(a.ID, a.Aliases),
		Aliases:               append([]string{a.ID}, a.Aliases...),
		Component:             c.Name,
		Version:               c.Version,
		Ecosystem:             identity.Ecosystem,
		PackagePURL:           c.PURL,
		Severity:              shared.SeverityUnknown,
		CVSSVector:            a.CVSSVector,
		CVSSScore:             a.CVSSScore,
		FixedVersions:         fixedVersions,
		RejectedFixedVersions: rejectedFixedVersions,
		Description:           a.Summary,
		// Exploitation-risk signals projected onto the corpus advisory (D1.3): carry them so an OFFLINE scan
		// orders findings by KEV/EPSS without the live network enricher (which still runs online and raises).
		KEV:             a.KEV,
		EPSS:            a.EPSS,
		EPSSPercentile:  a.EPSSPercentile, // D1.3: the EPSS rank, carried offline beside the score
		PublicExploit:   a.PublicExploit,  // D1.3: a public exploit exists (offline, from the synced corpus)
		AffectedSymbols: symbols,
	}
	if len(fixedVersions) > 0 {
		rf.FixedVersion = fixedVersions[0]
		rf.FixState = "fixed"
	}
	// Severity from the score; if the store has the vector but no precomputed score, derive it (an ingester
	// may store only the vector) – mirrors the OSV adapter so a vuln found by both correlates to one band.
	score := a.CVSSScore
	if score == 0 && a.CVSSVector != "" {
		// CVSSBaseScore scores a v4.0, v3.x, or v2 vector, so a stored v4-only vector still yields a band
		// instead of falling to Unknown.
		if s, ok := shared.CVSSBaseScore(a.CVSSVector); ok {
			score = s
			rf.CVSSScore = s
		}
	}
	if score > 0 {
		rf.Severity = shared.SeverityFromScore(score)
	}
	// A curated feed label overrides the score-derived band (parity with the live OSV adapter), and is
	// the only band for a label-only advisory with no CVSS vector - so an offline scan still orders it.
	if a.Severity != "" && a.Severity != shared.SeverityUnknown {
		rf.Severity = a.Severity
	}
	return rf
}

func coherentPURLIdentity(c sbom.Component) (sbom.ComponentIdentity, bool) {
	// Preserve only the scanner-local provenance along with the PURL. The
	// component's name and version are checked against that PURL below.
	purlIdentity := sbom.IdentityFromComponent(sbom.WithVerifiedRPMOrigin(
		sbom.Component{PURL: c.PURL}, sbom.VerifiedRPMOrigin(c)))
	if purlIdentity.Status != sbom.IdentityResolved {
		return sbom.ComponentIdentity{}, false
	}
	nameMatches := canonicalName(purlIdentity.Ecosystem, c.Name) == canonicalName(purlIdentity.Ecosystem, purlIdentity.Package)
	if purlIdentity.Ecosystem == "Maven" {
		// Syft can supply only the artifact name while the PURL carries group:artifact.
		artifact := purlIdentity.Package[strings.LastIndexByte(purlIdentity.Package, ':')+1:]
		nameMatches = nameMatches || c.Name == artifact
	}
	if !nameMatches {
		return sbom.ComponentIdentity{}, false
	}
	if purlType(c.PURL) == "rpm" {
		epoch := decodePURLSegment(purlQualifier(c.PURL, "epoch"))
		componentVersion := rpmCanonicalEVR(decodePURLSegment(c.Version), epoch)
		if componentVersion != rpmCanonicalEVR(purlIdentity.Version, epoch) {
			return sbom.ComponentIdentity{}, false
		}
		purlIdentity.Version = componentVersion
		return purlIdentity, true
	}
	if strings.TrimSpace(c.Version) != purlIdentity.Version {
		return sbom.ComponentIdentity{}, false
	}
	return purlIdentity, true
}

const maxRemediationVersionComparisons = 100_000

func ownedFixedVersions(value advisory.Advisory, identity sbom.ComponentIdentity, architecture, fallback string) ([]string, []string) {
	candidates := []string{fallback}
	ranges := make([]advisory.Range, 0)
	versionSets := make([][]string, 0)
	versionCount := 0
	for _, affected := range value.Affected {
		if affected.Ecosystem != identity.Ecosystem || affected.Package != identity.Package ||
			!advisory.ArchitectureApplies(affected.Architectures, architecture) {
			continue
		}
		candidates = append(candidates, advisory.FixedVersions(affected)...)
		ranges = append(ranges, affected.Ranges...)
		if len(affected.Versions) > 0 {
			versionSets = append(versionSets, affected.Versions)
			versionCount += len(affected.Versions)
		}
	}
	valid := map[string]bool{}
	rejected := map[string]bool{}
	pending := map[string]bool{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if pending[candidate] || rejected[candidate] {
			continue
		}
		comparison, comparable := advisory.CompareVersions(identity.Ecosystem, identity.Version, candidate)
		if !comparable || comparison >= 0 || advisory.Affected(identity.Ecosystem, candidate, ranges, nil) {
			rejected[candidate] = true
			continue
		}
		pending[candidate] = true
	}
	// Large explicit lists must not multiply work by every remediation candidate. Withhold unverified
	// suggestions when their validation exceeds this per-finding budget.
	if len(pending) > 0 && versionCount > maxRemediationVersionComparisons/len(pending) {
		for candidate := range pending {
			rejected[candidate] = true
		}
		return nil, sortedVersionKeys(rejected)
	}
	for candidate := range pending {
		stillAffected := false
		for _, versions := range versionSets {
			if advisory.AffectedVersionList(identity.Ecosystem, candidate, versions) {
				stillAffected = true
				break
			}
		}
		if stillAffected {
			rejected[candidate] = true
			continue
		}
		valid[candidate] = true
	}
	return sortedVersionKeys(valid), sortedVersionKeys(rejected)
}

func sortedVersionKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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

// rpmCanonicalEVR normalizes an rpm version to an explicit "epoch:version-release" form so BOTH the advisory
// feed (which reads a RedHat PURL's version + "epoch=" qualifier) and the scan side (which reads a component
// PURL the same way) compare on identical strings. rpm's own comparator defaults a missing epoch to 0, but
// an ASYMMETRIC epoch (one side "1:x", the other "x") would compare across the epoch and either miss (safe)
// or, worse, over-match every version (a false positive). Making epoch explicit on both sides removes that
// hazard. A version that already embeds an epoch (contains ':') is trusted as-is.
func rpmCanonicalEVR(version, epoch string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	if strings.IndexByte(version, ':') >= 0 {
		return version // epoch already embedded
	}
	epoch = strings.TrimSpace(epoch)
	if epoch == "" {
		epoch = "0"
	}
	return epoch + ":" + version
}

// osDistroEcosystem derives the release-versioned ecosystem key for an OS-package PURL from its purl type and
// "distro" qualifier (Syft emits e.g. distro=debian-9 / ubuntu-22.04 / amzn-2). It delegates to the shared
// sbom.DistroEcosystem for PURL-only identities. Verified CentOS 7 origin is
// process-local and the scan uses sbom.DistroEcosystemForComponent instead;
// TestDistroEcosystemLockstep covers both paths. An unmapped/malformed distro
// yields "" (skip, never a false match).
func redHatMinorEcosystem(purl string) string {
	if purlType(purl) != "rpm" {
		return ""
	}
	distro := strings.ToLower(strings.TrimSpace(purlQualifier(purl, "distro")))
	id, release, ok := strings.Cut(distro, "-")
	if !ok || (id != "rhel" && id != "redhat") {
		return ""
	}
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 || !allASCIIDigits(parts[0]) || !allASCIIDigits(parts[1]) {
		return ""
	}
	return "Red Hat:" + parts[0] + "." + parts[1]
}

func osDistroEcosystem(purl string) string {
	return sbom.DistroEcosystem(purlType(purl), purlQualifier(purl, "distro"))
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
		return "Hex" // Elixir/Erlang; SemVer-ordered ranges (advisory.schemeFor), #1037.
	case "composer":
		return "Packagist" // PHP; Composer-stability-ordered ranges (advisory.packagistScheme), #1037.
	case "pub":
		return "Pub" // Dart; SemVer-ordered ranges (advisory.schemeFor), #1037.
	}
	return ""
}

// AliasEdges exposes the owned store's alias edges for the given ids, so the SCA correlation step can build
// the transitive alias closure and merge cross-source findings that carry non-overlapping ids. It delegates
// to the store's optional AdvisoryAliasStore capability; a store without it returns no edges (correlation
// then behaves exactly as before). Bounded to the given ids.
func (s *Source) AliasEdges(ctx context.Context, ids []string) ([]advisory.AliasEdge, error) {
	aliasStore, ok := s.store.(ports.AdvisoryAliasStore)
	if !ok {
		return nil, nil
	}
	return aliasStore.AdvisoryAliasEdges(ctx, ids)
}
