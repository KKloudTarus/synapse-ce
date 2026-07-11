// Package sbom models a Software Bill of Materials and its components/licenses.
package sbom

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ClassifyFirstParty marks components whose module identity belongs to the scanned
// project itself (first-party). localModules is the set of module paths declared in
// the repository (go.mod `module`, package.json name, …).
//
// A component is first-party only when it BOTH (a) name-matches a local module AND
// (b) has no resolvable version. A real third-party dependency is pinned to a
// resolved version by its lockfile, so it is never misclassified even when the repo
// happens to contain a same-named local manifest (e.g. a third-party `vue@2.7.16`
// alongside a local package.json named "vue"). First-party classification only
// changes behavior for unversioned modules (they cannot be confirmed against an
// advisory), so gating on version-resolution is both the bug fix and semantically
// correct.
func ClassifyFirstParty(comps []Component, localModules []string) {
	if len(localModules) == 0 {
		return
	}
	set := make(map[string]bool, len(localModules))
	for _, m := range localModules {
		if m = strings.TrimSpace(m); m != "" {
			set[m] = true
		}
	}
	matches := func(name string) bool {
		if set[name] {
			return true
		}
		for m := range set {
			if strings.HasPrefix(name, m+"/") {
				return true
			}
		}
		return false
	}
	for i := range comps {
		if IsResolvedVersion(comps[i].Version) {
			continue // a resolved version means it's a real (third-party) package
		}
		if matches(comps[i].Name) {
			comps[i].FirstParty = true
		}
	}
}

// Format enumerates supported SBOM document formats.
type Format string

const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
)

// SBOM is a software bill of materials for a scanned target.
type SBOM struct {
	ID               shared.ID
	TargetRef        string // repo path, directory, or container image reference
	Source           string // generator, e.g. "syft"
	GeneratorVersion string // generator tool version, captured for reproducibility
	Components       []Component
	Dependencies     []Dependency // edges of the dependency graph (by component identity)

	// Raw is the generator's original SBOM document (e.g. CycloneDX JSON from Syft),
	// kept so a downstream detector (Grype) consumes the EXACT SBOM rather than a
	// lossy reconstruction. Not persisted or serialized (json:"-").
	Raw []byte `json:"-"`

	Audit shared.Audit
}

// Component is a single dependency / package.
type Component struct {
	Name     string
	Version  string
	PURL     string // package URL (purl spec)
	Licenses []License

	// Supplier is the entity that supplies the component (a Maven groupId, an npm scope, a GitHub org, a
	// package registry) – the NTIA "supplier name" minimum SBOM element. Captured from the producer/imported
	// SBOM when it carries one, else derived from the PURL namespace (SupplierFromPURL); empty when neither
	// yields one (a bare, namespaceless package). Emitted as SPDX PackageSupplier on export.
	Supplier string `json:",omitempty"`
	// SupplierSource records HOW Supplier was obtained – SupplierDeclared (asserted by the producer or an
	// imported/untrusted client SBOM) vs SupplierDerived (deterministically inferred by Synapse from the PURL
	// namespace) – so a downstream trust decision can tell an authoritative supplier from an echoed or inferred
	// one (mirrors LicenseSource/LicenseConfidence). Empty when Supplier is empty.
	SupplierSource string `json:",omitempty"`

	// License provenance: where the license data came from and, when it
	// is still unknown, why – so coverage is explainable + audit-ready.
	LicenseSource     string // "sbom" | "registry" | "local-file" | "" (unknown)
	LicenseConfidence string // "declared" | "registry" | "unknown"
	// LicenseConfidencePct is the license-text match coverage (0..100) when the license was
	// recovered by classifying a LICENSE file (source=local-file); 0 for other sources.
	LicenseConfidencePct float64
	UnknownReason        string // UnknownReason* when no license resolved

	// Provenance classification: is this the project's own module
	// (first-party) vs an external dependency (third-party). First-party modules
	// scanned from source carry no resolvable version, so their advisories are
	// historical, not actionable.
	FirstParty bool

	// Scope classification: where this component lives in the repo –
	// production code vs dev/test/example/fixture/benchmark/docs – so findings on
	// non-shipping assets can be ranked as background, not actionable. Location is
	// the on-disk manifest path the classification was derived from.
	Scope    string
	Location string

	// LayerID is the container-image layer (its uncompressed diff_id digest, e.g.
	// "sha256:…") that introduced this component, recovered from Syft's
	// `syft:location:N:layerID`. Empty for non-image scans. It joins a component –
	// and thus any vulnerability on it – back to the image layer it came from
	// (Epic D layer attribution); cross-references ImageInfo.Layers.
	LayerID string

	// Reachability is a COARSE, deterministic JVM class-reachability verdict: whether the
	// application's own compiled code (transitively) references any of this component's classes.
	// Empty = not analyzed / unknown (the default – non-JVM, source not built, or analysis skipped).
	// It only DEPRIORITIZES a finding, never suppresses one; Unreferenced means "no STATIC reference
	// found", NOT "provably unused" (reflection/DI/ServiceLoader edges are invisible to it).
	Reachability string

	// SHA1 is the lowercase hex SHA-1 of the component's artifact file (e.g. a JAR), when the SBOM
	// producer supplied it (syft emits it in CycloneDX `hashes`). Empty otherwise. It fingerprints the
	// exact artifact bytes, so it can recover the Maven coordinate of a shaded/renamed/metadata-less JAR
	// whose in-file identity was stripped, where pom.properties recovery cannot.
	SHA1 string `json:",omitempty"`

	// Checksums are the component artifact's integrity digests as recorded by the lockfile / producer
	// (e.g. npm `integrity` sha512, a Cargo.lock sha256), giving tamper evidence per component. Kept
	// alongside SHA1 (which is a single legacy hex form); empty when the source records none. Emitted as
	// SPDX package checksums on export.
	Checksums []Checksum `json:",omitempty"`
}

// Checksum is one integrity digest of a component artifact. Algorithm is an SPDX-style name (SHA1, SHA256,
// SHA512, ...); Value is the digest as the source recorded it (hex for SHA-256/SHA-1, base64 for an npm
// sha512 integrity).
type Checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Coarse JVM class-reachability verdicts. Empty ("") = not analyzed / unknown.
const (
	ReachabilityReachable    = "reachable"    // the app's compiled code (transitively) references a class of this component
	ReachabilityUnreferenced = "unreferenced" // no static reference found from the app closure (NOT proof of dead code)
)

// Component scope classifications.
const (
	ScopeProduction    = "production"
	ScopeDevelopment   = "development"
	ScopeTest          = "test"
	ScopeExample       = "example"
	ScopeFixture       = "fixture"
	ScopeBenchmark     = "benchmark"
	ScopeDocumentation = "documentation"
	ScopeUnknown       = "unknown"
)

// IsBackgroundScope reports whether a scope is non-shipping (example/test/etc.) –
// findings there are background, not actionable.
func IsBackgroundScope(s string) bool {
	switch s {
	case ScopeExample, ScopeTest, ScopeFixture, ScopeBenchmark, ScopeDocumentation:
		return true
	}
	return false
}

// ClassifyScope derives a component's scope from its manifest location path +
// CycloneDX scope (npm dev deps -> "excluded"). Directory heuristics win, since a
// vulnerable package under examples/ is background regardless of how it's declared.
func ClassifyScope(location, cdxScope string) string {
	l := strings.ToLower(location)
	segs := strings.FieldsFunc(l, func(r rune) bool { return r == '/' || r == '\\' })
	for _, s := range segs {
		switch s {
		case "examples", "example", "sample", "samples", "demo", "demos":
			return ScopeExample
		case "fixtures", "fixture", "testdata", "__fixtures__":
			return ScopeFixture
		case "test", "tests", "__tests__", "spec", "e2e":
			return ScopeTest
		case "benchmark", "benchmarks", "bench", "perf":
			return ScopeBenchmark
		case "docs", "doc", "documentation", "examples-docs", "website":
			return ScopeDocumentation
		}
	}
	// Manifest-type heuristics (dev/test requirement files).
	base := ""
	if len(segs) > 0 {
		base = segs[len(segs)-1]
	}
	switch {
	case strings.Contains(base, "requirements-dev"), strings.Contains(base, "dev-requirements"),
		strings.Contains(base, "requirements_dev"), base == "tools.go", strings.Contains(base, "package-dev"):
		return ScopeDevelopment
	case strings.Contains(base, "requirements-test"), strings.Contains(base, "test-requirements"):
		return ScopeTest
	}
	if strings.EqualFold(cdxScope, "excluded") {
		return ScopeDevelopment // CycloneDX "excluded" = npm devDependency
	}
	if strings.EqualFold(cdxScope, "required") {
		return ScopeProduction
	}
	if location == "" {
		return ScopeUnknown
	}
	return ScopeProduction
}

// IsResolvedVersion reports whether a component version is a concrete, matchable
// version (vs UNKNOWN / empty / a floating tag). Advisories can only be soundly
// confirmed against a resolved version.
func IsResolvedVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "unknown") || strings.EqualFold(v, "latest") {
		return false
	}
	switch c := v[0]; {
	case c >= '0' && c <= '9':
		return true
	case (c == 'v' || c == 'V') && len(v) > 1 && v[1] >= '0' && v[1] <= '9':
		return true
	}
	return false
}

// Unknown-license reasons – why a component has no resolved license.
const (
	LicenseSourceSBOM        = "sbom"
	LicenseSourceRegistry    = "registry"
	LicenseSourceOSMetadata  = "os-metadata"
	LicenseSourceManifest    = "manifest"
	LicenseSourceLicenseFile = "local-file" // wire value emitted by the JAR license-text resolver

	ReasonNoLicenseDeclared   = "no_license_declared"
	ReasonRegistryUnavailable = "registry_unavailable"
	ReasonMetadataMissing     = "metadata_missing"
	ReasonResolutionFailed    = "resolution_failed"
	ReasonUnsupportedEco      = "unsupported_ecosystem"
	ReasonFirstPartyModule    = "first_party_module" // the project's own module
	ReasonNoVersion           = "no_version"         // version unresolvable (UNKNOWN)
	ReasonLocalComponent      = "local_component"    // no PURL (local dir / CI action)
)

// LicenseCoverage summarizes how much of the SBOM has a resolved license.
type LicenseCoverage struct {
	Total    int     `json:"total"`
	Detected int     `json:"detected"`
	Unknown  int     `json:"unknown"`
	Pct      float64 `json:"pct"`
}

// ComputeLicenseCoverage tallies resolved vs unknown licenses across THIRD-PARTY
// components. First-party modules are the project's own code (no registry license)
// and are excluded so they don't artificially depress coverage.
func ComputeLicenseCoverage(comps []Component) LicenseCoverage {
	c := LicenseCoverage{}
	for _, comp := range comps {
		if comp.FirstParty {
			continue
		}
		c.Total++
		if len(comp.Licenses) > 0 {
			c.Detected++
		} else {
			c.Unknown++
		}
	}
	if c.Total > 0 {
		c.Pct = float64(c.Detected) / float64(c.Total) * 100
	} else {
		c.Pct = 100
	}
	return c
}

// Dependency is one edge of the dependency graph: Ref depends on each of
// DependsOn. Identities are PURLs (or name@version when a component has no PURL).
type Dependency struct {
	Ref       string
	DependsOn []string
}

// PathToRoot returns the dependency path from a top-level dependency (a node that
// nothing else depends on) down to target, as [root,..., target]. It walks the
// reverse of the edges (an edge Ref->DependsOn means Ref needs DependsOn). A
// single-element path means target is itself a direct/top-level dependency;
// nil means target is not in the graph. Cycle-safe via a visited set.
func PathToRoot(deps []Dependency, target string) []string {
	dependents := map[string][]string{} // who depends on X
	hasDependent := map[string]bool{}
	inGraph := map[string]bool{}
	for _, d := range deps {
		inGraph[d.Ref] = true
		for _, on := range d.DependsOn {
			dependents[on] = append(dependents[on], d.Ref)
			hasDependent[on] = true
			inGraph[on] = true
		}
	}
	if !inGraph[target] {
		return nil
	}
	if !hasDependent[target] {
		return []string{target} // already a root (direct dependency)
	}
	visited := map[string]bool{target: true}
	type node struct {
		id   string
		path []string
	}
	queue := []node{{target, []string{target}}}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, p := range dependents[n.id] {
			if visited[p] {
				continue
			}
			visited[p] = true
			np := append([]string{p}, n.path...)
			if !hasDependent[p] {
				return np // reached a root
			}
			queue = append(queue, node{p, np})
		}
	}
	return []string{target} // only reachable via a cycle; report the package itself
}

// ComponentID is the stable identity of a component for the dependency graph and
// cross-referencing: its PURL, or name@version when it has no PURL.
func ComponentID(name, version, purl string) string {
	if purl != "" {
		return purl
	}
	if version != "" {
		return name + "@" + version
	}
	return name
}

// License describes a detected license and its policy risk category.
type License struct {
	SPDXID   string
	Name     string
	Category LicenseCategory
}

// LicenseCategory groups licenses by obligation/risk for policy evaluation.
type LicenseCategory string

const (
	LicensePermissive   LicenseCategory = "permissive"
	LicenseWeakCopyleft LicenseCategory = "weak-copyleft"
	LicenseCopyleft     LicenseCategory = "copyleft"
	LicenseProprietary  LicenseCategory = "proprietary"
	LicenseUnknown      LicenseCategory = "unknown"
)
