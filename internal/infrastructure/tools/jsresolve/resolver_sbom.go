package jsresolve

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// npmPURLPrefix is the package-URL type prefix for the npm ecosystem. A component of any other
// ecosystem must never be correlated to a JavaScript import.
const npmPURLPrefix = "pkg:npm/"

// componentIndex is the npm slice of a normalized SBOM, indexed by package name for exact-PURL
// correlation (#400).
//
// Both sides of the comparison are normalized through jsresolution.NormalizePackageName, which lowercases:
// a component PURL's name is normalized when the index is built, and a specifier's package root is
// normalized when it is classified. Comparing the RAW forms would silently miss a mixed-case package, and a
// silent miss here becomes a dependency that looks unused.
type componentIndex struct {
	// byName maps the component's EXACT package name to its identities, sorted and deduplicated.
	byName map[string][]jsresolution.PackageIdentity
	// byFoldedName maps the lowercased name to the exact names that fold to it. npm hosts distinct
	// packages that differ only in case (JSONStream and jsonstream are different packages), so folding
	// is a last-resort rescue that must be REPORTED, never a silent identity swap.
	byFoldedName map[string][]string
	// supplied records whether an SBOM was provided at all. Without one, correlation is IMPOSSIBLE,
	// which is a different fact from "the SBOM does not contain this package".
	supplied bool
	// complete is false when the index itself is partial (budget exceeded, unparseable PURLs).
	complete bool
	// dropped records why a package name present in the SBOM produced no usable identity, so an import
	// of it is not reported as "absent from the sbom" when the truth is subtler.
	dropped map[string]string
}

// newComponentIndex builds the npm component index from doc. It never fails: a component it cannot
// interpret produces a coverage issue rather than an error, because a partial index must degrade the
// resolution rather than abort the scan.
func newComponentIndex(doc *sbom.SBOM, maxComponents, maxCandidates int, coverage *resolutionCoverageSink) *componentIndex {
	index := &componentIndex{
		byName:       map[string][]jsresolution.PackageIdentity{},
		byFoldedName: map[string][]string{},
		dropped:      map[string]string{},
		complete:     true,
	}
	if doc == nil {
		return index
	}
	index.supplied = true

	components := doc.Components
	if len(components) > maxComponents {
		// The SBOM is the only unbounded input here. Degrade rather than abort, but never index a
		// truncated prefix silently: a package beyond the cut would look absent from the SBOM.
		index.complete = false
		components = components[:maxComponents]
		coverage.add(jsresolution.CoverageIssue{
			Kind:   jsresolution.CoverageMetadataBudgetExceeded,
			Detail: fmt.Sprintf("sbom component budget exceeded (%d), so component correlation is partial", maxComponents),
		})
	}

	unparseable := 0
	unresolvedVersion := 0
	for i := range components {
		component := components[i]
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(component.PURL)), npmPURLPrefix) {
			// Another ecosystem, or a component with no PURL: not correlatable to a JS import.
			continue
		}
		name, version, ok := parseNPMPURL(component.PURL)
		if !ok {
			unparseable++
			continue
		}
		// A floating version ("latest", a range) is not a resolved identity, so it cannot be the exact
		// subject a later reachability analyzer needs.
		if !sbom.IsResolvedVersion(version) {
			unresolvedVersion++
			index.dropped[strings.ToLower(name)] = "listed only with an unresolved version"
			continue
		}
		index.byName[name] = append(index.byName[name], jsresolution.PackageIdentity{
			Name:    name,
			Version: version,
			PURL:    component.PURL,
		})
		folded := strings.ToLower(name)
		if folded != name {
			index.byFoldedName[folded] = append(index.byFoldedName[folded], name)
		}
	}

	if unparseable > 0 {
		index.complete = false
		coverage.add(jsresolution.CoverageIssue{
			Kind:   jsresolution.CoverageMissingSBOMComponent,
			Detail: fmt.Sprintf("%d npm component purls could not be interpreted, so correlation is partial", unparseable),
		})
	}
	if unresolvedVersion > 0 {
		index.complete = false
		coverage.add(jsresolution.CoverageIssue{
			Kind:   jsresolution.CoverageAmbiguousSBOMComponent,
			Detail: fmt.Sprintf("%d npm components carry an unresolved version and cannot be exact subjects", unresolvedVersion),
		})
	}

	// Iterate in sorted name order: coverage issues land in a CAPPED sink, so map iteration order would
	// decide which issues survive truncation and the output would stop being reproducible.
	names := make([]string, 0, len(index.byName))
	for name := range index.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		identities := index.byName[name]
		sort.Slice(identities, func(i, j int) bool { return identityLess(identities[i], identities[j]) })
		identities = deduplicatePackageIdentities(identities)
		if len(identities) > maxCandidates {
			// Refuse to select from a truncated candidate set: keep the name unresolved instead, and
			// remember why so the import's reason does not claim the package is absent from the SBOM.
			index.complete = false
			index.dropped[name] = "more component versions than the candidate budget allows"
			coverage.add(jsresolution.CoverageIssue{
				Kind:   jsresolution.CoverageAmbiguousSBOMComponent,
				Detail: fmt.Sprintf("package %q has more component versions than the candidate budget allows", name),
			})
			delete(index.byName, name)
			continue
		}
		index.byName[name] = identities
	}
	return index
}

// lookup returns the component identities for a package name, preferring an EXACT-case match.
//
// It reports foldedMatch when the result was found only by lowercasing. npm hosts distinct packages
// whose names differ only in case, so a folded hit is a plausible-but-unproven identity: the caller must
// degrade coverage rather than seal it as deterministic.
func (c *componentIndex) lookup(packageName string) (identities []jsresolution.PackageIdentity, foldedMatch bool) {
	if c == nil {
		return nil, false
	}
	if exact := c.byName[packageName]; len(exact) > 0 {
		return exact, false
	}
	folded := strings.ToLower(packageName)
	names := c.byFoldedName[folded]
	if len(names) == 0 {
		// The specifier itself may be the mixed-case side.
		if exact := c.byName[folded]; len(exact) > 0 && folded != packageName {
			return exact, true
		}
		return nil, false
	}
	var out []jsresolution.PackageIdentity
	for _, name := range names {
		out = append(out, c.byName[name]...)
	}
	sort.Slice(out, func(i, j int) bool { return identityLess(out[i], out[j]) })
	return deduplicatePackageIdentities(out), true
}

// isSupplied reports whether an SBOM was provided at all. Nil-safe, so every caller can use the same
// contract as lookup.
func (c *componentIndex) isSupplied() bool { return c != nil && c.supplied }

// isComplete reports whether the index covers the whole SBOM.
func (c *componentIndex) isComplete() bool { return c != nil && c.complete }

// dropReason returns why a name present in the SBOM produced no usable identity, or "" when the SBOM
// simply does not list it.
func (c *componentIndex) dropReason(packageName string) string {
	if c == nil {
		return ""
	}
	return c.dropped[packageName]
}

// parseNPMPURL extracts the package name and version from an npm package URL.
//
// The repository's parsers encode a scoped package as "pkg:npm/%40scope/name@1.2.3": the scope's leading
// "@" is percent-encoded, the separating "/" is literal, and the "@" before the version is literal. This
// decodes that form back to "@scope/name" so it can be compared with a source specifier's package root.
func parseNPMPURL(purl string) (string, string, bool) {
	trimmed := strings.TrimSpace(purl)
	if len(trimmed) <= len(npmPURLPrefix) || !strings.HasPrefix(strings.ToLower(trimmed), npmPURLPrefix) {
		return "", "", false
	}
	body := trimmed[len(npmPURLPrefix):]

	// Qualifiers and subpaths are not part of the identity.
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	// The version follows the LAST "@": a scoped name's own "@" is percent-encoded, so any literal "@"
	// that remains is the version separator.
	at := strings.LastIndex(body, "@")
	if at <= 0 || at == len(body)-1 {
		return "", "", false
	}
	rawName, version := body[:at], body[at+1:]
	name := purlDecodeName(rawName)
	if name == "" || version == "" {
		return "", "", false
	}
	// Validate the name through the domain normalizer (which lowercases) but RETURN the component's own
	// casing: npm hosts distinct packages that differ only in case, so folding here would let one
	// package's PURL be attached to another's import.
	if _, err := jsresolution.NormalizePackageName(name); err != nil {
		return "", "", false
	}
	return name, version, true
}

// purlDecodeName percent-decodes a PURL name segment. Only the encodings the repository's PURL builders
// produce are decoded; an unrecognized escape leaves the name unchanged so it fails validation rather
// than silently naming a different package.
func purlDecodeName(raw string) string {
	if !strings.Contains(raw, "%") {
		return raw
	}
	var sb strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] == '%' && i+2 < len(raw) {
			hi, hiOK := hexValue(raw[i+1])
			lo, loOK := hexValue(raw[i+2])
			if hiOK && loOK {
				sb.WriteByte(hi<<4 | lo)
				i += 3
				continue
			}
		}
		sb.WriteByte(raw[i])
		i++
	}
	return sb.String()
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// correlateComponent resolves a third-party package name against the SBOM.
//
// Exactly one resolved component version is a deterministic identity and becomes StatusComponent, which
// is what allows a later analyzer to use the exact PURL as its subject. Several versions stay AMBIGUOUS
// with every viable candidate preserved — never the first by map or slice order — and no component at all
// stays unresolved with an explicit reason. Each non-deterministic outcome degrades coverage, so a
// negative reachability conclusion cannot rest on it.
func (r *Resolver) correlateComponent(
	base jsresolution.ImportResolution,
	packageName string,
	components *componentIndex,
	candidateWork *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) jsresolution.ImportResolution {
	if !components.isSupplied() {
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{Name: packageName}
		base.Reason = "no sbom was supplied, so the package cannot be correlated to a component"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageMissingSBOMComponent, Path: base.From,
			Detail: fmt.Sprintf("package %q cannot be correlated without an sbom", packageName),
		})
		return base
	}

	matches, folded := components.lookup(packageName)
	if !candidateWork.consumeN(len(matches) + 1) {
		return markCandidateBudgetExceeded(base, candidateWork, coverage, r.limits.maxCandidateWork)
	}

	switch len(matches) {
	case 0:
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{Name: packageName}
		if dropped := components.dropReason(packageName); dropped != "" {
			base.Reason = "package is imported by first-party source but the sbom " + dropped
		} else {
			base.Reason = "package is imported by first-party source but is absent from the sbom"
		}
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageMissingSBOMComponent, Path: base.From,
			Detail: fmt.Sprintf("imported package %q has no usable sbom component", packageName),
		})
		return base
	case 1:
		if folded {
			// The only match differs from the specifier in case. npm hosts distinct packages that
			// differ only in case, so this is plausible, not proven: report it rather than seal it.
			base.Status = jsresolution.StatusUnresolved
			base.Package = jsresolution.PackageIdentity{Name: packageName}
			base.Reason = "the only matching sbom component differs from the imported specifier in case"
			coverage.add(jsresolution.CoverageIssue{
				Kind: jsresolution.CoverageAmbiguousSBOMComponent, Path: base.From,
				Detail: "imported package " + packageName + " matches an sbom component only by case folding",
			})
			return base
		}
		base.Status = jsresolution.StatusComponent
		base.Package = matches[0]
		base.Reason = ""
		return base
	default:
		base.Status = jsresolution.StatusAmbiguous
		base.Candidates = append([]jsresolution.PackageIdentity(nil), matches...)
		base.Reason = "package name matches more than one sbom component version and importer context does not select one"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageAmbiguousSBOMComponent, Path: base.From,
			Detail: fmt.Sprintf("imported package %q matches %d component versions", packageName, len(matches)),
		})
		return base
	}
}
