// Package manifest enriches a generator's SBOM from dependency manifests the
// generator under-uses: it reconstructs missing dependency edges
// (Gemfile.lock), recovers dependencies the generator cannot resolve from source
// (Maven pom.xml, Gradle version catalogs), and refines component scope via pnpm
// workspace attribution. It reads only files already in the acquired workspace –
// no execution, no network.
package manifest

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxManifestBytes = 16 << 20 // cap a single manifest read

// Enricher implements ports.SBOMEnricher over the workspace's manifest files.
type Enricher struct{}

// New returns a manifest enricher.
func New() *Enricher { return &Enricher{} }

var _ ports.SBOMEnricher = (*Enricher)(nil)

// Enrich augments doc in place and reports what it contributed.
func (Enricher) Enrich(ctx context.Context, dir string, doc *sbom.SBOM) ports.SBOMEnrichment {
	var res ports.SBOMEnrichment
	if doc == nil {
		return res
	}
	var gemEdges []sbom.Dependency
	var mavenComps, gradleComps []sbom.Component
	pnpmScopes := map[string]string{}
	checksumsByID := map[string][]sbom.Checksum{} // ComponentID (PURL-aware) -> lockfile integrity digests

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		name := strings.ToLower(d.Name())
		switch name {
		case "gemfile.lock":
			if data := read(path); data != nil {
				gemEdges = append(gemEdges, parseGemfileLockEdges(data)...)
			}
		case "pom.xml":
			if data := read(path); data != nil {
				mavenComps = append(mavenComps, parsePomComponents(data)...)
			}
		case "libs.versions.toml":
			if data := read(path); data != nil {
				// Delegate to the SHARED owned Gradle parser – one implementation for both the owned
				// SBOM producer (ownsbom.Gradle) and this Syft-enrichment path; no duplicated catalog parser.
				gradleComps = append(gradleComps, ownsbom.ParseGradleCatalog(data)...)
			}
		case "pnpm-lock.yaml":
			if data := read(path); data != nil {
				for k, v := range parsePnpmScopes(data) {
					if cur, ok := pnpmScopes[k]; !ok || scopeRank(v) > scopeRank(cur) {
						pnpmScopes[k] = v
					}
				}
			}
		}
		// Integrity: a lockfile carries per-artifact digests that Syft omits from its CycloneDX output. Run
		// the SHARED owned parser for this lockfile (reuse, not a second catalog implementation) and index its
		// digests by the PURL-aware ComponentID so they can be attached to the generator's components below.
		if p, ok := checksumLockParsers[name]; ok {
			if data := read(path); data != nil {
				comps, _, perr := p.Parse(ctx, ownsbom.ParseInput{Dir: filepath.Dir(path), Path: path, Content: data})
				if perr == nil {
					for _, c := range comps {
						if len(c.Checksums) == 0 {
							continue
						}
						// Key by ComponentID (not name@version) so integrity never cross-attaches between
						// ecosystems (npm foo@1 vs pypi foo@1) and PyPI's PEP-503 name normalization still aligns
						// with the generator's component (both normalize the PURL).
						if id := sbom.ComponentID(c.Name, c.Version, c.PURL); checksumsByID[id] == nil {
							checksumsByID[id] = c.Checksums
						}
					}
				}
			}
		}
		return nil
	})

	res.ComponentsAdded = mergeComponents(doc, append(mavenComps, gradleComps...))
	res.EdgesAdded = mergeEdges(doc, gemEdges)
	res.ScopesRefined = refineScopes(doc, pnpmScopes)
	res.ChecksumsAttached = attachChecksums(doc, checksumsByID)
	res.Sources = sourcesUsed(gemEdges, mavenComps, gradleComps, pnpmScopes, res.ChecksumsAttached)
	return res
}

// lockChecksumParser is the subset of an owned ecosystem parser this enricher needs: turn a lockfile's bytes
// into components (carrying their integrity Checksums).
type lockChecksumParser interface {
	Parse(ctx context.Context, in ownsbom.ParseInput) ([]sbom.Component, []sbom.Dependency, error)
}

// checksumLockParsers maps a lockfile name to the owned parser that extracts its per-artifact integrity, for
// the ecosystems whose parsers capture Checksums today (npm/pnpm/yarn Subresource Integrity, Cargo + Pipfile
// hashes, Composer dist shasum). More slot in here as their owned parsers gain checksum capture.
var checksumLockParsers = map[string]lockChecksumParser{
	"package-lock.json": ownsbom.NPM{},
	"pnpm-lock.yaml":    ownsbom.Pnpm{},
	"yarn.lock":         ownsbom.Yarn{},
	"cargo.lock":        ownsbom.Cargo{},
	"pipfile.lock":      ownsbom.Pipfile{},
	"poetry.lock":       ownsbom.Poetry{},
	"composer.lock":     ownsbom.Composer{},
}

// attachChecksums fills in a lockfile integrity digest for each generator component that has none, matched by
// the PURL-aware ComponentID. It never overwrites a digest the generator already supplied (SHA1 or Checksums).
// Returns the number of components given a checksum.
func attachChecksums(doc *sbom.SBOM, byID map[string][]sbom.Checksum) int {
	if len(byID) == 0 {
		return 0
	}
	n := 0
	for i := range doc.Components {
		c := &doc.Components[i]
		if len(c.Checksums) > 0 || c.SHA1 != "" {
			continue // the generator already supplied integrity
		}
		if cks := byID[sbom.ComponentID(c.Name, c.Version, c.PURL)]; cks != nil {
			c.Checksums = cks
			n++
		}
	}
	return n
}

// mergeComponents adds components the generator missed (by name@version identity).
func mergeComponents(doc *sbom.SBOM, extra []sbom.Component) int {
	have := make(map[string]bool, len(doc.Components))
	for _, c := range doc.Components {
		have[c.Name+"@"+c.Version] = true
	}
	added := 0
	for _, c := range extra {
		key := c.Name + "@" + c.Version
		if c.Name == "" || have[key] {
			continue
		}
		have[key] = true
		doc.Components = append(doc.Components, c)
		added++
	}
	return added
}

// mergeEdges adds reconstructed dependency edges not already present.
func mergeEdges(doc *sbom.SBOM, extra []sbom.Dependency) int {
	have := make(map[string]bool, len(doc.Dependencies))
	for _, d := range doc.Dependencies {
		have[d.Ref] = true
	}
	added := 0
	for _, e := range extra {
		if have[e.Ref] {
			continue // generator already provided this node's edges
		}
		have[e.Ref] = true
		doc.Dependencies = append(doc.Dependencies, e)
		added += len(e.DependsOn)
	}
	return added
}

// refineScopes re-scopes components when pnpm workspace attribution says a dep is
// only used by a background workspace (and the current scope is less specific).
func refineScopes(doc *sbom.SBOM, scopes map[string]string) int {
	if len(scopes) == 0 {
		return 0
	}
	refined := 0
	for i := range doc.Components {
		c := &doc.Components[i]
		s, ok := scopes[c.Name+"@"+c.Version]
		if !ok {
			continue
		}
		// Only move toward MORE background (lower rank) – never upgrade a
		// directory-derived background scope back to production.
		if scopeRank(s) < scopeRank(orDefault(c.Scope)) {
			c.Scope = s
			refined++
		}
	}
	return refined
}

func orDefault(s string) string {
	if s == "" {
		return sbom.ScopeUnknown
	}
	return s
}

func sourcesUsed(gem []sbom.Dependency, maven, gradle []sbom.Component, pnpm map[string]string, checksums int) []string {
	var s []string
	if len(gem) > 0 {
		s = append(s, "gemfile")
	}
	if len(maven) > 0 {
		s = append(s, "maven")
	}
	if len(gradle) > 0 {
		s = append(s, "gradle")
	}
	if len(pnpm) > 0 {
		s = append(s, "pnpm")
	}
	if checksums > 0 {
		s = append(s, "checksums")
	}
	return s
}

func read(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes))
	if err != nil {
		return nil
	}
	return data
}
