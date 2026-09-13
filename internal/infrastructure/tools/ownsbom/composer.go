package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Composer is the owned PHP parser: it reads composer.lock – the resolved dependency set –
// into composer components + the dependency edges its "require"/"require-dev" maps encode. composer.lock is
// JSON with two arrays: "packages" (production) and "packages-dev" (development), each entry {name:
// "vendor/package", version, require, require-dev}. The dev split is INLINE in the lock (no companion needed).
// Vendor-neutral (stdlib encoding/json), no third-party Composer library.
type Composer struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Composer) Ecosystem() string { return "composer" }

// Markers are the lockfile basenames Composer claims.
func (Composer) Markers() []string { return []string{"composer.lock"} }

// composerLock is the subset of composer.lock we parse: the two resolved-package arrays.
type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Shasum string `json:"shasum"` // the distribution artifact's SHA-1 hex (Composer records it per package)
	} `json:"dist"`
	// Require/RequireDev are the declared dependency constraints keyed by "vendor/package" → range. Platform
	// keys (php, ext-*, composer-*) never resolve to a component and are dropped, so only real edges survive.
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// Parse extracts the resolved PHP packages: "packages" as production, "packages-dev" as development. Each
// entry's name is "vendor/package" → pkg:composer/vendor/package@version. Production is added first so a
// package listed in both arrays keeps the safer production scope (componentSet dedups by PURL).
func (Composer) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var lock composerLock
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse composer.lock: %w", err)
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	purlOf := func(name string) string { return "pkg:composer/" + name + "@" }
	// Index every declared package name to its resolved PURL, so a "require" key resolves to the exact
	// component identity used as an edge endpoint. Built across both arrays before edges are emitted, since a
	// require can name a package listed later in the file.
	index := map[string]string{}
	indexPkgs := func(pkgs []composerPkg) {
		for _, p := range pkgs {
			name, version := strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
			if name != "" && version != "" {
				index[name] = purlOf(name) + version
			}
		}
	}
	indexPkgs(lock.Packages)
	indexPkgs(lock.PackagesDev)

	set := newComponentSet()
	var deps []sbom.Dependency
	emit := func(pkgs []composerPkg, scope string) {
		for _, p := range pkgs {
			name, version := strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
			if name == "" || version == "" {
				continue // an entry missing identity is dropped (componentSet would drop it anyway)
			}
			ref := index[name]
			comp := sbom.Component{
				Name:     name,
				Version:  version,
				PURL:     ref,
				Location: in.Path,
				Scope:    scope,
			}
			if s := strings.TrimSpace(p.Dist.Shasum); s != "" {
				comp.Checksums = []sbom.Checksum{{Algorithm: "SHA1", Value: s}}
			}
			set.add(comp)
			// One edge per package from its runtime "require" map. A dependency's require-dev is its own test
			// tree, never installed into this resolved set, so those keys are not real edges here. Ranges are
			// carried only for resolved targets, so a platform requirement (php, ext-*) contributes neither an
			// edge nor a range.
			seen := map[string]bool{ref: true} // drop self-edges + duplicate targets
			byTarget := map[string]string{}
			var on []string
			for depName, rng := range p.Require {
				t, ok := index[strings.TrimSpace(depName)]
				if !ok || seen[t] {
					continue
				}
				seen[t] = true
				on = append(on, t)
				if r := strings.TrimSpace(rng); r != "" {
					byTarget[t] = r
				}
			}
			if len(on) > 0 {
				sort.Strings(on)
				deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on, Scope: scope, RequestedRanges: rangesFor(on, byTarget)})
			}
		}
	}
	emit(lock.Packages, baseScope)
	emit(lock.PackagesDev, sbom.ScopeDevelopment)
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return set.components(), deps, nil
}
