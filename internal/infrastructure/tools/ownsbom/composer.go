package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Composer is the owned PHP parser: it reads composer.lock — the resolved dependency set —
// into composer components. composer.lock is JSON with two arrays: "packages" (production) and
// "packages-dev" (development), each entry {name: "vendor/package", version}. The dev split is INLINE in
// the lock (no companion needed). Components only — each package's "require" edges are deferred.
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
	set := newComponentSet()
	add := func(pkgs []composerPkg, scope string) {
		for _, p := range pkgs {
			name, version := strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
			if name == "" || version == "" {
				continue // an entry missing identity is dropped (componentSet would drop it anyway)
			}
			comp := sbom.Component{
				Name:     name,
				Version:  version,
				PURL:     "pkg:composer/" + name + "@" + version,
				Location: in.Path,
				Scope:    scope,
			}
			if s := strings.TrimSpace(p.Dist.Shasum); s != "" {
				comp.Checksums = []sbom.Checksum{{Algorithm: "SHA1", Value: s}}
			}
			set.add(comp)
		}
	}
	add(lock.Packages, baseScope)
	add(lock.PackagesDev, sbom.ScopeDevelopment)
	return set.components(), nil, nil
}
