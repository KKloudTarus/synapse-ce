package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Renv is the owned R parser: it reads renv.lock — the resolved dependency set produced by the renv
// package manager — into cran components. renv.lock is JSON with a top-level "Packages" object mapping a
// package name to a record carrying its "Package" and "Version". Components only — renv records a per-
// package "Requirements" list, but those edges are deferred. Vendor-neutral (stdlib encoding/json).
type Renv struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Renv) Ecosystem() string { return "cran" }

// Markers are the lockfile basenames Renv claims.
func (Renv) Markers() []string { return []string{"renv.lock"} }

// renvLock is the subset of renv.lock we parse: the resolved package records.
type renvLock struct {
	Packages map[string]renvPackage `json:"Packages"`
}

type renvPackage struct {
	Package string `json:"Package"` // the canonical package name (authoritative over the map key)
	Version string `json:"Version"` // the concrete resolved version
}

// Parse extracts the resolved R packages from a renv.lock. The record's "Package" is preferred over the
// map key for the name (they normally agree); a record missing a name or version is skipped. Result is
// sorted by PURL — renv.lock's Packages object has no inherent order, so sorting keeps output deterministic.
func (Renv) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var lock renvLock
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse renv.lock: %w", err)
	}
	scope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	for key, p := range lock.Packages {
		name := strings.TrimSpace(p.Package)
		if name == "" {
			name = strings.TrimSpace(key)
		}
		version := strings.TrimSpace(p.Version)
		if name == "" || version == "" {
			continue
		}
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     "pkg:cran/" + name + "@" + version,
			Location: in.Path,
			Scope:    scope,
		})
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}
