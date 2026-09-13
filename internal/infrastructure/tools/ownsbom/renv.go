package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Renv is the owned R parser: it reads renv.lock – the resolved dependency set produced by the renv
// package manager – into cran components. renv.lock is JSON with a top-level "Packages" object mapping a
// package name to a record carrying its "Package", "Version", and a "Requirements" name list. The
// Requirements are NAME-ONLY (renv.lock records no declared version ranges), so edges carry no
// RequestedRanges — the strongest sound edge the format supports. Vendor-neutral (stdlib encoding/json).
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
	Package      string   `json:"Package"`      // the canonical package name (authoritative over the map key)
	Version      string   `json:"Version"`      // the concrete resolved version
	Requirements []string `json:"Requirements"` // dependency NAMES (no ranges); base R packages may be absent from Packages
}

// Parse extracts the resolved R packages from a renv.lock. The record's "Package" is preferred over the
// map key for the name (they normally agree); a record missing a name or version is skipped. Result is
// sorted by PURL – renv.lock's Packages object has no inherent order, so sorting keeps output deterministic.
func (Renv) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var lock renvLock
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse renv.lock: %w", err)
	}
	scope := sbom.ClassifyScope(in.Path, "")
	// Index each resolved package NAME to its PURL first: Requirements name other packages that may appear
	// anywhere in the (unordered) Packages object, and a name absent from Packages (a base R package) is left
	// unresolved so it never becomes a fabricated endpoint.
	nameOf := func(key string, p renvPackage) string {
		if n := strings.TrimSpace(p.Package); n != "" {
			return n
		}
		return strings.TrimSpace(key)
	}
	index := map[string]string{}
	for key, p := range lock.Packages {
		name, version := nameOf(key, p), strings.TrimSpace(p.Version)
		if name != "" && version != "" {
			index[name] = "pkg:cran/" + name + "@" + version
		}
	}

	set := newComponentSet()
	var deps []sbom.Dependency
	for key, p := range lock.Packages {
		name, version := nameOf(key, p), strings.TrimSpace(p.Version)
		if name == "" || version == "" {
			continue
		}
		ref := index[name]
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     ref,
			Location: in.Path,
			Scope:    scope,
		})
		seen := map[string]bool{ref: true} // drop self-edges + duplicate targets
		var on []string
		for _, req := range p.Requirements {
			t, ok := index[strings.TrimSpace(req)]
			if !ok || seen[t] { // an unresolved requirement (e.g. base R) contributes no edge
				continue
			}
			seen[t] = true
			on = append(on, t)
		}
		if len(on) > 0 {
			sort.Strings(on)
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on, Scope: scope})
		}
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return comps, deps, nil
}
