package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// NuGet is the owned.NET parser: it reads packages.lock.json – the resolved NuGet
// dependency set (the deterministic lockfile produced by `dotnet restore` with RestorePackagesWithLockFile)
// – into nuget components. The lockfile maps each target framework to its resolved packages; a package's
// "resolved" field is the concrete version. "Project" entries are local project references, not registry
// packages, and are skipped. Components only – edges are not emitted yet. Vendor-neutral (stdlib encoding/json).
type NuGet struct{}

// Ecosystem identifies this parser's package ecosystem.
func (NuGet) Ecosystem() string { return "nuget" }

// Markers are the lockfile basenames NuGet claims.
func (NuGet) Markers() []string { return []string{"packages.lock.json"} }

// nugetLock is the subset of packages.lock.json we parse: per-target-framework resolved packages.
type nugetLock struct {
	Dependencies map[string]map[string]nugetEntry `json:"dependencies"`
}

type nugetEntry struct {
	Type     string `json:"type"`     // Direct | Transitive | Project | CentralTransitive
	Resolved string `json:"resolved"` // the concrete resolved version
}

// Parse extracts the resolved NuGet packages across all target frameworks. A package resolved under several
// frameworks at the same version dedups (componentSet, by PURL); "Project" references are skipped. The result
// is sorted by PURL – packages.lock.json's per-framework maps have no inherent order, so sorting keeps the
// component list deterministic across runs (the other lockfile parsers iterate ordered slices already).
func (NuGet) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var lock nugetLock
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse packages.lock.json: %w", err)
	}
	scope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	for _, packages := range lock.Dependencies {
		for name, e := range packages {
			name, version := strings.TrimSpace(name), strings.TrimSpace(e.Resolved)
			if name == "" || version == "" || strings.EqualFold(e.Type, "Project") {
				continue // a Project entry is a local project reference, not a registry package
			}
			set.add(sbom.Component{
				Name:     name,
				Version:  version,
				PURL:     "pkg:nuget/" + name + "@" + version,
				Location: in.Path,
				Scope:    scope,
			})
		}
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}
