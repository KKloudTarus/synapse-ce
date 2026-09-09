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
// – into nuget components AND the dependency graph. The lockfile maps each target framework to its resolved
// packages; a package's "resolved" field is the concrete version, and its "dependencies" field is a map of
// dependency name to version RANGE. Each dependency is resolved to a concrete version by looking the name up
// in the SAME framework's resolved-package map (resolution-as-filter: an edge is kept only when its target is
// a resolved package there), so the emitted edges carry concrete name@version identities, never the ranges.
// "Project" entries are local project references, not registry packages, and are skipped (as sources and as
// edge targets). Vendor-neutral (stdlib encoding/json).
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
	Type         string            `json:"type"`         // Direct | Transitive | Project | CentralTransitive
	Resolved     string            `json:"resolved"`     // the concrete resolved version
	Dependencies map[string]string `json:"dependencies"` // dependency name → version RANGE (the graph edges)
}

// nugetResolved is a resolved package's canonical name (as the lockfile spelled it) and concrete version,
// indexed by lowercased id so case-insensitive NuGet dependency references still resolve.
type nugetResolved struct {
	name    string
	version string
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
	// Iterate frameworks in name order so the accumulation (and thus the merged target order) is deterministic
	// across runs, regardless of the JSON map's iteration order.
	frameworks := make([]string, 0, len(lock.Dependencies))
	for fw := range lock.Dependencies {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)

	// Pass 1: per-framework resolved index, keyed by the LOWERCASED id (NuGet ids are case-insensitive), so a
	// dependency written with different casing than the resolved entry still resolves. The value keeps the
	// resolved entry's canonical name so the target PURL matches the emitted component's PURL. Project entries
	// are excluded (as sources and as edge targets).
	resolvedByFw := make(map[string]map[string]nugetResolved, len(frameworks))
	for _, fw := range frameworks {
		m := make(map[string]nugetResolved, len(lock.Dependencies[fw]))
		for name, e := range lock.Dependencies[fw] {
			if n, v := strings.TrimSpace(name), strings.TrimSpace(e.Resolved); n != "" && v != "" && !strings.EqualFold(e.Type, "Project") {
				m[strings.ToLower(n)] = nugetResolved{name: n, version: v}
			}
		}
		resolvedByFw[fw] = m
	}
	// resolve looks a dependency id up in its framework, falling back to the base TFM for a `{TFM}/{RID}`
	// section: a runtime-identifier target is a DELTA over the base TFM closure, not an independent closure, so
	// an edge from a RID-only package to a base-TFM package must still resolve.
	resolve := func(fw, depID string) (nugetResolved, bool) {
		key := strings.ToLower(strings.TrimSpace(depID))
		if r, ok := resolvedByFw[fw][key]; ok {
			return r, true
		}
		if base, _, isRID := strings.Cut(fw, "/"); isRID {
			if r, ok := resolvedByFw[base][key]; ok {
				return r, true
			}
		}
		return nugetResolved{}, false
	}

	// Pass 2: emit components and edges. edgeTargets accumulates, per source PURL, the ordered set of resolved
	// dependency PURLs; a package appearing under several frameworks merges its edges by source PURL.
	edgeTargets := map[string][]string{}
	edgeSeen := map[string]map[string]bool{}
	for _, fw := range frameworks {
		for name, e := range lock.Dependencies[fw] {
			name, version := strings.TrimSpace(name), strings.TrimSpace(e.Resolved)
			if name == "" || version == "" || strings.EqualFold(e.Type, "Project") {
				continue // a Project entry is a local project reference, not a registry package
			}
			ref := "pkg:nuget/" + name + "@" + version
			set.add(sbom.Component{
				Name:     name,
				Version:  version,
				PURL:     ref,
				Location: in.Path,
				Scope:    scope,
			})
			// Resolve each declared dependency (name → range) to the concrete package restored for this
			// framework. Dependency names are sorted so the per-package target order is deterministic.
			depNames := make([]string, 0, len(e.Dependencies))
			for dn := range e.Dependencies {
				depNames = append(depNames, dn)
			}
			sort.Strings(depNames)
			for _, dn := range depNames {
				r, ok := resolve(fw, dn)
				if !ok {
					continue // unresolved / Project dependency: no edge (resolution-as-filter)
				}
				target := "pkg:nuget/" + r.name + "@" + r.version
				if target == ref {
					continue // no self-edge
				}
				if edgeSeen[ref] == nil {
					edgeSeen[ref] = map[string]bool{}
				}
				if edgeSeen[ref][target] {
					continue
				}
				edgeSeen[ref][target] = true
				edgeTargets[ref] = append(edgeTargets[ref], target)
			}
		}
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	// Emit edges in source-PURL order (deterministic); targets keep their first-seen order.
	refs := make([]string, 0, len(edgeTargets))
	for ref := range edgeTargets {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	var edges []sbom.Dependency
	for _, ref := range refs {
		if on := edgeTargets[ref]; len(on) > 0 {
			edges = append(edges, sbom.Dependency{Ref: ref, DependsOn: on})
		}
	}
	return comps, edges, nil
}
