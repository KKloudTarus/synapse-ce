package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// NuGetAssets is the owned .NET parser for project.assets.json, the restore graph `dotnet restore` writes to
// obj/. Unlike packages.lock.json (opt-in, RestorePackagesWithLockFile), project.assets.json is ALWAYS produced
// by a restore, so it recovers the resolved NuGet graph for projects that do not enable the lockfile. Its
// `targets` map holds, per target framework, an entry keyed "<Name>/<Version>" (the concrete resolved version)
// carrying a `dependencies` map of dependency name -> version RANGE. Each dependency is resolved to a concrete
// version by looking the name up in the SAME framework's resolved set (resolution-as-filter: an edge is kept
// only when its target resolved there), so edges carry concrete identities, never ranges. "project" entries
// (local project references) are skipped as sources and edge targets. Vendor-neutral (stdlib encoding/json).
type NuGetAssets struct{}

// Ecosystem identifies this parser's package ecosystem.
func (NuGetAssets) Ecosystem() string { return "nuget" }

// Markers are the restore-output basenames NuGetAssets claims.
func (NuGetAssets) Markers() []string { return []string{"project.assets.json"} }

// nugetAssets is the subset of project.assets.json we parse: per-target-framework resolved packages.
type nugetAssets struct {
	Targets map[string]map[string]nugetAssetEntry `json:"targets"`
}

type nugetAssetEntry struct {
	Type         string            `json:"type"`         // package | project | ...
	Dependencies map[string]string `json:"dependencies"` // dependency name -> version RANGE (the graph edges)
}

// Parse extracts the resolved NuGet packages and their edges across all target frameworks. A package resolved
// under several frameworks at the same version dedups (componentSet, by PURL); "project" references are
// skipped. Output is sorted by PURL for determinism.
func (NuGetAssets) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var assets nugetAssets
	if err := json.Unmarshal(in.Content, &assets); err != nil {
		return nil, nil, fmt.Errorf("parse project.assets.json: %w", err)
	}
	scope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()

	frameworks := make([]string, 0, len(assets.Targets))
	for fw := range assets.Targets {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)

	// Pass 1: per-framework resolved index (lowercased name -> {canonical name, version}), from the
	// "<Name>/<Version>" target keys. NuGet ids are case-insensitive, so a dependency written with different
	// casing than the resolved key still resolves. Project entries are excluded.
	resolvedByFw := make(map[string]map[string]nugetResolved, len(frameworks))
	for _, fw := range frameworks {
		m := make(map[string]nugetResolved, len(assets.Targets[fw]))
		keys := make([]string, 0, len(assets.Targets[fw]))
		for key := range assets.Targets[fw] {
			keys = append(keys, key)
		}
		sort.Strings(keys) // deterministic even for a malformed assets file with case-only duplicate ids
		for _, key := range keys {
			e := assets.Targets[fw][key]
			if strings.EqualFold(e.Type, "project") {
				continue
			}
			name, version, ok := splitNuGetAssetKey(key)
			if !ok {
				continue
			}
			m[strings.ToLower(name)] = nugetResolved{name: name, version: version}
		}
		resolvedByFw[fw] = m
	}
	// resolve looks a dependency id up in its framework, falling back to the base TFM for a `{TFM}/{RID}`
	// runtime-identifier section (a DELTA over the base closure), mirroring the packages.lock.json parser.
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
		keys := make([]string, 0, len(assets.Targets[fw]))
		for key := range assets.Targets[fw] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			e := assets.Targets[fw][key]
			if strings.EqualFold(e.Type, "project") {
				continue // a project entry is a local project reference, not a registry package
			}
			name, version, ok := splitNuGetAssetKey(key)
			if !ok {
				continue
			}
			ref := "pkg:nuget/" + name + "@" + version
			set.add(sbom.Component{
				Name:     name,
				Version:  version,
				PURL:     ref,
				Location: in.Path,
				Scope:    scope,
			})
			depNames := make([]string, 0, len(e.Dependencies))
			for dn := range e.Dependencies {
				depNames = append(depNames, dn)
			}
			sort.Strings(depNames)
			for _, dn := range depNames {
				r, ok := resolve(fw, dn)
				if !ok {
					continue // unresolved / project dependency: no edge (resolution-as-filter)
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
	refs := make([]string, 0, len(edgeTargets))
	for ref := range edgeTargets {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	var edges []sbom.Dependency
	for _, ref := range refs {
		if on := edgeTargets[ref]; len(on) > 0 {
			edges = append(edges, sbom.Dependency{Ref: ref, DependsOn: on, Scope: scope})
		}
	}
	return comps, edges, nil
}

// splitNuGetAssetKey splits a project.assets.json target key "<Name>/<Version>" into its name and version. A
// NuGet id and version contain no "/", so a single cut is exact.
func splitNuGetAssetKey(key string) (name, version string, ok bool) {
	name, version, ok = strings.Cut(strings.TrimSpace(key), "/")
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if !ok || name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
