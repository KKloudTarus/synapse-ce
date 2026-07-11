package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Swift is the owned Swift Package Manager parser: it reads Package.resolved – the pinned
// dependency set – into swift components. It handles both the v1 layout (`object.pins[]`, each with a
// `package` name) and the v2/v3 layout (top-level `pins[]`, each with an `identity`); the resolved version
// is `state.version`. Components only; vendor-neutral (stdlib encoding/json). PURL uses the package identity
// (the canonical source-location form is a later refinement).
type Swift struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Swift) Ecosystem() string { return "swift" }

// Markers are the lockfile basenames Swift claims.
func (Swift) Markers() []string { return []string{"Package.resolved"} }

// swiftResolved spans the v1 (object.pins) and v2/v3 (top-level pins) Package.resolved layouts.
type swiftResolved struct {
	Pins   []swiftPin `json:"pins"`
	Object struct {
		Pins []swiftPin `json:"pins"`
	} `json:"object"`
}

type swiftPin struct {
	Identity string `json:"identity"` // v2/v3 name (lowercased repo identity)
	Package  string `json:"package"`  // v1 name
	State    struct {
		Version string `json:"version"`
	} `json:"state"`
}

// Parse extracts the pinned Swift packages. The package name is the v2/v3 `identity` or, failing that, the
// v1 `package`; the version is `state.version` (a branch/revision pin with no version is skipped – not
// version-matchable). Sorted by PURL for determinism; deduped by the shared componentSet.
func (Swift) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var doc swiftResolved
	if err := json.Unmarshal(in.Content, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse Package.resolved: %w", err)
	}
	pins := doc.Pins
	if len(pins) == 0 {
		pins = doc.Object.Pins // v1 layout
	}
	scope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	for _, p := range pins {
		name := strings.TrimSpace(p.Identity)
		if name == "" {
			name = strings.TrimSpace(p.Package)
		}
		version := strings.TrimSpace(p.State.Version)
		if name == "" || version == "" {
			continue // a branch/revision pin with no resolved version is not version-matchable
		}
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     "pkg:swift/" + name + "@" + version,
			Location: in.Path,
			Scope:    scope,
		})
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}
