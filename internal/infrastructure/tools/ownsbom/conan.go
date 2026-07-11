package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Conan is the owned C/C++ parser: it reads conan.lock — the resolved dependency set produced by the
// Conan package manager — into conan components. Two lockfile shapes are handled: the Conan 2.x form,
// which lists reference strings under "requires"/"build_requires"/"python_requires", and the Conan 1.x
// form, which nests a "graph_lock" whose node "ref" fields carry the same reference strings. A reference
// is name/version[@user/channel][#recipe_revision]; the name and version are extracted from it. Components
// only — the 1.x graph edges are deferred. Vendor-neutral (stdlib encoding/json).
type Conan struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Conan) Ecosystem() string { return "conan" }

// Markers are the lockfile basenames Conan claims.
func (Conan) Markers() []string { return []string{"conan.lock"} }

// conanLock covers both lockfile shapes: the 2.x top-level reference lists and the 1.x graph_lock nodes.
type conanLock struct {
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
	GraphLock      struct {
		Nodes map[string]struct {
			Ref string `json:"ref"`
		} `json:"nodes"`
	} `json:"graph_lock"`
}

// Parse extracts the resolved Conan packages from a conan.lock across both shapes. Result is sorted by
// PURL — the 2.x lists are ordered but the 1.x nodes map is not, so sorting keeps output deterministic.
func (Conan) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var lock conanLock
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse conan.lock: %w", err)
	}
	scope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	add := func(ref string) {
		name, version := parseConanRef(ref)
		if name == "" || version == "" {
			return
		}
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     "pkg:conan/" + name + "@" + version,
			Location: in.Path,
			Scope:    scope,
		})
	}
	for _, refs := range [][]string{lock.Requires, lock.BuildRequires, lock.PythonRequires} {
		for _, ref := range refs {
			add(ref)
		}
	}
	for _, node := range lock.GraphLock.Nodes {
		add(node.Ref)
	}
	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, nil, nil
}

// parseConanRef splits a Conan reference name/version[@user/channel][#recipe_revision] into its name and
// version. The version is the segment after the first "/", cut at the first "@" (user/channel) or "#"
// (recipe revision). Returns empty strings when the ref has no version segment.
func parseConanRef(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	slash := strings.IndexByte(ref, '/')
	if slash <= 0 {
		return "", "" // a bare name with no version is not a resolved component
	}
	name := ref[:slash]
	rest := ref[slash+1:]
	if i := strings.IndexAny(rest, "@#"); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(name), strings.TrimSpace(rest)
}
