package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Conan is the owned C/C++ parser. It reads conan.lock, the resolved
// dependency set produced by the Conan package manager, into Conan
// components.
//
// Two lockfile shapes are supported: Conan 2.x lists reference strings under
// requires, build_requires, and python_requires. Conan 1.x stores package
// references and graph relationships in graph_lock nodes. References use the
// form name/version[@user/channel][#recipe_revision].
//
// Conan 1.x requires and build_requires node IDs emit deterministic dependency
// relationships. Node-level python_requires references are emitted as development- or
// background-scoped components only because Conan stores a transitive
// reference closure rather than direct graph node IDs. The parser uses only
// the Go standard library.
type Conan struct{}

// Ecosystem identifies this parser's package ecosystem.
func (Conan) Ecosystem() string { return "conan" }

// Markers are the lockfile basenames Conan claims.
func (Conan) Markers() []string { return []string{"conan.lock", "conanfile.txt"} }

type conanLockNode struct {
	Ref            string   `json:"ref"`
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
}

// conanLock covers both lockfile shapes: the 2.x top-level reference lists and the 1.x graph_lock nodes.
type conanLock struct {
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
	GraphLock      struct {
		Nodes map[string]conanLockNode `json:"nodes"`
	} `json:"graph_lock"`
}

// Parse extracts resolved Conan components and, for Conan 1.x graph_lock
// files, dependency relationships from requires and build_requires.
// Node-level python_requires references are included as components but are
// not inferred as direct dependency edges.
// Results are sorted deterministically because Conan 1.x nodes are stored in a
// JSON object and therefore decoded into a Go map with unspecified iteration order.
func (Conan) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if strings.ToLower(filepath.Base(in.Path)) == "conanfile.txt" {
		// A resolved lockfile beside the manifest takes precedence; an Lstat is enough to test existence
		// (the registry reads + parses conan.lock on its own marker pass).
		if fi, err := os.Lstat(filepath.Join(in.Dir, "conan.lock")); err == nil && fi.Mode().IsRegular() {
			return nil, nil, nil
		}
		return parseConanTxt(ctx, in)
	}
	var lock conanLock
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse conan.lock: %w", err)
	}
	normalizeRef := func(ref string) (string, string, string, bool) {
		name, version := parseConanRef(ref)
		if name == "" || version == "" {
			return "", "", "", false
		}
		purl := "pkg:conan/" + name + "@" + version
		return name, version, purl, true
	}

	// Scope build/python requires as development (build-time tooling), matching the conanfile.txt mapping
	// of [tool_requires]; the path scope may already be a background one, which wins.
	prod := sbom.ClassifyScope(in.Path, "")
	dev := prod
	if !sbom.IsBackgroundScope(prod) {
		dev = sbom.ScopeDevelopment
	}
	set := newComponentSet()
	add := func(ref, scope string) {
		name, version, purl, ok := normalizeRef(ref)
		if !ok {
			return
		}
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     purl,
			Location: in.Path,
			Scope:    scope,
		})
	}
	for _, ref := range lock.Requires {
		add(ref, prod)
	}
	for _, ref := range lock.BuildRequires {
		add(ref, dev)
	}
	for _, ref := range lock.PythonRequires {
		add(ref, dev)
	}

	// Pass 1: Build a deterministic index of valid node IDs to normalized PURLs, and add components
	// (1.x graph nodes carry no requires-kind, so scope by path).
	nodePURL := make(map[string]string, len(lock.GraphLock.Nodes))
	nodeIDs := make([]string, 0, len(lock.GraphLock.Nodes))
	for id := range lock.GraphLock.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	for _, id := range nodeIDs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		ref := lock.GraphLock.Nodes[id].Ref
		name, version, purl, ok := normalizeRef(ref)
		if !ok {
			continue
		}
		nodePURL[id] = purl
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     purl,
			Location: in.Path,
			Scope:    prod,
		})
	}

	// Add node-level python_requires after all regular graph components so a
	// package present in both forms retains its path-derived graph scope.
	for _, id := range nodeIDs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		for _, ref := range lock.GraphLock.Nodes[id].PythonRequires {
			add(ref, dev)
		}
	}

	// Pass 2: Aggregate valid dependency edges according to PURL identity, ignoring self-edges.
	edgesByRef := make(map[string]map[string]struct{})
	for _, id := range nodeIDs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		source := nodePURL[id]
		if source == "" {
			continue
		}
		node := lock.GraphLock.Nodes[id]
		targetIDs := make([]string, 0, len(node.Requires)+len(node.BuildRequires))
		targetIDs = append(targetIDs, node.Requires...)
		targetIDs = append(targetIDs, node.BuildRequires...)

		for _, targetID := range targetIDs {
			target := nodePURL[targetID]
			if target == "" || target == source {
				continue
			}
			if edgesByRef[source] == nil {
				edgesByRef[source] = make(map[string]struct{})
			}
			edgesByRef[source][target] = struct{}{}
		}
	}

	// Materialize deterministic graph edges
	var deps []sbom.Dependency
	refs := make([]string, 0, len(edgesByRef))
	for ref := range edgesByRef {
		refs = append(refs, ref) // every entry has at least one target by construction
	}
	sort.Strings(refs)

	for _, ref := range refs {
		dependsOn := make([]string, 0, len(edgesByRef[ref]))
		for target := range edgesByRef[ref] {
			dependsOn = append(dependsOn, target)
		}
		sort.Strings(dependsOn)
		deps = append(deps, sbom.Dependency{
			Ref:       ref,
			DependsOn: dependsOn,
		})
	}

	comps := set.components()
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	return comps, deps, nil
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
