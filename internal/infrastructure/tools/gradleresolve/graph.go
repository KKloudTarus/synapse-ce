package gradleresolve

import (
	"bufio"
	"bytes"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// parseGradleGraph parses the init script's stdout into components, dependency EDGES, and the unresolved
// list. It extends parseGradleDeps: alongside each `SYNAPSE_DEP group:module:version` component it reads the
// `SYNAPSE_EDGE parent|child` lines the init script prints from the resolution-result graph, where parent is
// either another `group:module:version` module or the sentinel `SYNAPSE_ROOT` (a project/subproject, i.e.
// the child is a DIRECT dependency).
//
// The emitted graph is rootless: the project is not a node, direct deps are graph roots (matching the native
// lockfile parsers and the Maven resolver), so IsDirect / PathToRoot / IntroducedBy report the direct
// dependencies as the introducers of a transitive CVE. An edge is kept only when BOTH endpoints are known
// SYNAPSE_DEP components, which drops platform/BOM and project-to-project edges (a platform is never printed
// as a component). Every edge carries the `runtime` scope because the init script resolves only
// runtimeClasspath (production; test/compileOnly are excluded), so ReachableScopes never deprioritizes a
// Gradle node. A childless direct dep is emitted as a bare Ref so it is still reported direct.
func parseGradleGraph(data []byte) (comps []sbom.Component, deps []sbom.Dependency, unresolved []string) {
	comps, unresolved = parseGradleDeps(data)
	// Build the g:m:v -> PURL lookup the edge lines use (Name is group:module, Version is version).
	gavToPurl := make(map[string]string, len(comps))
	for _, c := range comps {
		gavToPurl[c.Name+":"+c.Version] = c.PURL
	}

	edgeChildren := map[string]map[string][]string{} // parent PURL -> scope -> child PURLs
	var parentOrder []string
	var directOrder []string
	directSeen := map[string]bool{}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "SYNAPSE_EDGE ") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "SYNAPSE_EDGE "))
		parent, child, ok := strings.Cut(body, "|")
		if !ok {
			continue
		}
		parent, child = strings.TrimSpace(parent), strings.TrimSpace(child)
		childPurl, childKnown := gavToPurl[child]
		if !childKnown {
			continue // platform/BOM or a project child that never became a component
		}
		if parent == "SYNAPSE_ROOT" {
			if !directSeen[childPurl] {
				directSeen[childPurl] = true
				directOrder = append(directOrder, childPurl)
			}
			continue
		}
		parentPurl, parentKnown := gavToPurl[parent]
		if !parentKnown || parentPurl == childPurl {
			continue
		}
		if edgeChildren[parentPurl] == nil {
			edgeChildren[parentPurl] = map[string][]string{}
			parentOrder = append(parentOrder, parentPurl)
		}
		edgeChildren[parentPurl]["runtime"] = append(edgeChildren[parentPurl]["runtime"], childPurl)
	}

	for _, parent := range parentOrder {
		byScope := edgeChildren[parent]
		for _, scope := range sortedKeys(byScope) {
			deps = append(deps, sbom.Dependency{Ref: parent, DependsOn: dedupSorted(byScope[scope]), Scope: scope})
		}
	}
	for _, direct := range directOrder {
		if edgeChildren[direct] == nil {
			deps = append(deps, sbom.Dependency{Ref: direct})
		}
	}
	return comps, deps, unresolved
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
