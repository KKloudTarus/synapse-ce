package mavenresolve

import (
	"bufio"
	"bytes"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// rootCoordRE matches the FIRST line of `mvn dependency:tree` output: the project itself, printed with no
// scope (groupId:artifactId:type[:classifier]:version). The project is the tree root but is NOT emitted as
// a graph node; its direct dependencies (depth 1) are the graph roots, exactly as the native lockfile
// parsers emit them.
var rootCoordRE = regexp.MustCompile(`^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[A-Za-z0-9_.-]+:(?:[A-Za-z0-9_.-]+:)?([A-Za-z0-9_.+-]+)$`)

// treeBranch matches a Maven tree branch marker ("+- " or "\- ") that immediately precedes a coordinate;
// the text before the marker is indentation ("|  " / "   " groups, three chars per depth level).
var treeBranch = regexp.MustCompile(`[+\\]- `)

// parseDependencyTree parses `mvn dependency:tree` text output into the resolved Maven components AND the
// dependency EDGES (parent -> child), capturing each edge's Maven scope. It is the testable core (no exec).
//
// The graph is ROOTLESS: the project line is dropped and the direct dependencies (depth 1) are the graph
// roots, matching the native lockfile parsers, so IsDirect / PathToRoot / IntroducedBy report the DIRECT
// dependencies (not the project) as the introducers of a transitive CVE. Test-scope nodes are dropped (not
// shipped, and Maven already narrows a compile dep pulled in only by a test dep to `test`, so dropping every
// `test` line drops the whole test subtree). Non-test nodes therefore form one connected forest under the
// direct deps, so a kept node's parent is another kept node. Components are deduplicated by PURL; transitive
// edges carry the child's scope (compile/runtime -> production, provided/system -> provided) so
// ReachableScopes can deprioritize a provided-only transitive. A childless direct dep is emitted as a bare
// Ref so it is still in-graph and reported direct.
func parseDependencyTree(data []byte) ([]sbom.Component, []sbom.Dependency) {
	var components []sbom.Component
	seenComp := map[string]bool{}
	edgeChildren := map[string]map[string][]string{} // parent PURL -> scope -> child PURLs (transitive edges)
	var parentOrder []string
	var directOrder []string
	directSeen := map[string]bool{}
	stack := map[int]string{} // depth -> kept-node PURL

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	first := true
	for sc.Scan() {
		// Strip an optional "[INFO] " logger prefix (batch-mode mvn) but PRESERVE the tree indentation that
		// follows, since depth is computed from it. TrimSpace here would erase a space-only indent and mis-
		// depth a prefixless tree.
		line := strings.TrimRight(sc.Text(), " \t\r")
		if strings.HasPrefix(line, "[INFO]") {
			line = strings.TrimPrefix(strings.TrimPrefix(line, "[INFO]"), " ")
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if first {
			if rootCoordRE.MatchString(strings.TrimSpace(line)) {
				first = false
			}
			continue
		}
		loc := treeBranch.FindStringIndex(line)
		if loc == nil {
			continue
		}
		depth := loc[1] / 3 // three indentation chars per level; the marker itself is the last group
		if depth < 1 {
			continue
		}
		// Everything on the stack at this depth or deeper belongs to an already-closed sibling subtree; clear
		// it so a node never attaches to a stale ancestor (e.g. a skipped test sibling's slot).
		for k := range stack {
			if k >= depth {
				delete(stack, k)
			}
		}
		m := coordRE.FindStringSubmatch(strings.TrimSpace(line[loc[1]:]))
		if m == nil {
			continue
		}
		group, artifact, version, scope := m[1], m[2], m[3], m[4]
		if scope == "test" || scope == "import" {
			continue // skipped; its slot at this depth stays cleared so descendants cannot attach to it
		}
		purl := "pkg:maven/" + group + "/" + artifact + "@" + version
		stack[depth] = purl
		if !seenComp[purl] {
			seenComp[purl] = true
			components = append(components, sbom.Component{
				Name: group + ":" + artifact, Version: version, PURL: purl, Scope: sbom.ScopeProduction,
			})
		}
		if depth == 1 {
			if !directSeen[purl] {
				directSeen[purl] = true
				directOrder = append(directOrder, purl)
			}
			continue
		}
		parent, ok := stack[depth-1]
		if !ok || parent == "" {
			continue // parent was skipped (test/import): keep the component, but emit no false edge
		}
		if edgeChildren[parent] == nil {
			edgeChildren[parent] = map[string][]string{}
			parentOrder = append(parentOrder, parent)
		}
		edgeChildren[parent][scope] = append(edgeChildren[parent][scope], purl)
	}

	var deps []sbom.Dependency
	for _, parent := range parentOrder {
		byScope := edgeChildren[parent]
		for _, scope := range sortedKeys(byScope) {
			deps = append(deps, sbom.Dependency{Ref: parent, DependsOn: dedupSorted(byScope[scope]), Scope: scope})
		}
	}
	// A childless direct dep must still appear in-graph so it is reported direct; one that is an edge parent
	// already is.
	for _, direct := range directOrder {
		if edgeChildren[direct] == nil {
			deps = append(deps, sbom.Dependency{Ref: direct})
		}
	}
	return components, deps
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
