// Package callgraph is the deterministic call-graph domain model (Tier-2 shared foundation): a
// directed graph of function-call edges plus the entrypoints reachability is measured from, and the pure
// query primitives over it. It is the SEAM both Tier-2 consumers build on – reachability PROOF
// ("is this vulnerable symbol actually called?") and taint SAST ("does a source reach a sink?").
//
// The model is deterministic and tool-agnostic: a builder adapter (Go SSA / govulncheck-class, shelled
// via argv) produces a Graph; the queries here are pure Go, so they are table-testable with no
// tool and a Tier-2 result is reproducible. Node identity is the same "importPath.Symbol" convention the
// OSV adapter emits for a vulnerability's affected symbols – so a reachability query can intersect
// call-graph nodes with a vuln's AffectedSymbols directly, with no translation.
//
// SCOPE: this models REACHABILITY (does a call path exist). Taint analysis needs richer edges –
// which argument/return flows, and sanitizer nodes that break a path – so it layers its OWN edge-attribute
// + sanitizer model on top of this node-identity convention rather than stretching Edge with optional
// taint fields (which would degrade the reachability primitive). Edge here stays a plain call edge.
package callgraph

// Edge is one node's outgoing calls: Caller calls each symbol in Callees. Symbols are
// "importPath.Symbol" identities (e.g. "github.com/foo/bar.Vuln"), matching vulnerability AffectedSymbols.
type Edge struct {
	Caller  string
	Callees []string
}

// Graph is a deterministic call graph: the call Edges plus the Entrypoints reachability is measured from
// (a Go build's main + exported API). A builder adapter populates it; the query methods are pure.
type Graph struct {
	Entrypoints []string
	Edges       []Edge
}

// adjacency builds the caller -> callees map once, for the multi-target queries to share. Empty node
// identities are dropped – a node id must be a real "importPath.Symbol"; the builder is an
// untrusted producer, so an empty caller/callee would otherwise pollute the reachable set or yield a path
// ending in "". Multiple edges with the same Caller are merged (append), so a builder may emit them split.
func (g Graph) adjacency() map[string][]string {
	adj := make(map[string][]string, len(g.Edges))
	for _, e := range g.Edges {
		if e.Caller == "" {
			continue
		}
		for _, c := range e.Callees {
			if c != "" {
				adj[e.Caller] = append(adj[e.Caller], c)
			}
		}
	}
	return adj
}

// Reachable returns the set of symbols reachable from any entrypoint by following call edges forward
// (the entrypoints themselves are included). Cycle-safe. Build once, then test many candidate symbols
// against it – the shape it wants when filtering a vuln's AffectedSymbols to the reachable ones.
func (g Graph) Reachable() map[string]bool {
	adj := g.adjacency()
	seen := make(map[string]bool, len(adj))
	var queue []string
	for _, e := range g.Entrypoints {
		if e != "" && !seen[e] {
			seen[e] = true
			queue = append(queue, e)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range adj[n] {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	return seen
}

// PathTo returns a shortest call path from an entrypoint to target as [entrypoint,..., target] – the
// PROOF that target is reachable (an explainable "main → … → vulnFunc" chain). It returns nil when
// target is unreachable from every entrypoint (including when target is not in the graph). A
// single-element path means target is itself an entrypoint. BFS, so the path is shortest; cycle-safe.
// When several shortest paths exist, the one via the earliest entrypoint then earliest edge order wins –
// deterministic for a fixed Graph (golden tests + the human-facing reachability proof depend on this).
func (g Graph) PathTo(target string) []string {
	if target == "" {
		return nil
	}
	adj := g.adjacency()
	seen := map[string]bool{}
	type node struct {
		id   string
		path []string
	}
	var queue []node
	for _, e := range g.Entrypoints {
		if e == "" || seen[e] {
			continue
		}
		if e == target {
			return []string{e} // target is itself an entrypoint
		}
		seen[e] = true
		queue = append(queue, node{e, []string{e}})
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range adj[n.id] {
			if seen[c] {
				continue
			}
			np := append(append([]string{}, n.path...), c)
			if c == target {
				return np // reached target – shortest path (BFS)
			}
			seen[c] = true
			queue = append(queue, node{c, np})
		}
	}
	return nil // unreachable
}

// Reaches reports whether target is reachable from any entrypoint.
func (g Graph) Reaches(target string) bool {
	return g.PathTo(target) != nil
}
