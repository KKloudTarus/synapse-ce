// Package taint is the deterministic taint-analysis domain model: a data-flow
// graph from untrusted SOURCES to dangerous SINKS, with SANITIZER nodes that neutralize a flow, plus the
// pure query that reports an injection – a source→sink path that crosses no sanitizer.
//
// It deliberately layers its OWN edge + role model on the shared "importPath.Symbol" node-identity
// convention (the one the call-graph + OSV affected-symbols use) rather than reusing callgraph.Edge
// a call edge says "A calls B"; a taint Flow says "tainted data moves A→B", and taint needs
// source/sink/sanitizer ROLES a plain call edge cannot carry. Like the callgraph seam, the queries are
// pure Go – deterministic + table-testable with no tool – so a Tier-2 taint result is reproducible and a
// builder adapter (over the shared call-graph engine) just populates the graph.
package taint

import "sort"

// Flow is one data-flow edge: tainted data moves From → To. Node identities are "importPath.Symbol".
type Flow struct {
	From string
	To   string
}

// FlowGraph is a deterministic taint graph: data-flow edges + the role sets. A Source introduces
// untrusted data; a Sink is a dangerous operation; a Sanitizer neutralizes data flowing through it (a
// flow that passes a sanitizer is clean past that point).
type FlowGraph struct {
	Sources    []string
	Sinks      []string
	Sanitizers []string
	Flows      []Flow
}

// TaintPath is a proven injection: untrusted data flows from Source to Sink with no sanitizer between –
// Path is the witness [source, …, sink], the explainable proof.
type TaintPath struct {
	Source string
	Sink   string
	Path   []string
}

func toSet(xs []string) map[string]bool {
	s := make(map[string]bool, len(xs))
	for _, x := range xs {
		if x != "" {
			s[x] = true
		}
	}
	return s
}

// adjacency builds the From → []To map once (empty endpoints dropped – the builder is untrusted).
func (g FlowGraph) adjacency() map[string][]string {
	adj := make(map[string][]string, len(g.Flows))
	for _, f := range g.Flows {
		if f.From != "" && f.To != "" {
			adj[f.From] = append(adj[f.From], f.To)
		}
	}
	return adj
}

// Vulnerabilities returns one shortest unsanitized source→sink path per (source, sink) pair that is
// reachable without crossing a sanitizer – i.e. the injection findings. A sanitizer node is a WALL: the
// search never expands out of it (data leaving a sanitizer is clean), so a sink reachable only through a
// sanitizer is correctly NOT reported. A source that is itself a sink is reported as a length-1 path.
// BFS (shortest witness) + cycle-safe; results are sorted (source, then sink) for deterministic output.
func (g FlowGraph) Vulnerabilities() []TaintPath {
	adj := g.adjacency()
	sinks := toSet(g.Sinks)
	sanitizers := toSet(g.Sanitizers)

	var out []TaintPath
	srcSeen := map[string]bool{} // dedup sources: a builder may emit the same source symbol twice
	for _, src := range g.Sources {
		if src == "" || srcSeen[src] {
			continue
		}
		srcSeen[src] = true
		found := map[string]bool{}         // sinks already reported for this source (shortest wins)
		seen := map[string]bool{src: true} // per-source visited; safe because sanitizers never enqueue successors
		type node struct {
			id   string
			path []string
		}
		queue := []node{{src, []string{src}}}
		// A source that is itself a sink (and not a sanitizer) is an immediate finding.
		if sinks[src] && !sanitizers[src] {
			out = append(out, TaintPath{Source: src, Sink: src, Path: []string{src}})
			found[src] = true
		}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if sanitizers[n.id] {
				continue // wall: data leaving a sanitizer is clean – do not expand
			}
			for _, to := range adj[n.id] {
				if seen[to] {
					continue
				}
				seen[to] = true
				np := append(append([]string{}, n.path...), to)
				if sinks[to] && !sanitizers[to] && !found[to] {
					out = append(out, TaintPath{Source: src, Sink: to, Path: np})
					found[to] = true
				}
				queue = append(queue, node{to, np})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Sink < out[j].Sink
	})
	return out
}

// Vulnerable reports whether any unsanitized source→sink flow exists.
func (g FlowGraph) Vulnerable() bool { return len(g.Vulnerabilities()) > 0 }
