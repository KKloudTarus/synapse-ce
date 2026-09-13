package taint

// Taint labels + preconditions (Semgrep taint-labels, EPIC #1042 2.3). A source can carry a LABEL, and a
// sink can REQUIRE a set of labels: the sink is a FULL match only when a source carrying each required label
// reaches it unsanitized. When not every required label is proven to reach, the flow is CONDITIONALLY
// reachable, NEVER suppressed, because the coarse function-granular model cannot prove a label's absence
// (fail-open: an unknown precondition can only lower confidence, never hide a finding).

// Precondition is the evaluation of a sink's Requires against the labels proven to reach it.
type Precondition string

const (
	// PreconditionNone: the sink has no label precondition (classic single-label taint).
	PreconditionNone Precondition = "none"
	// PreconditionSatisfied: every required label is carried by a source that reaches the sink.
	PreconditionSatisfied Precondition = "satisfied"
	// PreconditionUnknown: the sink is reached, but not every required label is proven to reach it. The
	// flow is conditionally reachable; it is never suppressed (the model cannot prove the label's absence).
	PreconditionUnknown Precondition = "unknown"
)

// LabelsReaching returns, for each node reachable from a labeled source without crossing a sanitizer, the
// set of source labels that reach it. It runs the same sanitizer-walled forward search as Vulnerabilities,
// unioning each labeled source's label into every node it reaches. A source with no SourceLabels entry
// contributes the default (empty) label, which is only relevant to a sink that requires the empty label.
func (g FlowGraph) LabelsReaching() map[string]map[string]bool {
	adj := g.adjacency()
	sanitizers := toSet(g.Sanitizers)
	out := map[string]map[string]bool{}
	add := func(node, label string) {
		if out[node] == nil {
			out[node] = map[string]bool{}
		}
		out[node][label] = true
	}
	seenSrc := map[string]bool{}
	for _, src := range g.Sources {
		if src == "" || seenSrc[src] {
			continue
		}
		seenSrc[src] = true
		label := g.SourceLabels[src]
		// Forward BFS from this source, walled by sanitizers (a node past a sanitizer is clean, so its
		// label does not propagate through), mirroring Vulnerabilities exactly.
		visited := map[string]bool{src: true}
		queue := []string{src}
		add(src, label)
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if sanitizers[n] {
				continue // wall: do not propagate the label past a sanitizer
			}
			for _, to := range adj[n] {
				if visited[to] {
					continue
				}
				visited[to] = true
				add(to, label)
				queue = append(queue, to)
			}
		}
	}
	return out
}

// EvaluatePrecondition classifies a sink's Requires against the labels proven to reach a node (from
// LabelsReaching). Empty requires => PreconditionNone. Every required label present => PreconditionSatisfied.
// Otherwise => PreconditionUnknown (conditionally reachable, never a suppression). A required empty-string
// label is ignored so a malformed rule cannot force every flow conditional.
func EvaluatePrecondition(reached map[string]bool, requires []string) Precondition {
	need := 0
	for _, r := range requires {
		if r == "" {
			continue
		}
		need++
		if !reached[r] {
			return PreconditionUnknown
		}
	}
	if need == 0 {
		return PreconditionNone
	}
	return PreconditionSatisfied
}
