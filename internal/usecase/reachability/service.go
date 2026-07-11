// Package reachability is the Tier-2 reachability query API: it wraps a
// ports.CallGraphBuilder + the deterministic callgraph domain queries into the service consumers
// use to turn "is this vulnerable symbol actually called?" into an evidence-backed reachability
// judgment. It is pure deterministic orchestration – no LLM, no persistence, no engagement state – so it
// is table-testable with a fake builder.
//
// COVERAGE vs NOT-REACHABLE (the load-bearing distinction): a build error from the builder means the
// target had NO call-graph coverage (un-buildable module, unsupported language) – the caller must fall
// back to a lower reachability tier, NEVER record a false "not reachable". A successful build that simply
// does not reach a symbol is a definitive "not reachable" for that symbol. Analyze surfaces the first as
// an error and the second as Result{Reachable:false}.
package reachability

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Result is one symbol's reachability verdict. Path is the proof – a shortest entrypoint→symbol call
// chain ("main → … → vulnFunc") – present only when Reachable.
type Result struct {
	Symbol    string
	Reachable bool
	Path      []string
}

// Analysis is the outcome of a successful reachability run: the per-symbol verdicts plus the Entrypoints
// the graph was measured from. Entrypoints is the provenance sealed with the Tier-2 judgment ("proven
// reachable from these roots") – and a zero-entrypoint analysis is a soft no-coverage signal a consumer
// may choose to treat as inconclusive rather than definitive.
type Analysis struct {
	Results     []Result
	Entrypoints []string
}

// Service answers reachability queries for a target by building its call graph once and querying it.
type Service struct {
	builder ports.CallGraphBuilder
}

// NewService validates and returns the reachability service.
func NewService(builder ports.CallGraphBuilder) (*Service, error) {
	if builder == nil {
		return nil, fmt.Errorf("%w: reachability service needs a call-graph builder", shared.ErrValidation)
	}
	return &Service{builder: builder}, nil
}

// Analyze builds the target's call graph ONCE, then resolves each symbol to a reachability Result. The
// symbols are vulnerability AffectedSymbols (the "importPath.Symbol" form the builder emits – no
// translation). Input order is preserved; duplicate symbols are de-duplicated.
//
// A builder error (or a nil graph from a misbehaving builder) means NO coverage and is returned as an
// error → the caller falls back to a lower tier, NOT a false "not reachable". A successful, non-nil graph
// is definitive: every queried symbol gets a Result (Reachable + Path when called).
func (s *Service) Analyze(ctx context.Context, targetRef string, symbols []string) (*Analysis, error) {
	g, err := s.builder.Build(ctx, targetRef)
	if err != nil {
		return nil, fmt.Errorf("build call graph for %q: %w", targetRef, err) // no coverage – caller falls back
	}
	if g == nil {
		// A builder must return an (empty) graph on success; a nil graph is a builder bug, treated as
		// no-coverage rather than dereferenced (callgraph.Graph has value receivers) or read as "nothing
		// reachable" – fail safe toward tier-fallback, never a false negative.
		return nil, fmt.Errorf("build call graph for %q: %w: builder returned no graph", targetRef, shared.ErrValidation)
	}
	reachable := g.Reachable() // build the reachable set once, query many symbols against it
	out := make([]Result, 0, len(symbols))
	seen := map[string]bool{}
	for _, sym := range symbols {
		if sym == "" || seen[sym] {
			continue
		}
		seen[sym] = true
		r := Result{Symbol: sym}
		if reachable[sym] {
			r.Reachable = true
			r.Path = g.PathTo(sym) // the proof chain for the human-facing reachability judgment
		}
		out = append(out, r)
	}
	return &Analysis{Results: out, Entrypoints: g.Entrypoints}, nil
}
