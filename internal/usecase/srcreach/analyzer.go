// Package srcreach implements deterministic Tier-1 reachability over a first-party source import scan,
// shared by every language whose dependency usage is observable as an import/require/use statement.
//
// SAFETY: an "unreachable" verdict suppresses work, so a false unreachable is worse than no verdict. The
// analyzer therefore REFUSES to answer — returning a no-coverage error, which leaves any prior tier
// standing — whenever the scan reports that anything could hide a reference: dynamic loading, macro
// expansion, computed include paths, metaprogramming, an unreadable file or an exhausted budget. Only a
// completely observed target can produce a negative.
//
// Matching is deliberately GENEROUS. A package may be referenced under several plausible names (a Rust
// crate's hyphens become underscores in `use`, a PHP package's Composer name is not its namespace, a Ruby
// gem's require path often differs from its gem name), so every plausible name counts as a reference.
// Over-matching biases toward "reachable", which is the safe direction; under-matching would suppress a
// real finding.
package srcreach

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// importScanner is the narrow read the analyzer needs; ports.SourceImportScanner satisfies it.
type importScanner interface {
	ScanImports(ctx context.Context, dir string) (ports.SourceImportGraph, error)
	Lang() string
}

// CandidateNamer expands a dependency name into every plausible source-level reference name. It is the
// one piece that differs per language.
type CandidateNamer func(packageName string) []string

// Analyzer implements the reachproof analyzer contract over a source import scan.
type Analyzer struct {
	scanner    importScanner
	candidates CandidateNamer
}

// New validates and returns the analyzer.
func New(scanner importScanner, candidates CandidateNamer) (*Analyzer, error) {
	if scanner == nil {
		return nil, fmt.Errorf("%w: srcreach analyzer needs an import scanner", shared.ErrValidation)
	}
	if candidates == nil {
		return nil, fmt.Errorf("%w: srcreach analyzer needs a candidate namer", shared.ErrValidation)
	}
	return &Analyzer{scanner: scanner, candidates: candidates}, nil
}

// Lang reports the ecosystem this analyzer answers for.
func (a *Analyzer) Analyzeable() string { return a.scanner.Lang() }

// Analyze reports, for each subject package name, whether first-party source references it.
func (a *Analyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: srcreach analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: srcreach analysis requires a target directory", shared.ErrValidation)
	}

	graph, err := a.scanner.ScanImports(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("srcreach: %s import scan (no coverage - prior tier stands): %w", a.scanner.Lang(), err)
	}
	// An unknown region means some reference could be invisible, so absence of a reference is not proof
	// of absence for ANY subject. This is the non-negotiable of the whole feature.
	if !graph.Complete() {
		return nil, fmt.Errorf("%w: %s reachability is inconclusive - %s (no coverage)",
			shared.ErrValidation, a.scanner.Lang(), strings.Join(graph.CoverageReasons, "; "))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	referenced := make(map[string]bool, len(graph.ImportedPackages))
	for _, name := range graph.ImportedPackages {
		referenced[strings.ToLower(strings.TrimSpace(name))] = true
	}

	results := make([]reachability.Result, 0, len(subjects))
	seen := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		if strings.TrimSpace(subject) == "" || seen[subject] {
			continue
		}
		seen[subject] = true
		result := reachability.Result{Symbol: subject}
		for _, candidate := range a.candidates(subject) {
			if referenced[candidate] {
				result.Reachable = true
				// The proof names the reference form that matched, which is evidence a reader can check
				// against the source without the analyzer quoting any of it.
				result.Path = []string{a.scanner.Lang() + " import " + candidate}
				break
			}
		}
		results = append(results, result)
	}

	entrypoints := append([]string(nil), graph.Entrypoints...)
	sort.Strings(entrypoints)
	return &reachability.Analysis{Results: results, Entrypoints: entrypoints}, nil
}

// NormalizeCandidates lowercases, trims, sorts and deduplicates a candidate list so matching is
// deterministic regardless of how a language's namer produced it.
func NormalizeCandidates(in []string) []string {
	out := make([]string, 0, len(in))
	for _, name := range in {
		if trimmed := strings.ToLower(strings.TrimSpace(name)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	result := out[:1]
	for _, name := range out[1:] {
		if name != result[len(result)-1] {
			result = append(result, name)
		}
	}
	return result
}
