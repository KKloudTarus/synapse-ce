// Package nugetreach is the build-aware .NET reachability analyzer. It decides whether a NuGet package is
// referenced by first-party code, but unlike a source-only import scanner it never guesses a package's
// namespace from its id (AWSSDK.S3 ships the Amazon.S3 namespace). It observes the namespaces first-party
// source references, reads each subject package's REAL exported namespaces from its restored assemblies, and
// concludes a package unreferenced ONLY when it is a declared direct dependency, its full namespace set is
// known, and none of those namespaces is observed. Every gap (a dynamic construct in source, a missing
// restore graph, an unreadable assembly, a transitive subject) fails closed to unknown: the analyzer omits
// that subject from its results so no false not_affected can be minted.
package nugetreach

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// DirectDependencyReader returns the declared direct NuGet dependencies under dir (lowercased), and whether
// a manifest was found. It is the guard that keeps a TRANSITIVE package out of a Tier-1 answer.
type DirectDependencyReader func(ctx context.Context, dir string) (map[string]bool, bool)

// Analyzer runs build-aware .NET reachability. It satisfies the reachproof coordinator's analyzer contract
// (Analyze), so a NotReachable result is minted through the same audited propose->verify gate as the other
// reachability tiers.
type Analyzer struct {
	scanner    ports.SourceImportScanner
	data       ports.NuGetReachabilityData
	directDeps DirectDependencyReader
}

// New validates dependencies and returns an Analyzer.
func New(scanner ports.SourceImportScanner, data ports.NuGetReachabilityData, directDeps DirectDependencyReader) (*Analyzer, error) {
	if scanner == nil || data == nil || directDeps == nil {
		return nil, fmt.Errorf("%w: nugetreach analyzer is missing a dependency", shared.ErrValidation)
	}
	return &Analyzer{scanner: scanner, data: data, directDeps: directDeps}, nil
}

// Analyze observes first-party namespace references and returns, for each subject package it can decide, a
// reachability Result. It returns an error (no coverage: the prior tier stands) whenever a GLOBAL gap makes
// any negative conclusion unsafe: the source observation failed or is incomplete (a reflection/dynamic
// construct), no NuGet manifest is present, or no restore graph (project.assets.json) exists. A subject it
// cannot decide (transitive, or with an incomplete/empty known namespace set) is OMITTED, so the coordinator
// leaves the prior tier standing rather than mint a false not_affected.
func (a *Analyzer) Analyze(ctx context.Context, dir string, symbols []string) (*reachability.Analysis, error) {
	graph, err := a.scanner.ScanImports(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("observe .NET namespace references (no coverage): %w", err)
	}
	if !graph.Complete() {
		// A dynamic construct anywhere in source could reach any package invisibly, so NO negative is safe.
		return nil, fmt.Errorf("%w: .NET reachability inconclusive, source observation incomplete (no coverage): %s",
			shared.ErrValidation, strings.Join(graph.CoverageReasons, "; "))
	}
	observed := make(map[string]bool, len(graph.ImportedPackages))
	for _, ns := range graph.ImportedPackages {
		observed[ns] = true
	}

	direct, ok := a.directDeps(ctx, dir)
	if !ok {
		return nil, fmt.Errorf("%w: no .NET manifest, cannot tell direct from transitive (no coverage)", shared.ErrValidation)
	}

	pkgData, present, err := a.data.LoadReachabilityData(ctx, dir, symbols)
	if err != nil {
		return nil, fmt.Errorf("load .NET build metadata (no coverage): %w", err)
	}
	if !present {
		// Without the restore graph a package's real namespaces are unknown, so source-only observation
		// cannot soundly conclude anything: fail closed.
		return nil, fmt.Errorf("%w: no .NET restore graph (project.assets.json); build the project for reachability (no coverage)", shared.ErrValidation)
	}

	var results []reachability.Result
	seen := map[string]bool{}
	for _, sym := range symbols {
		if seen[sym] {
			continue
		}
		seen[sym] = true
		id := strings.ToLower(strings.TrimSpace(sym))
		if id == "" || !direct[id] {
			continue // transitive or unnamed: unknown, omit (a later tier may resolve transitivity)
		}
		pn, known := pkgData[id]
		if !known || !pn.Complete || len(pn.Namespaces) == 0 {
			continue // incomplete or empty namespace set: unknown, omit (fail closed)
		}
		results = append(results, reachability.Result{
			Symbol:    sym,
			Reachable: anyNamespaceObserved(pn.Namespaces, observed),
		})
	}
	return &reachability.Analysis{Results: results, Entrypoints: graph.Entrypoints}, nil
}

// anyNamespaceObserved reports whether first-party source references any of a package's real namespaces. It
// matches symmetrically so it holds whether or not the observed set is prefix-closed: a package namespace is
// reached when it (or any of its dotted prefixes) is observed, AND when any observed namespace is that
// package namespace or a sub-namespace of it. Over-matching only adds reachability, the safe direction; the
// danger to avoid is UNDER-matching, which would suppress a used package.
func anyNamespaceObserved(namespaces []string, observed map[string]bool) bool {
	pkg := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		pkg[ns] = true
		segments := strings.Split(ns, ".")
		for i := len(segments); i >= 1; i-- {
			if observed[strings.Join(segments[:i], ".")] {
				return true // the package namespace, or a parent of it, is referenced
			}
		}
	}
	for o := range observed {
		if o == "" {
			continue
		}
		segments := strings.Split(o, ".")
		for i := len(segments); i >= 1; i-- {
			if pkg[strings.Join(segments[:i], ".")] {
				return true // an observed namespace is the package namespace, or a sub-namespace of it
			}
		}
	}
	return false
}
