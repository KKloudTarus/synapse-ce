package ports

import "context"

// SourceImportGraph is one language's first-party import observation for a target.
//
// It is deliberately coarse: Tier-1 reachability asks only whether first-party code references a
// dependency at all, so a package name set plus an honest account of what could NOT be observed is
// sufficient — and far more robust than a call graph over languages whose dynamic loading defeats one.
type SourceImportGraph struct {
	// ImportedPackages are the distribution/crate/gem names first-party source references, lowercased.
	ImportedPackages []string
	// Entrypoints are the discovered entrypoints, kept as provenance for the sealed proof. They are
	// discovered structurally, not verified to execute.
	Entrypoints []string
	// CoverageReasons explains, in short non-source-quoting labels, why the observation is incomplete.
	// A NON-EMPTY list means no negative conclusion is safe: something could reference a dependency
	// without this scan seeing it.
	CoverageReasons []string
	// FilesScanned is the number of source files actually read.
	FilesScanned int
}

// Complete reports whether the observation is good enough to support a NEGATIVE conclusion.
func (g SourceImportGraph) Complete() bool { return len(g.CoverageReasons) == 0 }

// SourceImportScanner observes first-party imports for one language.
//
// Implementations must be source-only: they read and lex text, and never execute project code, a package
// manager, a build system or a language runtime, and never access the network. Any construct that could
// reference a dependency invisibly — dynamic loading, macro expansion, computed paths, metaprogramming —
// must be recorded in CoverageReasons rather than ignored, because a missed reference becomes a false
// "unreachable" that suppresses a real vulnerability.
type SourceImportScanner interface {
	ScanImports(ctx context.Context, dir string) (SourceImportGraph, error)
	// Lang is the ecosystem this scanner observes, matching the package-URL type ("cargo", "composer",
	// "gem"), so a coordinator can pair it with the right components.
	Lang() string
}
