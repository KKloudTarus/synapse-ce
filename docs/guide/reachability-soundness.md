# Reachability soundness

Synapse treats a static `not_reachable` result as suppressing evidence only when the analysis can prove that the negative is complete. A Tier-2 call-graph result therefore fails open whenever the reachable surface contains a construct the graph cannot model soundly.

## Go opaque constructs

The owned Go SSA call-graph builder records these source-level constructs as analysis-wide blind constructs when they are reachable:

- `//go:linkname`
- `unsafe`
- cgo (`import "C"`)
- assembly-backed bodyless functions

Detection happens from the loaded Go source before SSA can erase or rewrite the relevant signal, then the result is intersected with the graph's reachable symbols. Package initializers are reachability roots, so an opaque package initializer blocks suppression. A dead opaque helper does not disable an otherwise sound negative, and build-excluded source files do not poison an active symbol.

When any of these constructs is present on the reachable surface, the existing `ReachabilityClaim.ProvedNotReachable` / `SuppressesFinding` guard refuses to treat a Tier-2 `not_reachable` as proof of absence. The finding remains visible instead of becoming suppressing `not_affected` evidence.

Regression coverage lives in `internal/infrastructure/tools/ssacallgraph`, including the checked-in `testdata/reachbench/go_blind_unsafe` fixture. This behavior implements issue #1138 under EPIC #1120.
