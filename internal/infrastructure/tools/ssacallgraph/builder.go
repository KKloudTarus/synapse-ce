// Package ssacallgraph builds a deterministic call graph from Go SOURCE using go/ssa – the general,
// first-party call graph taint analysis needs. The govulncheck builder is vuln-trace-scoped and
// yields no edges for a general source→sink query, so taint needs its own general builder. This
// produces the SAME callgraph.Graph domain type + the SAME "importPath.Symbol" node identity as the
// govulncheck builder, so taint + reachability share node ids with no translation.
//
// It uses golang.org/x/tools (go/packages + go/ssa + go/callgraph) – the heavy analysis library. Because
// heavy tools are shelled out via argv, the intent is to compile this into a standalone, sandboxed argv binary
// (cmd/synapse-callgraph) the adapter execs – so x/tools stays OUT of the api server's import graph. This
// package holds the pure build logic (the testable core, like govulncheck's parseGovulncheck); the cmd +
// adapter wrapper land in a follow-up slice.
package ssacallgraph

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"sort"

	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

// BuildGraph loads the Go packages under dir (the module's./...), builds SSA + a CHA call graph, and
// reduces it to the deterministic domain callgraph.Graph: edges are caller→callee by "importPath.Symbol";
// entrypoints are the FIRST-PARTY (loaded-module) exported functions + any main. CHA (class-hierarchy
// analysis) is a SOUND over-approximation – the right precision tier for the taint over-approximation MVP
// ; precise VTA/def-use is a later refinement. Output is deterministic (sorted, deduped). Honors
// ctx. Load/type errors fail closed (a partial graph would silently drop edges → false-negative taint).
func BuildGraph(ctx context.Context, dir string) (*domaincg.Graph, error) {
	cfg := &packages.Config{
		Mode:    packages.LoadAllSyntax,
		Dir:     dir,
		Context: ctx,
		Tests:   false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, fmt.Errorf("%d package load/type error(s) – refusing a partial call graph", n)
	}
	if len(pkgs) == 0 {
		return &domaincg.Graph{}, nil
	}

	// First-party package paths (the loaded module's own packages) – entrypoints are drawn from these, so a
	// stdlib/dependency exported function isn't treated as a reachability root.
	firstParty := map[string]bool{}
	for _, p := range pkgs {
		if p.PkgPath != "" {
			firstParty[p.PkgPath] = true
		}
	}

	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()
	cg := cha.CallGraph(prog)
	cg.DeleteSyntheticNodes() // collapse wrapper/thunk nodes so edges connect real functions

	adj := map[string]map[string]bool{}
	entry := map[string]bool{}
	for fn, node := range cg.Nodes {
		caller := nodeID(fn)
		if caller == "" {
			continue
		}
		if isEntrypoint(fn, firstParty) {
			entry[caller] = true
		}
		for _, e := range node.Out {
			callee := nodeID(e.Callee.Func)
			if callee == "" || callee == caller {
				continue // drop self-edges + un-nameable (synthetic) callees
			}
			if adj[caller] == nil {
				adj[caller] = map[string]bool{}
			}
			adj[caller][callee] = true
		}
	}
	return &domaincg.Graph{Entrypoints: sortedKeys(entry), Edges: edgesOf(adj)}, nil
}

// nodeID composes an ssa.Function into the "importPath.Symbol" identity (matching the govulncheck builder +
// OSV AffectedSymbols): "pkg.Func", or "pkg.RecvType.Method" for a method (receiver pointer stripped).
// Returns "" for a function with no package (synthetic/shared/anonymous) – it has no stable symbol id.
func nodeID(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	// A monomorphized generic INSTANCE (e.g. "Map[int]") has a nil ssa Pkg + a parameterized Name, so it
	// would yield "" and SEVER every edge through the generic (a taint false-negative). Resolve to the
	// generic ORIGIN ("Map" – real Pkg, clean name), which also matches govulncheck's un-parameterized
	// symbol so the two builders' node ids align. Origin() is nil for a non-instance, so this is a no-op there.
	if o := fn.Origin(); o != nil {
		fn = o
	}
	if fn.Pkg == nil || fn.Pkg.Pkg == nil || fn.Name() == "" {
		return ""
	}
	pkg := fn.Pkg.Pkg.Path()
	if recv := fn.Signature.Recv(); recv != nil {
		if r := recvTypeName(recv.Type()); r != "" {
			return pkg + "." + r + "." + fn.Name()
		}
		return "" // a method whose receiver type can't be named has no stable id
	}
	return pkg + "." + fn.Name()
}

// recvTypeName is the receiver's named type, pointer stripped (e.g. *sql.DB → "DB"), matching the
// govulncheck "Receiver" convention. Returns "" for an unnamed receiver type.
func recvTypeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name()
	}
	return ""
}

// isEntrypoint reports whether fn is a reachability root: an exported function/method of a FIRST-PARTY
// (loaded-module) package, or a package main's main func. These are where external callers / the runtime
// enter the first-party code.
func isEntrypoint(fn *ssa.Function, firstParty map[string]bool) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	path := fn.Pkg.Pkg.Path()
	if !firstParty[path] {
		return false
	}
	if fn.Name() == "main" && fn.Pkg.Pkg.Name() == "main" {
		return true
	}
	return token.IsExported(fn.Name())
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// edgesOf flattens the caller→callees adjacency into sorted, deduped callgraph.Edges (canonical order).
func edgesOf(adj map[string]map[string]bool) []domaincg.Edge {
	if len(adj) == 0 {
		return nil
	}
	callers := make([]string, 0, len(adj))
	for c := range adj {
		callers = append(callers, c)
	}
	sort.Strings(callers)
	out := make([]domaincg.Edge, 0, len(callers))
	for _, caller := range callers {
		callees := sortedKeys(adj[caller])
		out = append(out, domaincg.Edge{Caller: caller, Callees: callees})
	}
	return out
}
