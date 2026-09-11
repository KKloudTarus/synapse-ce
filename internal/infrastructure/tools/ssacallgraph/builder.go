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
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// BuildGraph loads the Go packages under dir (the module's./...), builds SSA + a CHA call graph, and
// reduces it to the deterministic domain callgraph.Graph: edges are caller→callee by "importPath.Symbol";
// entrypoints are the FIRST-PARTY (loaded-module) exported functions + any main. CHA (class-hierarchy
// analysis) is a SOUND over-approximation – the right precision tier for the taint over-approximation MVP.
// Output is deterministic (sorted, deduped). Honors ctx. Load/type errors fail closed (a partial graph would
// silently drop edges → false-negative taint). This is the reachability contract (ports.CallGraphBuilder);
// it discards the value-level exec facts BuildGraphAndExecFacts also computes.
func BuildGraph(ctx context.Context, dir string) (*domaincg.Graph, error) {
	g, _, err := BuildGraphAndExecFacts(ctx, dir)
	return g, err
}

// BuildGraphAndExecFacts is BuildGraph plus the value-level exec-sink facts D5.4 needs: from the SAME single
// SSA build it also returns, per first-party function, whether every os/exec.Command/CommandContext call
// site in it passes a compile-time-constant, non-interpreter program name (argv[0]). The call graph is
// byte-identical to BuildGraph's (reachability depends on it, so the facts are strictly ADDITIVE), and the
// facts only ever DE-ESCALATE a CWE-78 finding to CWE-88 downstream — a function with a variable, interpreter,
// or unproven program name simply carries no fact and keeps CWE-78 (fail-closed). Facts are bounded to
// first-party functions (like the position table): a sink-using function in a dependency carries no fact and
// keeps CWE-78.
func BuildGraphAndExecFacts(ctx context.Context, dir string) (*domaincg.Graph, taint.ExecFacts, error) {
	cfg := &packages.Config{
		Mode:    packages.LoadAllSyntax,
		Dir:     dir,
		Context: ctx,
		Tests:   false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, taint.ExecFacts{}, fmt.Errorf("load packages: %w", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, taint.ExecFacts{}, fmt.Errorf("%d package load/type error(s) – refusing a partial call graph", n)
	}
	if len(pkgs) == 0 {
		return &domaincg.Graph{}, taint.ExecFacts{}, nil
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

	// execArgs is the catalog's single source of truth for which callee is an exec sink and which of its
	// arguments is the program name (argv[0]) the value-level check inspects.
	execArgs := taint.ExecSinkArgs(taint.DefaultCatalog())
	// execSeen/execSafe accumulate the verdict PER (function symbol, exec sink symbol) ACROSS the (possibly
	// several) SSA nodes that map to one "importPath.Symbol" id — generic instances share an origin id via
	// nodeID, so a (function, sink) is safe only when EVERY node for it is (AND, the fail-closed direction).
	// Keying by sink symbol means a sink the pass never inspected is never marked safe (builder/catalog
	// drift fails closed).
	execSeen := map[string]map[string]bool{} // function symbol → sink symbol → seen
	execSafe := map[string]map[string]bool{} // function symbol → sink symbol → all sites safe so far

	adj := map[string]map[string]bool{}
	entry := map[string]bool{}
	positions := map[string]string{} // first-party symbol → "relpath:line" (def-use precision for taint findings)
	for fn, node := range cg.Nodes {
		caller := nodeID(fn)
		if caller == "" {
			continue
		}
		if isEntrypoint(fn, firstParty) {
			entry[caller] = true
		}
		if p := firstPartyPos(prog.Fset, fn, dir, firstParty); p != "" {
			positions[caller] = p
		}
		if isFirstPartyFunc(fn, firstParty) {
			for sink, siteSafe := range execConstantSafe(fn, execArgs) {
				if execSeen[caller] == nil {
					execSeen[caller] = map[string]bool{}
					execSafe[caller] = map[string]bool{}
				}
				if !execSeen[caller][sink] {
					execSeen[caller][sink] = true
					execSafe[caller][sink] = true // optimistic; AND-ed down below
				}
				if !siteSafe {
					execSafe[caller][sink] = false
				}
			}
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

	var execFuncs map[string]taint.ExecFuncFacts
	for caller, sinks := range execSeen {
		var safe map[string]bool
		for sink := range sinks {
			if execSafe[caller][sink] {
				if safe == nil {
					safe = map[string]bool{}
				}
				safe[sink] = true
			}
		}
		if len(safe) > 0 {
			if execFuncs == nil {
				execFuncs = map[string]taint.ExecFuncFacts{}
			}
			execFuncs[caller] = taint.ExecFuncFacts{SafeSinks: safe}
		}
	}
	g := &domaincg.Graph{Entrypoints: sortedKeys(entry), Edges: edgesOf(adj), Positions: positions}
	return g, taint.ExecFacts{Funcs: execFuncs}, nil
}

// isFirstPartyFunc reports whether fn is defined in a loaded-module (first-party) package, resolving a
// generic instance to its origin so the check matches nodeID's id. It bounds the value-level exec analysis
// to the module's own code (where taint sink-using functions live), mirroring firstPartyPos.
func isFirstPartyFunc(fn *ssa.Function, firstParty map[string]bool) bool {
	if fn == nil {
		return false
	}
	if o := fn.Origin(); o != nil {
		fn = o
	}
	return fn.Pkg != nil && fn.Pkg.Pkg != nil && firstParty[fn.Pkg.Pkg.Path()]
}

// execConstantSafe inspects fn's body for calls to the catalog's exec sinks (execArgs: callee id → the
// program-name argument index) and returns, per exec sink symbol seen in fn, whether EVERY call site to it is
// provably safe to de-escalate. A site is safe only when it is a plain *ssa.Call (not go/defer) whose
// program-name argument is a compile-time constant naming a known-fixed-safe program (argIsFixedSafeProgram)
// AND whose *exec.Cmd result is confined (execResultConfined): the program cannot be re-pointed via a field
// write and does not escape before execution.
//
// It is fail-closed against the SAME over-approximation the CHA call graph uses. CHA attributes an exec-sink
// edge not only to a static call but also to a call THROUGH A FUNCTION VALUE whose signature matches the
// sink (chautil resolves func-value calls by signature). Such a call has StaticCallee()==nil, so it is
// invisible to the per-site check; if it returns *exec.Cmd it could be an exec.Command alias with an
// attacker-controlled program. So any unresolved (StaticCallee==nil) call returning *exec.Cmd poisons EVERY
// exec-sink verdict for fn (result "safe" only when there is no such call), matching the edge set the finding
// actually fires on. A returned map with a false value keeps CWE-78; an absent sink means no de-escalation.
func execConstantSafe(fn *ssa.Function, execArgs map[string]int) map[string]bool {
	safe := map[string]bool{}
	unresolvedExecCmd := false
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			ci, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			common := ci.Common()
			callee := common.StaticCallee()
			if callee == nil {
				// A dynamic/indirect call CHA may resolve to an exec sink by signature. If it can yield a
				// *exec.Cmd we cannot prove the program is fixed — fail closed for the whole function.
				if signatureReturnsExecCmd(common.Signature()) {
					unresolvedExecCmd = true
				}
				continue
			}
			argIdx, isExec := execArgs[nodeID(callee)]
			if !isExec {
				continue
			}
			call, isPlainCall := instr.(*ssa.Call) // go/defer have no usable result to confine
			siteSafe := isPlainCall &&
				argIsFixedSafeProgram(common.Args, argIdx) &&
				execResultConfined(call)
			if prev, seen := safe[nodeID(callee)]; !seen {
				safe[nodeID(callee)] = siteSafe
			} else {
				safe[nodeID(callee)] = prev && siteSafe
			}
		}
	}
	if unresolvedExecCmd {
		for sink := range safe {
			safe[sink] = false
		}
	}
	return safe
}

// argIsFixedSafeProgram reports whether the call argument at idx is a compile-time-constant string naming a
// known-fixed-safe program (allowlist) — a fixed program that makes the exec call at worst argument
// injection. It is deliberately strict: it treats ONLY a literal *ssa.Const string as constant (a value
// derived from a parameter, a call, a Phi, or string concatenation is NOT provably constant), and an
// out-of-range index, a non-string constant, an empty string, or a program not on the allowlist is not safe.
// Every "not proven" answer keeps CWE-78.
func argIsFixedSafeProgram(args []ssa.Value, idx int) bool {
	if idx < 0 || idx >= len(args) {
		return false
	}
	c, ok := args[idx].(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.String {
		return false
	}
	name := constant.StringVal(c.Value)
	if name == "" {
		return false // an empty program name is not a normal fixed program; keep the CWE-78 over-approximation
	}
	return taint.IsFixedSafeProgram(name)
}

// execResultConfined reports whether the *exec.Cmd produced by call cannot have its executed program
// changed before it runs: every use of the result is either a method call ON the Cmd (Run/Output/Start/…,
// none of which re-point .Path/.Args from stdlib) or a harmless debug ref. ANY other use — taking a field
// address (&cmd.Path, the classic cmd.Path = attacker), storing the Cmd, boxing it into an interface,
// returning it, or passing it to another function that could mutate it — is treated as NOT confined
// (fail-closed), so a fixed constant argv[0] whose Cmd is later re-pointed keeps CWE-78. A result with no
// uses is confined (it is never executed, so nothing can be injected through it).
func execResultConfined(call *ssa.Call) bool {
	refs := call.Referrers()
	if refs == nil {
		return true
	}
	for _, r := range *refs {
		switch instr := r.(type) {
		case *ssa.Call:
			if !cmdIsReceiver(instr.Common(), call) {
				return false
			}
		case *ssa.Go:
			if !cmdIsReceiver(instr.Common(), call) {
				return false
			}
		case *ssa.Defer:
			if !cmdIsReceiver(instr.Common(), call) {
				return false
			}
		case *ssa.DebugRef:
			// debug metadata only; cannot affect execution
		default:
			return false // FieldAddr / Store / MakeInterface / Return / Phi / … → conservative: not confined
		}
	}
	return true
}

// cmdIsReceiver reports whether cmd is used in cc purely as the RECEIVER of a concrete method (Args[0] of a
// static method call), as opposed to being passed as an ordinary argument (which could escape and be
// mutated) or used in a dynamic call. Method calls on *exec.Cmd (Run/Output/…) are the only confined use.
func cmdIsReceiver(cc *ssa.CallCommon, cmd *ssa.Call) bool {
	callee := cc.StaticCallee()
	if callee == nil || callee.Signature == nil || callee.Signature.Recv() == nil {
		return false // dynamic call, or a non-method function taking cmd as a plain arg → escape
	}
	return len(cc.Args) > 0 && cc.Args[0] == ssa.Value(cmd) // cmd must be the receiver (first arg)
}

// signatureReturnsExecCmd reports whether sig returns an *os/exec.Cmd, so an unresolved call with this
// signature could be an exec.Command/CommandContext alias whose program name we cannot inspect.
func signatureReturnsExecCmd(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	res := sig.Results()
	for i := 0; i < res.Len(); i++ {
		if isExecCmdPtr(res.At(i).Type()) {
			return true
		}
	}
	return false
}

// isExecCmdPtr reports whether t is *os/exec.Cmd. It unwraps type aliases at each level (Go 1.23+
// materializes aliases as types.Alias by default), so a "type CmdAlias = exec.Cmd" or "type P = *exec.Cmd"
// return type is still recognized and cannot be used to smuggle an unresolved exec constructor past the
// fail-closed check.
func isExecCmdPtr(t types.Type) bool {
	p, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(p.Elem()).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "os/exec" && obj.Name() == "Cmd"
}

// firstPartyPos returns fn's definition position as "relpath:line" (relative to the scan root dir) for a
// FIRST-PARTY function, or "" otherwise. It bounds the position table to the module's own code (which is
// where taint source/sink USING-functions live) and never emits an absolute host path (GR3: a path outside
// dir, or an un-relativizable one, degrades to the base name). It resolves a generic INSTANCE to its ORIGIN
// so the key matches nodeID's id exactly. It carries only a path + line — never file contents.
func firstPartyPos(fset *token.FileSet, fn *ssa.Function, dir string, firstParty map[string]bool) string {
	if o := fn.Origin(); o != nil {
		fn = o
	}
	if fn.Pkg == nil || fn.Pkg.Pkg == nil || !firstParty[fn.Pkg.Pkg.Path()] {
		return ""
	}
	if !fn.Pos().IsValid() {
		return ""
	}
	p := fset.Position(fn.Pos())
	if p.Filename == "" {
		return ""
	}
	name := p.Filename
	// Keep the relative path only when it stays INSIDE the scan root; a real escape ("../…") degrades to
	// the base name (no host-layout leak). Match the escape precisely so a directory literally named
	// "..foo" is not misclassified as an escape.
	if rel, err := filepath.Rel(dir, name); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		name = rel
	} else {
		name = filepath.Base(name)
	}
	return fmt.Sprintf("%s:%d", name, p.Line)
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
