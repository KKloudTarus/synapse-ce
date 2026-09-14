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
	"golang.org/x/tools/go/callgraph/vta"
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
	// CHA-seeded VTA, two rounds, then collapse synthetic nodes: the govulncheck reachability algorithm.
	// CHA is a sound over-approximation that resolves an interface/dynamic call to EVERY type-compatible
	// method; VTA (variable-type analysis) then propagates the concrete types that actually flow to each
	// call site and removes the CHA edges it can PROVE impossible, and a second VTA round tightens further.
	// VTA only removes edges it proves cannot occur, so it never drops a call that can really happen: it
	// tightens precision RELATIVE TO the CHA-only graph without reducing soundness (better taint precision and
	// reachability accuracy). It does not raise soundness to an absolute guarantee: the graph is still bounded
	// by the CHA seed and the blind-construct guard. VTA is blind to the same dynamic constructs as CHA
	// (reflection, plugins, linkname, unsafe); those are handled by the analysis-wide blind-construct guard
	// below, not by the graph edges (EPIC #1042 #1055).
	allFuncs := ssautil.AllFunctions(prog)
	cg := cha.CallGraph(prog)
	cg = vta.CallGraph(allFuncs, cg)
	cg = vta.CallGraph(allFuncs, cg)
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
	positions := map[string]string{}   // first-party symbol → "relpath:line" (def-use precision for taint findings)
	reflectiveFns := map[string]bool{} // node id → performs a reflective invocation the graph cannot target
	pluginFns := map[string]bool{}     // node id → loads a Go plugin (plugin.Open / Lookup): arbitrary code
	routeBlind := false                // a route registration passed a handler value that could not be resolved
	for fn, node := range cg.Nodes {
		caller := nodeID(fn)
		if caller == "" {
			continue
		}
		if isEntrypoint(fn, firstParty) {
			entry[caller] = true
		}
		// Reflection blindness is scoped to the REACHABLE surface below, so it is collected for EVERY function
		// (a dependency helper that reflectively invokes a first-party-supplied function can hide a symbol too;
		// EPIC #1042 #1065), not only first-party code.
		if fnReflectivelyInvokes(fn) {
			reflectiveFns[caller] = true
		}
		// A plugin load (plugin.Open / Plugin.Lookup) brings in code that exists in no analyzed package, so
		// the call graph is fully blind to what it can invoke: a symbol reached only through a loaded plugin
		// would be misreported not_reachable (EPIC #1042 #1055). Flagged like reflection, and scoped to the
		// reachable surface below.
		if fnLoadsPlugin(fn) {
			pluginFns[caller] = true
		}
		if isFirstPartyFunc(fn, firstParty) {
			handlers, blind := routeHandlers(fn, firstParty)
			for _, h := range handlers {
				entry[h] = true // EPIC #1042 #1065: a handler registered on an HTTP router is a reachability root
			}
			if blind {
				routeBlind = true // a handler value we could not resolve: don't let its reached symbols suppress
			}
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
	// Blind constructs are analysis-wide: any not_reachable derived from this graph is unsound while one is
	// present, so the reachproof coordinator refuses to suppress on it (EPIC #1042 #1065). Reflection is
	// flagged only when a REACHABLE function performs it (a reflect.Value.Call/Method the CHA graph cannot
	// target), so an unreachable dependency's reflection does not needlessly disable every suppression.
	var blind []string
	reachable := g.Reachable()
	for id := range reflectiveFns {
		if reachable[id] {
			blind = append(blind, "reflection")
			break
		}
	}
	for id := range pluginFns {
		if reachable[id] {
			blind = append(blind, "plugin")
			break
		}
	}
	if routeBlind {
		blind = append(blind, "framework_route")
	}
	sort.Strings(blind)
	g.BlindConstructs = blind
	return g, taint.ExecFacts{Funcs: execFuncs}, nil
}

// routeHandlers returns the node ids of first-party functions fn passes as handler values to a web-framework
// route registration (net/http Handle/HandleFunc, or a call into gin/chi/gorilla/echo). Such a handler is a
// reachability ENTRY POINT even when it is unexported, because the framework invokes it on an inbound
// request; the CHA graph would otherwise treat an unexported handler reached only via registration as a root
// only incidentally. This is sound in the raise direction: an extra entry point can only make more symbols
// reachable, never fabricate a not_reachable (EPIC #1042 #1065).
//
// blind is true when a handler-SHAPED argument (a func or an interface that can box one, e.g. http.Handler)
// could not be resolved to a static function. That is a dynamic handler the graph is blind to, so its reached
// symbols must not be suppressed; the caller records a framework_route blind construct.
func routeHandlers(fn *ssa.Function, firstParty map[string]bool) (out []string, blind bool) {
	if fn == nil {
		return nil, false
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			cc, ok := instr.(ssa.CallInstruction)
			if !ok || !isRouteRegistration(cc.Common()) {
				continue
			}
			for _, arg := range cc.Common().Args {
				if !isHandlerShaped(arg) {
					continue // the path string, an int, etc. — not a handler value
				}
				h := handlerFuncOf(arg)
				if h == nil {
					blind = true // a dynamic handler value we cannot resolve to a static function
					continue
				}
				if isFirstPartyFunc(h, firstParty) {
					if id := nodeID(h); id != "" {
						out = append(out, id)
					}
				}
			}
		}
	}
	return out, blind
}

// isHandlerShaped reports whether v's type can carry an HTTP handler: a func value, or an interface value
// (http.Handler, echo.HandlerFunc via an interface, ...) that can box one. String/int route arguments are
// not handler-shaped and are ignored, so an unresolved path argument never flags a blind construct.
func isHandlerShaped(v ssa.Value) bool {
	if v == nil {
		return false
	}
	switch v.Type().Underlying().(type) {
	case *types.Signature, *types.Interface:
		return true
	}
	return false
}

// routeRegistrationVerbs is the set of method/function names that register an HTTP handler across the
// supported routers (net/http, gin, chi, gorilla/mux, echo). Gating on the verb (not on any call into the
// package) stops a non-registration router call like gin's c.JSON(200, payload) from being misread as a
// registration and needlessly flagging a framework_route blind construct.
var routeRegistrationVerbs = map[string]bool{
	"Handle": true, "HandleFunc": true, "Any": true, "All": true, "Match": true, "Method": true, "MethodFunc": true, "Mount": true, "Add": true,
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
	"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true, "Head": true, "Options": true, "Connect": true, "Trace": true,
	// Middleware registration: a handler passed to Use/Pre runs on every request, so it is a request-surface
	// entry point too (gin/echo/chi/gorilla Use, echo Pre). Missing it could suppress a symbol reached only
	// through middleware (EPIC #1042 #1065).
	"Use": true, "Pre": true,
}

// isRouteRegistration reports whether a call registers an HTTP handler. It resolves the callee's name+package
// for both a static call (StaticCallee) and an interface invoke (Common.Method, e.g. chi.Router.Get where the
// receiver is the router interface), then defers to isRegistrationName. Handling the invoke case closes the
// gap where an interface-typed router (r.Get("/x", h)) was skipped and its handler never became an entry
// point (EPIC #1042 #1065).
func isRouteRegistration(cc *ssa.CallCommon) bool {
	if cc == nil {
		return false
	}
	if callee := cc.StaticCallee(); callee != nil && callee.Pkg != nil && callee.Pkg.Pkg != nil {
		return isRegistrationName(callee.Name(), callee.Pkg.Pkg.Path())
	}
	if cc.IsInvoke() && cc.Method != nil && cc.Method.Pkg() != nil {
		return isRegistrationName(cc.Method.Name(), cc.Method.Pkg().Path())
	}
	return false
}

// isRegistrationName is the pure name+package gate: net/http's Handle/HandleFunc, or a registration verb in a
// recognized router package. Over-matching a verb WITHIN a router package is harmless (extra entry points
// only raise reachability, and an unresolved handler only flags a blind construct that prevents suppression),
// but matching a NON-verb call must not fire, or every router-package call would falsely disable suppression.
func isRegistrationName(name, pkg string) bool {
	if pkg == "" {
		return false
	}
	if pkg == "net/http" {
		return name == "Handle" || name == "HandleFunc"
	}
	for _, router := range []string{"github.com/gin-gonic/gin", "github.com/go-chi/chi", "github.com/gorilla/mux", "github.com/labstack/echo"} {
		if pkg == router || strings.HasPrefix(pkg, router+"/") {
			return routeRegistrationVerbs[name]
		}
	}
	return false
}

// handlerFuncOf extracts the *ssa.Function a route-registration argument refers to, unwrapping the SSA value
// wrappers a handler is commonly built through: a named-type conversion (http.HandlerFunc(h)), an interface
// box (http.Handle takes http.Handler), a ChangeType, and a closure (MakeClosure). It returns nil for a
// handler the graph cannot resolve to a static function (a value read from a slice/map/field, a method value
// through an interface), which the caller treats as a blind construct. The unwrap is depth-bounded so a
// pathological chain cannot loop.
func handlerFuncOf(v ssa.Value) *ssa.Function {
	for i := 0; i < 16 && v != nil; i++ {
		switch t := v.(type) {
		case *ssa.Function:
			return t
		case *ssa.MakeClosure:
			if f, ok := t.Fn.(*ssa.Function); ok {
				return f
			}
			return nil
		case *ssa.MakeInterface:
			v = t.X
		case *ssa.ChangeType:
			v = t.X
		case *ssa.Convert:
			v = t.X
		default:
			return nil
		}
	}
	return nil
}

// fnReflectivelyInvokes reports whether fn contains a static call to a reflect dynamic-invocation method
// (reflect.Value.Call / CallSlice / Method / MethodByName). The CHA call graph cannot know the callee such a
// call dispatches to, so first-party code using it makes the graph blind to those targets: a vulnerable
// symbol reached only reflectively would be misreported not_reachable. Detecting the reflective invocation
// (not merely importing reflect, which fmt/json pull in transitively) keeps the signal targeted.
func fnReflectivelyInvokes(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			cc, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			callee := cc.Common().StaticCallee()
			if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil {
				continue
			}
			if callee.Pkg.Pkg.Path() != "reflect" {
				continue
			}
			switch callee.Name() {
			case "Call", "CallSlice", "Method", "MethodByName":
				return true
			}
		}
	}
	return false
}

// fnLoadsPlugin reports whether fn contains a static call to plugin.Open or (*plugin.Plugin).Lookup. A Go
// plugin is compiled code that exists in no analyzed package, so neither CHA nor VTA can know what a loaded
// plugin invokes: a vulnerable symbol reached only through a plugin would be misreported not_reachable.
// Detecting the load site (not merely importing "plugin") keeps the blind signal targeted.
func fnLoadsPlugin(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			cc, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			callee := cc.Common().StaticCallee()
			if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil {
				continue
			}
			if callee.Pkg.Pkg.Path() != "plugin" {
				continue
			}
			switch callee.Name() {
			case "Open", "Lookup":
				return true
			}
		}
	}
	return false
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
	// A first-party package initializer is a reachability root: the runtime runs it at program start, so a
	// vulnerable symbol reached only from a `func init()` (or the synthesized package `init`) is genuinely
	// reachable. go/ssa names the synthesized initializer "init" and each source `func init()` "init#1",
	// "init#2", ... Missing these under-approximated reachability (EPIC #1042 #1055, the noted init gap);
	// adding them is sound in the raise direction, since an extra root can only make more symbols reachable.
	if fn.Name() == "init" || strings.HasPrefix(fn.Name(), "init#") {
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
