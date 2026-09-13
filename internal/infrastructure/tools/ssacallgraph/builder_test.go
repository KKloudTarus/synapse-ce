package ssacallgraph

import (
	"context"
	"go/constant"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/ssa"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hasEdge(g *domaincg.Graph, caller, callee string) bool {
	for _, e := range g.Edges {
		if e.Caller == caller {
			for _, c := range e.Callees {
				if c == callee {
					return true
				}
			}
		}
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestBuildGraphFunctionEdges(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "os/exec"

func main() { run("ls") }

func run(name string) { _ = exec.Command(name).Run() }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Specific edges must exist (the full CHA graph is huge – assert the ones we control).
	if !hasEdge(g, "cgfixture.main", "cgfixture.run") {
		t.Errorf("missing edge cgfixture.main → cgfixture.run (edges=%d)", len(g.Edges))
	}
	if !hasEdge(g, "cgfixture.run", "os/exec.Command") {
		t.Errorf("missing edge cgfixture.run → os/exec.Command (a stdlib sink-shaped call)")
	}
	// main is a first-party reachability root; the unexported run is not.
	if !contains(g.Entrypoints, "cgfixture.main") {
		t.Errorf("cgfixture.main must be an entrypoint; got %v", g.Entrypoints)
	}
	if contains(g.Entrypoints, "cgfixture.run") {
		t.Errorf("unexported cgfixture.run must NOT be an entrypoint")
	}
}

func TestBuildGraphRecordsFirstPartyPositions(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "os/exec"

func main() { run("ls") }

func run(name string) { _ = exec.Command(name).Run() }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// First-party functions carry a "relpath:line" definition position (def-use precision for taint).
	if got := g.Positions["cgfixture.main"]; got != "main.go:5" {
		t.Errorf("main position = %q, want main.go:5", got)
	}
	if got := g.Positions["cgfixture.run"]; got != "main.go:7" {
		t.Errorf("run position = %q, want main.go:7", got)
	}
	// Positions are RELATIVE (never an absolute host path) so no host layout leaks.
	for sym, pos := range g.Positions {
		if strings.HasPrefix(pos, "/") {
			t.Errorf("position for %q must be relative, got absolute %q", sym, pos)
		}
	}
	// A stdlib/dependency symbol is NOT first-party, so it carries no position (bounded table).
	if _, ok := g.Positions["os/exec.Command"]; ok {
		t.Errorf("stdlib symbol must not carry a first-party position")
	}
}

func TestBuildGraphMethodNodeID(t *testing.T) {
	// A method node is "pkg.RecvType.Method" with the receiver pointer stripped – matching the govulncheck
	// builder's convention so taint/reachability node ids align.
	dir := writeModule(t, map[string]string{
		"go.mod": "module mfix\n\ngo 1.21\n",
		"m.go": `package main

type Svc struct{}

func (s *Svc) Handle() { helper() }

func helper() {}

func main() { (&Svc{}).Handle() }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !hasEdge(g, "mfix.Svc.Handle", "mfix.helper") {
		t.Errorf("missing method edge mfix.Svc.Handle → mfix.helper (entrypoints=%v, edges=%d)", g.Entrypoints, len(g.Edges))
	}
	if !contains(g.Entrypoints, "mfix.Svc.Handle") {
		t.Errorf("exported method (*Svc).Handle should be an entrypoint as mfix.Svc.Handle; got %v", g.Entrypoints)
	}
}

// TestBuildGraphVTAPrunesUninstantiatedImpl proves the CHA→VTA→VTA upgrade (#1055) tightens precision
// soundly: an interface call resolves only to the implementation whose concrete type actually flows to the
// call site. CHA would add an edge to EVERY Greeter implementation; VTA proves no Danger value reaches g and
// prunes it, so Danger.Greet and the danger() it alone reaches are NOT reachable. This is sound — no Danger
// value can reach this call site — so it removes a spurious flow without hiding a real one.
func TestBuildGraphVTAPrunesUninstantiatedImpl(t *testing.T) {
	// The interface and its method are UNEXPORTED, so the implementations are not exported-method entrypoints;
	// their only reachability is through the interface call, which is exactly what VTA resolves.
	dir := writeModule(t, map[string]string{
		"go.mod": "module vtafix\n\ngo 1.21\n",
		"main.go": `package main

type greeter interface{ greet() }

type safeImpl struct{}

func (safeImpl) greet() {}

type dangerImpl struct{}

func (dangerImpl) greet() { danger() }

func danger() {}

func main() {
	var g greeter = safeImpl{}
	g.greet()
}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	reach := g.Reachable()
	if !reach["vtafix.safeImpl.greet"] {
		t.Errorf("safeImpl.greet (the instantiated impl called via the interface) must be reachable; entrypoints=%v", g.Entrypoints)
	}
	if reach["vtafix.dangerImpl.greet"] {
		t.Errorf("VTA must prune the uninstantiated dangerImpl.greet from g.greet() (CHA over-approximation)")
	}
	if reach["vtafix.danger"] {
		t.Errorf("danger(), reached only via the pruned dangerImpl.greet, must not be reachable")
	}
}

// TestBuildGraphInitIsEntrypoint proves the entry-policy fix (#1055): a first-party func init() is a
// reachability root, so a symbol reached only from init is reachable. Before, init was missed and such a
// symbol was under-approximated as unreachable.
func TestBuildGraphInitIsEntrypoint(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module initfix\n\ngo 1.21\n",
		"main.go": `package main

func init() { fromInit() }

func fromInit() {}

func main() {}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !g.Reachable()["initfix.fromInit"] {
		t.Errorf("a symbol reached only from func init() must be reachable; entrypoints=%v", g.Entrypoints)
	}
}

// TestBuildGraphPluginLoadIsBlindConstruct proves the blind-construct guard (#1055) flags a reachable
// plugin.Open: a loaded Go plugin's code is in no analyzed package, so the graph is blind to what it invokes
// and the reachproof coordinator must refuse to mint not_reachable. Without this, a symbol reached only
// through a plugin would be wrongly suppressed.
func TestBuildGraphPluginLoadIsBlindConstruct(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module plugfix\n\ngo 1.21\n",
		"main.go": `package main

import "plugin"

func main() {
	_, _ = plugin.Open("mod.so")
}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !contains(g.BlindConstructs, "plugin") {
		t.Errorf("a reachable plugin.Open must record a \"plugin\" blind construct; got %v", g.BlindConstructs)
	}
}

func TestBuildGraphGenericInstanceEdgesSurvive(t *testing.T) {
	// A call chain THROUGH a generic function must NOT be severed. A monomorphized instance (Map[int]) has a
	// nil ssa Pkg + a parameterized name, so without Origin() resolution its in/out edges would silently drop
	// – a taint false-negative. The node id resolves to the un-parameterized origin "genfix.Map" (matching
	// the govulncheck convention), so both edges survive.
	dir := writeModule(t, map[string]string{
		"go.mod": "module genfix\n\ngo 1.21\n",
		"main.go": `package main

func Map[T any](xs []T, f func(T) T) []T {
	out := make([]T, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}

func id(x int) int { return x }

func main() { _ = Map([]int{1, 2}, id) }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !hasEdge(g, "genfix.main", "genfix.Map") {
		t.Errorf("edge INTO the generic (genfix.main → genfix.Map) must survive Origin resolution (edges=%d)", len(g.Edges))
	}
	if !hasEdge(g, "genfix.Map", "genfix.id") {
		t.Errorf("edge OUT of the generic (genfix.Map → genfix.id) must survive – a severed chain is a taint false-negative")
	}
}

func TestBuildGraphLoadErrorFailsClosed(t *testing.T) {
	// A package that does not compile must fail closed – a partial graph would silently drop edges (a taint
	// false-negative), so BuildGraph refuses it rather than returning an under-approximation.
	dir := writeModule(t, map[string]string{
		"go.mod":  "module brokenfix\n\ngo 1.21\n",
		"main.go": "package main\nfunc main() { undefinedSymbol() }\n",
	})
	if _, err := BuildGraph(context.Background(), dir); err == nil {
		t.Error("a module with a type error must fail closed, not yield a partial graph")
	}
}

// TestBuildGraphExecFactsSafeVsUnsafe is the value-level proof for D5.4 over the acceptance twins and the
// adversarial cases the review surfaced. A first-party function's exec sink is reported safe-to-de-escalate
// ONLY when argv[0] is a constant known-fixed-safe program at every site AND the *exec.Cmd is confined AND
// there is no unresolved *exec.Cmd-returning call; everything else keeps CWE-78. The reachability call graph
// is unchanged by this additive pass.
func TestBuildGraphExecFactsSafeVsUnsafe(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module bench\n\ngo 1.21\n",
		"main.go": `package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

type Commander func(string, ...string) *exec.Cmd

// AliasCmd is a type ALIAS of exec.Cmd (Go 1.23+ materializes it as types.Alias); AliasRunner returns a
// pointer to it, exercising the alias-unwrapping path in isExecCmdPtr.
type AliasCmd = exec.Cmd
type AliasRunner func(string, ...string) *AliasCmd

func main() {
	in := os.Getenv("X")
	SafeEcho(in)
	SafePing(in)
	CtxSafe(context.Background(), in)
	UnsafeVar(in)
	ShellInterp(in)
	VersionedPython(in)
	Mixed(in)
	PathMutated(in)
	Escapes(in)
	IndirectFuncValue(exec.Command, in)
	AbsPath(in)
	AliasIndirect(aliasCommand, in)
	NoExec(in)
}

func aliasCommand(name string, arg ...string) *AliasCmd { return exec.Command(name, arg...) }

// constant, allowlisted argv[0], result flows straight into Run → safe (de-escalates to CWE-88).
func SafeEcho(in string) { _ = exec.Command("echo", in).Run() }

// constant argv[0] with fixed flags then a tainted arg → still safe (fixed program).
func SafePing(host string) { _ = exec.Command("ping", "-c", "1", host).Run() }

// CommandContext: the program name is arg 1 (arg 0 is the context) → safe.
func CtxSafe(ctx context.Context, in string) { _ = exec.CommandContext(ctx, "echo", in).Run() }

// variable argv[0] (attacker picks the program) → NOT safe (keeps CWE-78).
func UnsafeVar(in string) {
	parts := strings.Fields(in)
	_ = exec.Command(parts[0], parts[1:]...).Run()
}

// constant argv[0] but a shell (not on the allowlist; command rides in -c) → NOT safe.
func ShellInterp(cmd string) { _ = exec.Command("sh", "-c", cmd).Run() }

// constant argv[0] naming a versioned interpreter (not on the allowlist) → NOT safe.
func VersionedPython(code string) { _ = exec.Command("python3.11", "-c", code).Run() }

// two exec sites, one safe one variable → NOT safe (every site must be safe).
func Mixed(in string) {
	_ = exec.Command("echo", in).Run()
	_ = exec.Command(in).Run()
}

// constant, allowlisted argv[0] BUT the program is re-pointed via a field write → NOT safe (real command
// injection through cmd.Path).
func PathMutated(in string) {
	cmd := exec.Command("echo", "ok")
	cmd.Path = in
	_ = cmd.Run()
}

// the *exec.Cmd escapes to another function that could mutate it → NOT safe (conservative).
func Escapes(in string) {
	cmd := exec.Command("echo", in)
	configure(cmd)
	_ = cmd.Run()
}

func configure(c *exec.Cmd) { _ = c }

// a direct constant exec call PLUS an indirect func-value exec call with a variable program. CHA attributes
// an os/exec.Command edge to the func-value call by signature, but StaticCallee is nil there, so the pass
// must fail closed for the whole function → NOT safe.
func IndirectFuncValue(pick Commander, prog string) {
	_ = exec.Command("echo", "ok").Run()
	_ = pick(prog).Run()
}

// constant but a PATH form (basename echo is allowlisted, but the directory could point at untrusted code)
// → NOT safe.
func AbsPath(in string) { _ = exec.Command("/tmp/echo", in).Run() }

// a direct constant exec call PLUS an indirect func-value call returning *AliasCmd (an alias of exec.Cmd).
// The alias-unwrapping fail-closed check must poison the verdict → NOT safe.
func AliasIndirect(run AliasRunner, prog string) {
	_ = exec.Command("echo", "ok").Run()
	_ = run(prog).Run()
}

// no exec call → no fact at all.
func NoExec(in string) { _ = os.Getenv(in) }
`,
	})
	_, facts, err := BuildGraphAndExecFacts(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	safeFor := func(sym, sink string) bool { return facts.Funcs[sym].SafeSinks[sink] }

	// Safe cases de-escalate.
	if !safeFor("bench.SafeEcho", "os/exec.Command") {
		t.Errorf("SafeEcho must be safe-to-de-escalate; facts=%+v", facts.Funcs["bench.SafeEcho"])
	}
	if !safeFor("bench.SafePing", "os/exec.Command") {
		t.Errorf("SafePing must be safe-to-de-escalate")
	}
	if !safeFor("bench.CtxSafe", "os/exec.CommandContext") {
		t.Errorf("CtxSafe must be safe-to-de-escalate for CommandContext")
	}

	// Every unsafe case must keep CWE-78 (no safe fact for its exec sink).
	unsafe := []struct{ fn, sink string }{
		{"bench.UnsafeVar", "os/exec.Command"},         // variable argv[0]
		{"bench.ShellInterp", "os/exec.Command"},       // shell interpreter
		{"bench.VersionedPython", "os/exec.Command"},   // versioned interpreter not on the allowlist
		{"bench.Mixed", "os/exec.Command"},             // one unsafe site among two
		{"bench.PathMutated", "os/exec.Command"},       // cmd.Path re-pointed
		{"bench.Escapes", "os/exec.Command"},           // *exec.Cmd escapes to another function
		{"bench.IndirectFuncValue", "os/exec.Command"}, // unresolved func-value exec call
		{"bench.AbsPath", "os/exec.Command"},           // path form (basename not enough)
		{"bench.AliasIndirect", "os/exec.Command"},     // func-value returning an alias of *exec.Cmd
	}
	for _, u := range unsafe {
		if safeFor(u.fn, u.sink) {
			t.Errorf("%s must NOT be safe-to-de-escalate (keeps CWE-78); facts=%+v", u.fn, facts.Funcs[u.fn])
		}
	}

	// A function with no exec call carries no fact.
	if _, ok := facts.Funcs["bench.NoExec"]; ok {
		t.Errorf("a function with no exec sink must carry no exec fact")
	}

	// The reachability contract's graph is unchanged by the additive facts pass, and CHA does attribute the
	// os/exec.Command edge to the func-value caller (the reason the pass must fail closed there).
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	if !hasEdge(g, "bench.SafeEcho", "os/exec.Command") {
		t.Errorf("the call graph must be unchanged by the facts pass (SafeEcho → os/exec.Command edge missing)")
	}
	if !hasEdge(g, "bench.IndirectFuncValue", "os/exec.Command") {
		t.Errorf("CHA must attribute the func-value exec edge to IndirectFuncValue (the fail-closed trigger)")
	}
}

// TestArgIsFixedSafeProgramFailClosedBranches unit-tests the SSA argument gate's fail-closed branches that
// the integration fixture does not isolate: out-of-range index, non-const arg, non-string const, empty
// const, and a non-allowlisted program.
func TestArgIsFixedSafeProgramFailClosedBranches(t *testing.T) {
	strConst := func(s string) ssa.Value { return ssa.NewConst(constant.MakeString(s), types.Typ[types.String]) }
	intConst := ssa.NewConst(constant.MakeInt64(7), types.Typ[types.Int]) // non-string const
	variable := new(ssa.Parameter)                                        // stands in for a variable argv[0]

	if argIsFixedSafeProgram([]ssa.Value{strConst("echo")}, 1) {
		t.Error("out-of-range index must be unsafe")
	}
	if argIsFixedSafeProgram([]ssa.Value{strConst("echo")}, -1) {
		t.Error("negative index must be unsafe")
	}
	if argIsFixedSafeProgram([]ssa.Value{variable}, 0) {
		t.Error("a non-const (variable) argv[0] must be unsafe")
	}
	if argIsFixedSafeProgram([]ssa.Value{intConst}, 0) {
		t.Error("a non-string const must be unsafe")
	}
	if argIsFixedSafeProgram([]ssa.Value{strConst("")}, 0) {
		t.Error("an empty-string const must be unsafe")
	}
	if argIsFixedSafeProgram([]ssa.Value{strConst("sh")}, 0) {
		t.Error("a shell const must be unsafe")
	}
	if !argIsFixedSafeProgram([]ssa.Value{strConst("echo")}, 0) {
		t.Error("an allowlisted const must be safe")
	}
}

// TestBuildGraphFlagsReflectionBlindConstruct: first-party code that performs a reflect.Value.Call makes the
// CHA graph blind to the reflective target, so the builder must flag "reflection" analysis-wide (EPIC #1042
// #1065) so no not_reachable derived from it can suppress a finding.
func TestBuildGraphFlagsReflectionBlindConstruct(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "reflect"

func main() { invoke(target) }

func target() {}

func invoke(fn interface{}) { reflect.ValueOf(fn).Call(nil) }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !contains(g.BlindConstructs, "reflection") {
		t.Fatalf("first-party reflect.Value.Call must flag the reflection blind construct; got %v", g.BlindConstructs)
	}
}

// TestBuildGraphNoReflectionNoBlindConstruct: an ordinary program (no first-party reflective invocation) must
// NOT flag a blind construct, so a sound not_reachable can still suppress.
func TestBuildGraphNoReflectionNoBlindConstruct(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "fmt"

func main() { fmt.Println("hi") }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(g.BlindConstructs) != 0 {
		t.Fatalf("a program with no first-party reflective invocation must have no blind constructs; got %v", g.BlindConstructs)
	}
}

// TestBuildGraphRouteHandlerIsEntrypoint: an UNEXPORTED handler registered on net/http must become a
// reachability entry point (framework-route discovery, EPIC #1042 #1065), so a vuln reached only through it
// is not misreported not_reachable. A plain unexported function that is never registered stays a non-root.
func TestBuildGraphRouteHandlerIsEntrypoint(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "net/http"

func main() {
	http.HandleFunc("/vuln", handleVuln)
	unregistered()
}

func handleVuln(w http.ResponseWriter, r *http.Request) {}

func unregistered() {}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !contains(g.Entrypoints, "cgfixture.handleVuln") {
		t.Fatalf("an unexported handler registered via http.HandleFunc must be an entrypoint; got %v", g.Entrypoints)
	}
	if contains(g.Entrypoints, "cgfixture.unregistered") {
		t.Fatalf("an unexported, unregistered function must NOT be an entrypoint; got %v", g.Entrypoints)
	}
}

// TestBuildGraphUnreachableReflectionNotFlagged: reflection in an UNREACHABLE function must NOT flag the
// analysis-wide blind construct, so a sound not_reachable on the reachable surface can still suppress. This
// exercises the reachable-surface scoping (EPIC #1042 #1065).
func TestBuildGraphUnreachableReflectionNotFlagged(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "reflect"

func main() { println("hi") }

// unexported + never called -> not an entrypoint, not reachable.
func deadReflect(fn interface{}) { reflect.ValueOf(fn).Call(nil) }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if contains(g.BlindConstructs, "reflection") {
		t.Fatalf("reflection in an unreachable function must not flag the analysis; got %v", g.BlindConstructs)
	}
}

// TestBuildGraphWrappedHandlerResolved: a handler wrapped in http.HandlerFunc(...) and passed to http.Handle
// (an interface arg) must still be resolved to an entrypoint via the SSA unwrap (EPIC #1042 #1065 fix).
func TestBuildGraphWrappedHandlerResolved(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "net/http"

func main() { http.Handle("/vuln", http.HandlerFunc(handleVuln)) }

func handleVuln(w http.ResponseWriter, r *http.Request) {}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !contains(g.Entrypoints, "cgfixture.handleVuln") {
		t.Fatalf("a handler wrapped in http.HandlerFunc and registered via http.Handle must be an entrypoint; got %v", g.Entrypoints)
	}
}

// TestBuildGraphDynamicHandlerFlagsBlind: a route registered with a handler value the graph cannot resolve to
// a static function (read from a variable/slice) must flag a framework_route blind construct, so symbols it
// might reach are not suppressed.
func TestBuildGraphDynamicHandlerFlagsBlind(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "net/http"

func pick() http.HandlerFunc { return nil }

func main() {
	h := pick() // a dynamic handler value the CHA graph cannot resolve to a static function
	http.Handle("/dyn", h)
}
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !contains(g.BlindConstructs, "framework_route") {
		t.Fatalf("an unresolved dynamic route handler must flag framework_route; got %v", g.BlindConstructs)
	}
}

// TestIsRegistrationName covers the route-registration verb gate (EPIC #1042 #1065): an interface-router verb
// (chi.Router.Get) IS a registration even though it arrives as an invoke, while a non-registration router
// call (gin c.JSON) is NOT, so it never falsely disables suppression. net/http is limited to Handle/HandleFunc.
func TestIsRegistrationName(t *testing.T) {
	cases := []struct {
		name, pkg string
		want      bool
	}{
		{"Handle", "net/http", true},
		{"HandleFunc", "net/http", true},
		{"Get", "net/http", false},        // net/http registration is only Handle/HandleFunc
		{"NewRequest", "net/http", false}, // a client call, not registration
		{"Get", "github.com/go-chi/chi/v5", true},
		{"Mount", "github.com/go-chi/chi/v5", true},
		{"JSON", "github.com/gin-gonic/gin", false}, // finding 3: a handler body call, not a registration
		{"GET", "github.com/gin-gonic/gin", true},
		{"HandleFunc", "github.com/gorilla/mux", true},
		{"Add", "github.com/labstack/echo/v4", true},
		{"Use", "github.com/gin-gonic/gin", true}, // middleware runs on every request -> request-surface entry
		{"Pre", "github.com/labstack/echo/v4", true},
		{"Use", "github.com/gorilla/mux", true},
		{"Foo", "example.com/other", false}, // not a router package
		{"Get", "", false},
	}
	for _, c := range cases {
		if got := isRegistrationName(c.name, c.pkg); got != c.want {
			t.Errorf("isRegistrationName(%q,%q)=%v want %v", c.name, c.pkg, got, c.want)
		}
	}
}
