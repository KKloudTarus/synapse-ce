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
