package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

func TestIsFixedSafeProgram(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Allowlisted BARE names → safe to de-escalate (exact, case-sensitive, no suffix strip).
		{"echo", true},
		{"ping", true},
		{"ping6", true},
		{"ls", true},
		{"cat", true},
		{"grep", true},
		{"sha256sum", true},
		// A path form is NOT de-escalated: a directory component can point at untrusted code (/tmp/echo),
		// so the basename does not prove the program is fixed.
		{"/bin/echo", false},
		{"/tmp/echo", false},
		{"./echo", false},
		{`..\echo`, false},
		// Case / suffix / whitespace variants are DIFFERENT files → keep CWE-78 (no normalization).
		{"ECHO", false},
		{"echo.exe", false},
		{"echo ", false},
		{" echo", false},
		// NOT allowlisted → keep CWE-78 (fail-closed). Shells + interpreters + command-runners.
		{"sh", false},
		{"/bin/sh", false},
		{"bash", false},
		{"python", false},
		{"python3", false},
		{"python3.11", false}, // versioned interpreter: the common real binary name — must NOT de-escalate
		{"php8.2", false},
		{"ruby2.7", false},
		{"node18", false},
		{"deno", false},
		{"bun", false},
		{"pkexec", false},
		{"flock", false},
		{"chroot", false},
		{"env", false},
		{"xargs", false},
		{"sudo", false},
		{"find", false},       // find -exec runs commands
		{"awk", false},        // awk system()/interpreter
		{"sed", false},        // sed e command execs
		{"git", false},        // argument-to-RCE (git -c core.sshCommand); keep CWE-78
		{"sort", false},       // GNU sort --compress-program=PROG runs PROG
		{"wget", false},       // wget --use-askpass=CMD runs CMD
		{"curl", false},       // excluded out of caution (rich option surface; SSRF is CWE-918)
		{"traceroute", false}, // traceroute -M/--module can select an external module
		{"", false},
		{"someunknowntool", false}, // unknown → keep CWE-78
	}
	for _, c := range cases {
		if got := IsFixedSafeProgram(c.name); got != c.want {
			t.Errorf("IsFixedSafeProgram(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestExecSinkArgs(t *testing.T) {
	args := ExecSinkArgs(DefaultCatalog())
	if got, ok := args["os/exec.Command"]; !ok || got != 0 {
		t.Errorf("os/exec.Command program-name arg must be 0, got %d ok=%v", got, ok)
	}
	if got, ok := args["os/exec.CommandContext"]; !ok || got != 1 {
		t.Errorf("os/exec.CommandContext program-name arg must be 1 (arg 0 is the context), got %d ok=%v", got, ok)
	}
	// A non-exec sink must not appear (only Exec-tagged sinks are exec sinks).
	if _, ok := args["database/sql.DB.Query"]; ok {
		t.Error("a SQLi sink must not be listed as an exec sink")
	}
}

// AssembleWithFacts de-escalates a command-injection sink to CWE-88 only when the SSA pass listed that exact
// sink symbol in the function's SafeSinks; without it the coarse CWE-78 over-approximation stands.
func TestAssembleWithFactsDeEscalatesExecSink(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.safe", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}
	facts := ExecFacts{Funcs: map[string]ExecFuncFacts{
		"app.safe": {SafeSinks: map[string]bool{"os/exec.Command": true}},
	}}

	_, sinkClass := AssembleWithFacts(g, DefaultCatalog(), facts)
	classes := sinkClass["app.safe"]
	if len(classes) != 1 || classes[0].CWE != "CWE-88" || classes[0].Rule != "taint-argument-injection" {
		t.Fatalf("a safe exec sink must de-escalate to CWE-88 argument injection: %+v", classes)
	}
	if classes[0].Symbol != "os/exec.Command" {
		t.Errorf("de-escalation must not change the sink symbol, got %q", classes[0].Symbol)
	}
	if classes[0].Exec != nil {
		t.Errorf("a de-escalated sink must clear its Exec policy (already de-escalated): %+v", classes[0].Exec)
	}
}

func TestAssembleWithFactsKeepsCWE78WithoutFact(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.unsafe", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}
	// No fact for app.unsafe (variable argv[0] emits none) → keep CWE-78.
	_, sinkClass := AssembleWithFacts(g, DefaultCatalog(), ExecFacts{})
	classes := sinkClass["app.unsafe"]
	if len(classes) != 1 || classes[0].CWE != "CWE-78" || classes[0].Rule != "taint-command-injection" {
		t.Fatalf("no fact must keep CWE-78 command injection: %+v", classes)
	}
}

// A per-symbol fact for a DIFFERENT sink must not de-escalate an exec sink it does not name (fail-closed
// against builder/catalog drift).
func TestAssembleWithFactsIsPerSinkSymbol(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.h", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}
	// The function is marked safe for CommandContext, but it calls Command — Command must NOT de-escalate.
	facts := ExecFacts{Funcs: map[string]ExecFuncFacts{
		"app.h": {SafeSinks: map[string]bool{"os/exec.CommandContext": true}},
	}}
	_, sinkClass := AssembleWithFacts(g, DefaultCatalog(), facts)
	if c := sinkClass["app.h"]; len(c) != 1 || c[0].CWE != "CWE-78" {
		t.Fatalf("a fact naming a different sink must not de-escalate os/exec.Command: %+v", c)
	}
}

// CommandContext (program name at arg 1) de-escalates the same way as Command when its symbol is listed.
func TestAssembleWithFactsDeEscalatesCommandContext(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.ctx", Callees: []string{"os.Getenv", "os/exec.CommandContext"}},
	}}
	facts := ExecFacts{Funcs: map[string]ExecFuncFacts{
		"app.ctx": {SafeSinks: map[string]bool{"os/exec.CommandContext": true}},
	}}
	_, sinkClass := AssembleWithFacts(g, DefaultCatalog(), facts)
	if c := sinkClass["app.ctx"]; len(c) != 1 || c[0].CWE != "CWE-88" {
		t.Fatalf("CommandContext must de-escalate to CWE-88, got %+v", c)
	}
}

// De-escalation is scoped to exec sinks: a safe verdict on a function must not touch its non-exec (e.g.
// SQLi) sinks — those have no ExecPolicy.
func TestAssembleWithFactsLeavesNonExecSinksAlone(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.both", Callees: []string{"os.Getenv", "os/exec.Command", "database/sql.DB.Query"}},
	}}
	facts := ExecFacts{Funcs: map[string]ExecFuncFacts{
		"app.both": {SafeSinks: map[string]bool{"os/exec.Command": true}},
	}}
	_, sinkClass := AssembleWithFacts(g, DefaultCatalog(), facts)
	var sawSQLi, sawArgInj bool
	for _, s := range sinkClass["app.both"] {
		if s.CWE == "CWE-89" && s.Rule == "taint-sqli" {
			sawSQLi = true
		}
		if s.CWE == "CWE-88" && s.Symbol == "os/exec.Command" {
			sawArgInj = true
		}
		if s.CWE == "CWE-78" {
			t.Errorf("the exec sink must have de-escalated, not stayed CWE-78: %+v", s)
		}
	}
	if !sawSQLi {
		t.Error("the SQLi sink must be untouched by exec de-escalation")
	}
	if !sawArgInj {
		t.Error("the exec sink must de-escalate to CWE-88")
	}
}

// Assemble (no facts) is exactly AssembleWithFacts with an empty table: the command-injection sink stays
// CWE-78, proving back-compatibility for every existing caller.
func TestAssembleIsAssembleWithEmptyFacts(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.h", Callees: []string{"os.Getenv", "os/exec.Command"}},
	}}
	_, viaAssemble := Assemble(g, DefaultCatalog())
	if c := viaAssemble["app.h"]; len(c) != 1 || c[0].CWE != "CWE-78" {
		t.Fatalf("Assemble must keep CWE-78 (empty facts), got %+v", c)
	}
}
