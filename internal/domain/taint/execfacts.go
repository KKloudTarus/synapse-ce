package taint

import "strings"

// ExecPolicy is the value-level de-escalation policy for an exec-style command sink (D5.4). It is pure,
// auditable security data (no behavior): a reviewer reads it to see exactly when a CWE-78 command-injection
// finding is allowed to narrow to a lower class, and to what.
//
// ProgramNameArg is the call-argument index of the program name (argv[0]) — os/exec.Command's arg 0,
// CommandContext's arg 1 (arg 0 is the context). It is consumed by the SSA pass (which inspects that exact
// argument at every call site); the domain never dereferences a call. DeEscalatedCWE/DeEscalatedRule is the
// class the finding drops TO when the program name is proven a compile-time constant naming a known-fixed
// safe program at every site (see IsFixedSafeProgram) AND the resulting *exec.Cmd is confined: the program
// is then fixed and attacker-uncontrolled, so the residual risk is argument injection, not command injection.
type ExecPolicy struct {
	ProgramNameArg  int
	DeEscalatedCWE  string
	DeEscalatedRule string
}

// ExecFacts carries the value-level exec-sink verdicts the SSA pass computes in the sandboxed call-graph
// builder — the argv[0]-is-constant precision the function-granular call graph cannot express. Funcs maps a
// first-party function "importPath.Symbol" (the same identity the call graph uses for a sink-using node) to
// its verdict. An ABSENT entry means "no proof" and keeps the coarse CWE-78 over-approximation (fail-closed),
// so a builder that omits the table (older binary, or a target it could not analyze) degrades safely.
type ExecFacts struct {
	Funcs map[string]ExecFuncFacts
}

// ExecFuncFacts is one function's value-level exec verdict, keyed PER SINK SYMBOL: SafeSinks holds the exec
// sink symbols (e.g. "os/exec.Command") for which the SSA pass proved EVERY call site in the function passes
// a compile-time-constant, non-interpreter program name AND the resulting *exec.Cmd is confined (its program
// is never re-pointed via a field write and it never escapes before execution). De-escalation applies ONLY
// to a sink symbol in this set — a sink the pass never inspected (a future/other exec sink the builder's
// default catalog does not cover) is absent and keeps CWE-78, so a builder/catalog drift fails closed
// rather than de-escalating a sink whose safety was never checked.
type ExecFuncFacts struct {
	SafeSinks map[string]bool
}

// ExecSinkArgs projects the catalog's exec sinks to a "symbol → program-name arg index" map, the single
// source of truth the SSA pass reads to know which call argument to inspect. A catalog with no exec sinks
// yields an empty map (the pass then computes no verdicts, and every command-injection finding keeps CWE-78).
func ExecSinkArgs(cat Catalog) map[string]int {
	out := make(map[string]int, len(cat.Sinks))
	for _, s := range cat.Sinks {
		if s.Exec != nil && s.Symbol != "" {
			out[s.Symbol] = s.Exec.ProgramNameArg
		}
	}
	return out
}

// deEscalateExecSink returns the sink to record for a sink-using function: the original sink unchanged,
// unless it is an exec-style sink (Exec != nil) that the SSA pass listed in the function's SafeSinks set
// (argv[0] a constant, known-fixed-safe program at every call site AND the *exec.Cmd result confined), in
// which case its CWE/Rule narrow to the ExecPolicy target and Exec is cleared (already de-escalated). The
// check is PER SINK SYMBOL, so a sink the pass never inspected is never de-escalated. The Symbol is never
// changed, so the caller's symbol-keyed dedup is unaffected.
func deEscalateExecSink(s Sink, f ExecFuncFacts) Sink {
	if s.Exec == nil || !f.SafeSinks[s.Symbol] {
		return s
	}
	s.CWE = s.Exec.DeEscalatedCWE
	s.Rule = s.Exec.DeEscalatedRule
	s.Exec = nil
	return s
}

// IsFixedSafeProgram reports whether a constant program name (argv[0]) is on the curated ALLOWLIST of
// programs that provably do NOT execute or interpret a command or code taken from their arguments — so that
// with a fixed argv[0] the worst case is argument injection (CWE-88), never command injection (CWE-78).
//
// It de-escalates ONLY a BARE program name matched EXACTLY (case-sensitive, no suffix stripping) against the
// vetted set. Any name containing a path separator ("/bin/echo", "./echo", "..\\x") keeps CWE-78: a
// directory component can point at attacker-writable or otherwise untrusted code (e.g. "/tmp/echo"), so the
// basename does NOT prove the program is fixed. Any name with whitespace, a different case ("ECHO"), or a
// suffix ("echo.exe") is a DIFFERENT file on a case-sensitive filesystem and also keeps CWE-78. It assumes
// the runtime PATH used to resolve a bare name is not attacker-controlled; a target that rewrites its own
// PATH to an attacker directory is a separate untrusted-search-path weakness, not the taint flow analyzed
// here.
//
// This is FAIL-CLOSED by design (the #1 bar: never understate a real command injection). The set of programs
// that DO run a command from their arguments — shells (sh -c), interpreters (python -c, deno eval), and
// command-runners (env, xargs, pkexec, flock, chroot, find -exec, …) — is open-ended and version-suffixed
// on real hosts ("python3.11", "php8.2"), so a denylist of them can never be complete and would fail OPEN.
// Instead only an explicitly-vetted safe program de-escalates; ANY other constant program name (an unknown
// tool, a versioned interpreter, a command-runner, a path) keeps CWE-78. A program missing from this
// allowlist costs only a residual false positive (the pre-D5.4 over-approximation, gated by a verifier);
// de-escalating an unrecognized program would risk understating a real command injection, which this must
// never do. Every entry takes data/paths/URLs as arguments and never spawns an argument as a command.
func IsFixedSafeProgram(name string) bool {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.ContainsAny(name, " \t\r\n\v\f") {
		return false // a path, or a name with whitespace, is not a bare vetted program
	}
	return fixedSafePrograms[name]
}

// fixedSafePrograms is the curated allowlist of programs that never execute a command/code from their
// arguments, so a constant argv[0] naming one makes the exec call at worst argument injection (CWE-88). It
// deliberately EXCLUDES anything that can run a program named in a later argument (shells, interpreters,
// sudo/pkexec/env/xargs/find/flock/chroot/ssh/awk/sed/…) and grows only under security review. Grouped by
// kind. A program's OTHER risks (path traversal for cp/cat, SSRF for curl) are separate CWEs, not CWE-78.
var fixedSafePrograms = map[string]bool{
	// Trivial / control.
	"echo": true, "printf": true, "true": true, "false": true, "sleep": true, "yes": true, "seq": true,
	// Text processing that does not exec. Deliberately ABSENT: sed/awk (interpreters), and "sort" (GNU sort's
	// --compress-program=PROG executes PROG, an argument-to-command-exec vector).
	"cat": true, "tac": true, "head": true, "tail": true, "nl": true, "wc": true, "cut": true, "tr": true,
	"rev": true, "fold": true, "fmt": true, "tee": true, "uniq": true, "comm": true,
	"paste": true, "cmp": true, "column": true, "expand": true, "unexpand": true,
	// Search (grep has no exec option; ripgrep's --pre runs a command, so "rg" is absent).
	"grep": true, "egrep": true, "fgrep": true,
	// Encoding / hashing.
	"base64": true, "base32": true, "md5sum": true, "sha1sum": true, "sha256sum": true, "sha512sum": true,
	"cksum": true, "b2sum": true,
	// Filesystem inspection / manipulation (path traversal is CWE-22/CWE-88, not command exec).
	"ls": true, "stat": true, "file": true, "basename": true, "dirname": true, "readlink": true,
	"realpath": true, "pwd": true, "cp": true, "mv": true, "mkdir": true, "rmdir": true, "touch": true,
	"ln": true, "df": true, "du": true,
	// System / identity info.
	"date": true, "hostname": true, "uname": true, "whoami": true, "id": true, "groups": true,
	"uptime": true, "arch": true, "nproc": true, "printenv": true, "logname": true,
	// Network probes (SSRF/URL risk is CWE-918, not command exec). Deliberately ABSENT: curl/wget (wget
	// --use-askpass=CMD runs CMD; rich option surfaces), "traceroute" (-M/--module can select an external
	// module), and "ip"/"nmap" (ip netns exec, nmap --script) — all can execute a command/code from an arg.
	"ping": true, "ping6": true, "tracepath": true, "dig": true, "nslookup": true, "host": true,
}
