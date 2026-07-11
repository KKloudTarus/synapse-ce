package taint

import (
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

// Sink is a dangerous-operation function in the catalog, tagged with the injection class it represents.
// CWE is the weakness id (e.g. "CWE-89") and Rule the short taint-rule name (e.g. "taint-sqli"); both ride
// from the catalog through Assemble into the eventual SASTClaim, so a judgment carries its injection class.
type Sink struct {
	Symbol string // "importPath.Symbol", e.g. "database/sql.DB.Query"
	CWE    string // e.g. "CWE-89"
	Rule   string // e.g. "taint-sqli"
}

// Catalog is the curated, per-language set of taint roles in the shared "importPath.Symbol" convention
// SOURCE functions that return untrusted data (net/http.Request.FormValue, os.Getenv),
// SINK functions that perform a dangerous operation (database/sql.DB.Query, os/exec.Command – each tagged
// with its injection class), and SANITIZER functions that neutralize data (html.EscapeString,
// net/url.QueryEscape). It is pure data – no behavior – so it is table-testable and reviewable as a
// standalone security artifact, independent of the call-graph engine that feeds Assemble.
type Catalog struct {
	Sources    []string
	Sinks      []Sink
	Sanitizers []string
}

// Assemble builds a taint.FlowGraph from a call graph + the catalog, realizing a coarse
// control-flow-as-data-flow over-approximation: a function that CALLS a catalog source/sink/sanitizer takes
// on that role, and the call edges become Flows. FlowGraph.Vulnerabilities() then reports a forward call
// path from a source-using function to a sink-using function that crosses no sanitizer-using function – and
// the classic same-function shape (`db.Query(r.FormValue(...))`) where one function is both source- and
// sink-using surfaces as the length-1 path Vulnerabilities() already models.
//
// The second return is the sink-class index: a FlowGraph sink-node ("importPath.Symbol" of the *using*
// function) → the distinct catalog Sinks it calls (CWE + rule, sorted by symbol), so the judgment
// coordinator can tag each reported path with its injection class – and a function that reaches two
// sink classes yields a claim per class rather than silently dropping one. The index is keyed by the
// using-function and lists every sink class that function calls regardless of sanitizer pruning, so the
// consumer must JOIN it against the paths Vulnerabilities() actually reports (sinkClass[path.Sink]) rather
// than treat every listed class as source-reachable.
//
// Coarseness (gated + triaged, NOT presented as precise): function granularity ⇒
// a false POSITIVE when the tainted value does not actually reach the sink's argument; and
// false NEGATIVES on shapes a call graph alone can't separate at value level: the sibling-call shape (a
// function gets tainted data from one callee and hands it to another, with no forward edge between the
// two using-functions); a function that sanitizes one value but sinks another (the sanitizer role walls
// the whole node); a source-using function that ALSO calls a sanitizer (walled at the source – the
// mirror of the previous case); and class-blindness – a sanitizer node walls EVERY injection class
// through it, not only the class it neutralizes.
//
// Precise SSA def-use closes these and is the deferred follow-up; this MVP is the recall floor that a
// distinct human/LLM verifier gates before promotion. Because the wall is class-blind, the sanitizer set is
// kept to PURPOSE-BUILT neutralizers (escapers / containment checks) and deliberately omits incidental
// general utilities (e.g. strconv.Atoi) that, walling every flow through their caller, would suppress
// unrelated real injections.
func Assemble(g callgraph.Graph, cat Catalog) (FlowGraph, map[string][]Sink) {
	srcSet := toSet(cat.Sources)
	sanSet := toSet(cat.Sanitizers)
	sinkSet := make(map[string]Sink, len(cat.Sinks))
	for _, s := range cat.Sinks {
		if s.Symbol == "" {
			continue
		}
		if _, dup := sinkSet[s.Symbol]; !dup { // first catalog entry for a symbol wins (deterministic input order)
			sinkSet[s.Symbol] = s
		}
	}

	var fg FlowGraph
	sources := map[string]bool{}
	sinks := map[string]bool{}
	sanitizers := map[string]bool{}
	sinkClassSet := map[string]map[string]Sink{} // using-function node → symbol → catalog Sink (dedup)

	for _, e := range g.Edges {
		if e.Caller == "" {
			continue // the builder is untrusted: drop malformed edges rather than mint phantom roles
		}
		for _, callee := range e.Callees {
			if callee == "" {
				continue
			}
			fg.Flows = append(fg.Flows, Flow{From: e.Caller, To: callee})
			if srcSet[callee] {
				sources[e.Caller] = true
			}
			if sanSet[callee] {
				sanitizers[e.Caller] = true
			}
			if s, ok := sinkSet[callee]; ok {
				sinks[e.Caller] = true
				if sinkClassSet[e.Caller] == nil {
					sinkClassSet[e.Caller] = map[string]Sink{}
				}
				sinkClassSet[e.Caller][s.Symbol] = s
			}
		}
	}

	fg.Sources = sortedKeys(sources)
	fg.Sinks = sortedKeys(sinks)
	fg.Sanitizers = sortedKeys(sanitizers)

	sinkClass := make(map[string][]Sink, len(sinkClassSet))
	for node, set := range sinkClassSet {
		syms := make([]string, 0, len(set))
		for sym := range set {
			syms = append(syms, sym)
		}
		sort.Strings(syms)
		list := make([]Sink, 0, len(syms))
		for _, sym := range syms {
			list = append(list, set[sym])
		}
		sinkClass[node] = list
	}
	return fg, sinkClass
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DefaultCatalog is the starter injection pack over the five injection classes – SQL injection,
// command injection, path traversal, SSRF, and reflected XSS – keyed in the shared "importPath.Symbol"
// convention (methods are "importPath.RecvType.Method", the receiver's leading '*' stripped, matching the
// call-graph + govulncheck node ids). It is intentionally high-signal rather than exhaustive: a curated
// catalog is the unit a security reviewer can audit, and it is meant to grow under review, not to be a
// complete model of the standard library.
func DefaultCatalog() Catalog {
	return Catalog{
		Sources: []string{
			// Untrusted request input.
			"net/http.Request.FormValue",
			"net/http.Request.PostFormValue",
			"net/http.Request.FormFile",
			"net/http.Request.Cookie",
			"net/http.Header.Get", // request headers (r.Header.Get) – header-driven injection
			"net/url.Values.Get",
			// Process environment / argv are attacker-influenced in many deployment models.
			"os.Getenv",
		},
		Sinks: []Sink{
			// CWE-89 – SQL injection: string-built queries reach the DB driver.
			{Symbol: "database/sql.DB.Query", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.DB.QueryContext", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.DB.QueryRow", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.DB.QueryRowContext", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.DB.Exec", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.DB.ExecContext", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.Tx.Query", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.Tx.QueryContext", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.Tx.Exec", CWE: "CWE-89", Rule: "taint-sqli"},
			{Symbol: "database/sql.Tx.ExecContext", CWE: "CWE-89", Rule: "taint-sqli"},
			// CWE-78 – OS command injection.
			{Symbol: "os/exec.Command", CWE: "CWE-78", Rule: "taint-command-injection"},
			{Symbol: "os/exec.CommandContext", CWE: "CWE-78", Rule: "taint-command-injection"},
			// CWE-22 – path traversal: an attacker-controlled path opened on the host filesystem.
			{Symbol: "os.Open", CWE: "CWE-22", Rule: "taint-path-traversal"},
			{Symbol: "os.OpenFile", CWE: "CWE-22", Rule: "taint-path-traversal"},
			{Symbol: "os.ReadFile", CWE: "CWE-22", Rule: "taint-path-traversal"},
			{Symbol: "os.Create", CWE: "CWE-22", Rule: "taint-path-traversal"},
			// CWE-918 – SSRF: an attacker-controlled URL fetched server-side.
			{Symbol: "net/http.Get", CWE: "CWE-918", Rule: "taint-ssrf"},
			{Symbol: "net/http.Post", CWE: "CWE-918", Rule: "taint-ssrf"},
			{Symbol: "net/http.Head", CWE: "CWE-918", Rule: "taint-ssrf"},
			{Symbol: "net/http.Client.Do", CWE: "CWE-918", Rule: "taint-ssrf"},
			{Symbol: "net/http.Client.Get", CWE: "CWE-918", Rule: "taint-ssrf"},
			{Symbol: "net/http.Client.Post", CWE: "CWE-918", Rule: "taint-ssrf"},
			// CWE-79 – reflected XSS. text/template does NOT auto-escape (unlike html/template); and the
			// dominant Go reflected-XSS sink is writing untrusted bytes straight to the response. NOTE:
			// ResponseWriter is an INTERFACE, so whether this fires depends on how the call graph resolves
			// interface dispatch (CHA edges land on the concrete *http.response.Write); it is listed for
			// intent + future builders and is harmless if it does not match (no FP, no panic).
			{Symbol: "text/template.Template.Execute", CWE: "CWE-79", Rule: "taint-xss"},
			{Symbol: "text/template.Template.ExecuteTemplate", CWE: "CWE-79", Rule: "taint-xss"},
			{Symbol: "net/http.ResponseWriter.Write", CWE: "CWE-79", Rule: "taint-xss"},
		},
		// Sanitizers are PURPOSE-BUILT neutralizers only – each entry's sole job is to render data safe – so a
		// class-blind wall (see Assemble) does not also suppress unrelated real flows. Incidental utilities
		// (strconv.Atoi, etc.) are deliberately excluded. filepath.Clean is NOT a path-traversal sanitizer:
		// Clean("/base/"+"../../etc/passwd") collapses to "/etc/passwd", so it would mask CWE-22; the sound
		// containment check is filepath.IsLocal (Go 1.20+).
		Sanitizers: []string{
			"html.EscapeString",     // XSS – HTML entity escaper
			"net/url.QueryEscape",   // SSRF / URL – query escaper
			"net/url.PathEscape",    // SSRF / URL – path-segment escaper
			"path/filepath.IsLocal", // CWE-22 – rejects paths that escape the base dir (the real traversal guard)
		},
	}
}
