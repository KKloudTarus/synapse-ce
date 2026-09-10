package taint

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

// The classic injection shape: ONE function both reads untrusted input and calls a dangerous sink
// (`db.Query(r.FormValue("id"))`). That function is both source- and sink-using, so Vulnerabilities reports
// it as the length-1 path – the most common, clearest taint bug.
func TestAssembleSameFunctionIsLength1Path(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"net/http.Request.FormValue", "database/sql.DB.Query"}},
	}}
	fg, sinkClass := Assemble(g, DefaultCatalog())

	vulns := fg.Vulnerabilities()
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d: %+v", len(vulns), vulns)
	}
	v := vulns[0]
	if v.Source != "app.handler" || v.Sink != "app.handler" || !reflect.DeepEqual(v.Path, []string{"app.handler"}) {
		t.Errorf("same-function injection must be a length-1 path at the using-function: %+v", v)
	}
	classes := sinkClass["app.handler"]
	if len(classes) != 1 || classes[0].CWE != "CWE-89" || classes[0].Rule != "taint-sqli" {
		t.Errorf("sink-class index must carry the SQLi class for the using-function: %+v", classes)
	}
}

// Linear cross-function flow: a handler reads input then (transitively) calls a function that sinks it.
// The forward call path handler→dao is the over-approximation the FlowGraph reports.
func TestAssembleLinearCrossFunction(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "app.dao"}},
		{Caller: "app.dao", Callees: []string{"os/exec.Command"}},
	}}
	fg, sinkClass := Assemble(g, DefaultCatalog())

	vulns := fg.Vulnerabilities()
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d: %+v", len(vulns), vulns)
	}
	v := vulns[0]
	if v.Source != "app.handler" || v.Sink != "app.dao" {
		t.Errorf("want handler→dao flow, got %+v", v)
	}
	if !reflect.DeepEqual(v.Path, []string{"app.handler", "app.dao"}) {
		t.Errorf("path witness must be the call chain: %+v", v.Path)
	}
	if cs := sinkClass["app.dao"]; len(cs) != 1 || cs[0].CWE != "CWE-78" {
		t.Errorf("dao must be tagged command-injection: %+v", cs)
	}
}

// A sanitizer-using function on the only path to the sink WALLS the flow: data leaving it is treated as
// clean, so the sink reachable only through it is correctly NOT reported.
func TestAssembleSanitizerWalls(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "app.clean"}},
		{Caller: "app.clean", Callees: []string{"net/url.QueryEscape", "app.fetch"}},
		{Caller: "app.fetch", Callees: []string{"net/http.Get"}},
	}}
	fg, _ := Assemble(g, DefaultCatalog())

	if fg.Vulnerable() {
		t.Errorf("a path that crosses a sanitizer-using function must be reported clean: %+v", fg.Vulnerabilities())
	}
}

// When the sink is ALSO reachable by a path that does NOT cross the sanitizer, the flow is still a vuln –
// the wall only prunes the sanitized route.
func TestAssembleUnsanitizedRouteStillVuln(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"os.Getenv", "app.clean", "app.fetch"}},
		{Caller: "app.clean", Callees: []string{"net/url.QueryEscape"}},
		{Caller: "app.fetch", Callees: []string{"net/http.Get"}},
	}}
	fg, _ := Assemble(g, DefaultCatalog())

	vulns := fg.Vulnerabilities()
	if len(vulns) != 1 || vulns[0].Sink != "app.fetch" {
		t.Fatalf("the direct handler→fetch route bypasses the sanitizer and must be reported: %+v", vulns)
	}
}

// A using-function that reaches two distinct sink classes yields a claim per class (no silent drop).
func TestAssembleMultiClassSinkNode(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "app.handler", Callees: []string{"database/sql.DB.Query", "os/exec.Command"}},
	}}
	_, sinkClass := Assemble(g, DefaultCatalog())

	classes := sinkClass["app.handler"]
	if len(classes) != 2 {
		t.Fatalf("a node calling two sink classes must record both, got %+v", classes)
	}
	// Sorted by symbol: "database/sql.DB.Query" (CWE-89) before "os/exec.Command" (CWE-78).
	if classes[0].CWE != "CWE-89" || classes[1].CWE != "CWE-78" {
		t.Errorf("sink classes must be deterministic (sorted by symbol): %+v", classes)
	}
}

// Malformed edges from the (untrusted) builder must be dropped, never minting phantom roles.
func TestAssembleDropsEmptyEndpoints(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "", Callees: []string{"database/sql.DB.Query"}},         // no caller → dropped
		{Caller: "app.x", Callees: []string{"", "database/sql.DB.Exec"}}, // empty callee skipped, real one kept
	}}
	fg, _ := Assemble(g, DefaultCatalog())

	if len(fg.Sinks) != 1 || fg.Sinks[0] != "app.x" {
		t.Errorf("only the well-formed sink-using function may appear: %+v", fg.Sinks)
	}
	for _, f := range fg.Flows {
		if f.From == "" || f.To == "" {
			t.Errorf("no flow may carry an empty endpoint: %+v", f)
		}
	}
}

// Determinism: identical input ⇒ identical FlowGraph + sink-class index (a Tier-2 result must be reproducible).
func TestAssembleDeterministic(t *testing.T) {
	g := callgraph.Graph{Edges: []callgraph.Edge{
		{Caller: "b.h2", Callees: []string{"os/exec.Command", "net/http.Request.FormValue"}},
		{Caller: "a.h1", Callees: []string{"database/sql.DB.Query", "os.Getenv"}},
	}}
	fg1, sc1 := Assemble(g, DefaultCatalog())
	fg2, sc2 := Assemble(g, DefaultCatalog())
	if !reflect.DeepEqual(fg1, fg2) || !reflect.DeepEqual(sc1, sc2) {
		t.Error("Assemble must be deterministic for identical input")
	}
	// Role sets are sorted.
	if !reflect.DeepEqual(fg1.Sources, []string{"a.h1", "b.h2"}) {
		t.Errorf("sources must be sorted: %+v", fg1.Sources)
	}
}

// The starter pack is a security artifact: every sink must carry a CWE + rule, and no symbol may be empty.
func TestDefaultCatalogWellFormed(t *testing.T) {
	c := DefaultCatalog()
	if len(c.Sources) == 0 || len(c.Sinks) == 0 || len(c.Sanitizers) == 0 {
		t.Fatal("the default catalog must populate all three role sets")
	}
	seenCWE := map[string]bool{}
	for _, s := range c.Sinks {
		if s.Symbol == "" || s.CWE == "" || s.Rule == "" {
			t.Errorf("every catalog sink must carry symbol+CWE+rule: %+v", s)
		}
		seenCWE[s.CWE] = true
	}
	for _, want := range []string{"CWE-89", "CWE-78", "CWE-22", "CWE-918", "CWE-79"} {
		if !seenCWE[want] {
			t.Errorf("the starter pack must cover %s", want)
		}
	}
	for _, sym := range append(append([]string{}, c.Sources...), c.Sanitizers...) {
		if sym == "" {
			t.Error("no source/sanitizer symbol may be empty")
		}
	}
	// Soundness guard (security review): a class-blind sanitizer wall must list ONLY purpose-built
	// neutralizers. filepath.Clean does not prevent traversal (it would mask CWE-22) and incidental
	// utilities like strconv.Atoi would wall unrelated real flows – both must stay OUT.
	unsound := map[string]bool{"path/filepath.Clean": true, "strconv.Atoi": true, "strconv.ParseInt": true}
	for _, s := range c.Sanitizers {
		if unsound[s] {
			t.Errorf("%q is not a sound sanitizer (class-blind wall would suppress real injections); keep it out", s)
		}
	}
}

// The expanded path/SSRF sink coverage flags a flow through a newly-modeled sink (a tainted path reaching
// os.Remove, a tainted URL reaching http.PostForm), the same way the original sinks do.
func TestAssembleExpandedSinks(t *testing.T) {
	cases := []struct {
		name string
		sink string
		cwe  string
	}{
		{"path-remove", "os.Remove", "CWE-22"},
		{"path-mkdirall", "os.MkdirAll", "CWE-22"},
		{"path-readdir", "os.ReadDir", "CWE-22"},
		{"path-rename", "os.Rename", "CWE-22"},
		{"ssrf-postform", "net/http.PostForm", "CWE-918"},
		{"ssrf-client-head", "net/http.Client.Head", "CWE-918"},
	}
	for _, tc := range cases {
		g := callgraph.Graph{Edges: []callgraph.Edge{
			{Caller: "app.handler", Callees: []string{"net/http.Request.FormValue", "app.op"}},
			{Caller: "app.op", Callees: []string{tc.sink}},
		}}
		fg, sinkClass := Assemble(g, DefaultCatalog())
		vulns := fg.Vulnerabilities()
		if len(vulns) != 1 || vulns[0].Sink != "app.op" {
			t.Errorf("%s: want a flow to the sink, got %+v", tc.name, vulns)
			continue
		}
		if cs := sinkClass["app.op"]; len(cs) != 1 || cs[0].CWE != tc.cwe {
			t.Errorf("%s: sink must be tagged %s, got %+v", tc.name, tc.cwe, cs)
		}
	}
}

// The new path sinks that also take a non-path argument are deliberately NOT added, so a tainted content
// argument cannot fire a false path-traversal: os.WriteFile stays out of the catalog.
func TestWriteFileNotAPathSink(t *testing.T) {
	for _, s := range DefaultCatalog().Sinks {
		if s.Symbol == "os.WriteFile" {
			t.Errorf("os.WriteFile takes a data argument; a class-blind match would false-positive on tainted content")
		}
	}
}

// The Go source set includes the Go 1.22 path parameter and the header accessors, so a flow from a path
// parameter (or Referer/User-Agent) into a sink is detected.
func TestAssembleExpandedSources(t *testing.T) {
	for _, src := range []string{"net/http.Request.PathValue", "net/http.Request.Referer", "net/http.Request.UserAgent"} {
		g := callgraph.Graph{Edges: []callgraph.Edge{
			{Caller: "app.handler", Callees: []string{src, "app.op"}},
			{Caller: "app.op", Callees: []string{"os/exec.Command"}},
		}}
		fg, _ := Assemble(g, DefaultCatalog())
		vulns := fg.Vulnerabilities()
		if len(vulns) != 1 || vulns[0].Source != "app.handler" || vulns[0].Sink != "app.op" {
			t.Errorf("%s: expected a source->sink flow, got %+v", src, vulns)
		}
	}
}
