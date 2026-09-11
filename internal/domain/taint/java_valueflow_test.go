package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
)

const javaTestFile = "App.java"

func jPos() javaprogram.Position { return javaprogram.Position{File: javaTestFile, Line: 5, Column: 2} }

func jModID() string  { return javaprogram.CanonicalSymbolID("App", "<module>") }
func jClsID() string  { return javaprogram.CanonicalSymbolID("App", "App") }
func jHandID() string { return javaprogram.CanonicalSymbolID("App", "App.handle") }

// javaSkeleton assembles a valid one-module/one-class/one-method document around the given method params,
// values, flows, calls, and imports. The method "handle" owns all the facts.
func javaSkeleton(params []javaprogram.Parameter, values []javaprogram.Value, flows []javaprogram.ValueFlow,
	calls []javaprogram.Call, imports []javaprogram.Import) javaprogram.Document {
	p := jPos()
	return javaprogram.Document{
		SchemaVersion: javaprogram.SchemaVersion,
		Modules:       []javaprogram.Module{{Name: "App", File: javaTestFile, Pos: p}},
		Symbols: []javaprogram.Symbol{
			{ID: jModID(), Module: "App", QualifiedName: "<module>", Name: "App", Kind: javaprogram.SymbolModule, Pos: p},
			{ID: jClsID(), Module: "App", QualifiedName: "App", Name: "App", ParentID: jModID(), Kind: javaprogram.SymbolClass, Pos: p},
			{ID: jHandID(), Module: "App", QualifiedName: "App.handle", Name: "handle", ParentID: jClsID(), Kind: javaprogram.SymbolMethod, Pos: p, Parameters: params},
		},
		Values:      values,
		Flows:       flows,
		Calls:       calls,
		Imports:     imports,
		FilesSeen:   1,
		FilesParsed: 1,
	}
}

// callSourceDoc models: `X r = <sourceCallee>(...); <sinkCallee>(..., r)` where the source-call result flows
// into argument 0 of the sink call. sinkNew makes the sink an object-creation (`new T(r)`).
func callSourceDoc(t *testing.T, sourceCallee, sinkCallee []string, sinkNew bool, imports []javaprogram.Import) javaprogram.Document {
	t.Helper()
	p := jPos()
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-arg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"r"}}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{{FromID: "v-src", ToID: "v-arg", Kind: javaprogram.FlowAssignment, Pos: p}}
	kind := javaprogram.ReferenceAttribute
	if len(sourceCallee) == 1 {
		kind = javaprogram.ReferenceName
	}
	sinkKind := javaprogram.ReferenceAttribute
	if len(sinkCallee) == 1 {
		sinkKind = javaprogram.ReferenceName
	}
	calls := []javaprogram.Call{
		{ID: "c-src", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: kind, Segments: sourceCallee}, ResultID: "v-src", Pos: p},
		{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: sinkKind, Segments: sinkCallee}, New: sinkNew,
			Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"r"}}, ValueID: "v-arg", Pos: p}}, Pos: p},
	}
	return javaSkeleton(nil, values, flows, calls, imports)
}

func javaRules(t *testing.T, doc javaprogram.Document) map[string]bool {
	t.Helper()
	g, err := BuildJavaValueGraph(doc, DefaultJavaCatalog())
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	out := map[string]bool{}
	for _, v := range g.Vulnerabilities() {
		out[v.Rule] = true
	}
	return out
}

func TestJavaTaintPositivePerClass(t *testing.T) {
	src := []string{"request", "getParameter"}
	cases := []struct {
		name    string
		sink    []string
		sinkNew bool
		imports []javaprogram.Import
		want    string
	}{
		{"sql-statement", []string{"stmt", "executeQuery"}, false, nil, "java-taint-sql-statement"},
		{"sql-prepare", []string{"conn", "prepareStatement"}, false, nil, "java-taint-sql-statement"},
		{"command-exec", []string{"rt", "exec"}, false, nil, "java-taint-command-exec"},
		{"command-processbuilder", []string{"ProcessBuilder"}, true, nil, "java-taint-command-processbuilder"},
		{"deser-ois-ctor", []string{"ObjectInputStream"}, true,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "java.io.ObjectInputStream", Name: "ObjectInputStream", Pos: jPos()}},
			"java-taint-deser-ois"},
		{"code-eval", []string{"engine", "eval"}, false, nil, "java-taint-code-scripteval"},
		{"ssrf-resttemplate", []string{"rest", "getForObject"}, false, nil, "java-taint-ssrf-resttemplate"},
		{"path-file-ctor", []string{"File"}, true,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "java.io.File", Name: "File", Pos: jPos()}},
			"java-taint-path-file"},
		{"ssrf-url-ctor", []string{"URL"}, true,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "java.net.URL", Name: "URL", Pos: jPos()}},
			"java-taint-ssrf-url"},
		{"path-paths-get", []string{"Paths", "get"}, false,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "java.nio.file.Paths", Name: "Paths", Pos: jPos()}},
			"java-taint-path-paths-get"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := javaRules(t, callSourceDoc(t, src, tc.sink, tc.sinkNew, tc.imports))
			if !got[tc.want] {
				t.Errorf("want rule %q from a request.getParameter -> %v flow; got %v", tc.want, tc.sink, got)
			}
		})
	}
}

// TestJavaAnnotationSourceReachesSink: a @RequestParam-annotated parameter is a source, so its value flowing
// into a SQL sink is a finding without any explicit source call.
func TestJavaAnnotationSourceReachesSink(t *testing.T) {
	p := jPos()
	params := []javaprogram.Parameter{{Name: "id", Kind: javaprogram.ParameterPositional, ValueID: "v-id", Pos: p,
		Annotations: []javaprogram.Reference{{Kind: javaprogram.ReferenceName, Segments: []string{"RequestParam"}}}}}
	values := []javaprogram.Value{
		{ID: "v-id", ScopeID: jHandID(), Kind: javaprogram.ValueParameter, Name: "id", Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"id"}}, Pos: p},
		{ID: "v-arg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"id"}}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{{FromID: "v-id", ToID: "v-arg", Kind: javaprogram.FlowExpression, Pos: p}}
	calls := []javaprogram.Call{{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"stmt", "executeQuery"}},
		Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"id"}}, ValueID: "v-arg", Pos: p}}, Pos: p}}
	got := javaRules(t, javaSkeleton(params, values, flows, calls, nil))
	if !got["java-taint-sql-statement"] {
		t.Errorf("an @RequestParam param flowing into executeQuery must be a SQL finding; got %v", got)
	}
}

// TestJavaCanonicalPathIsNotASanitizer: getCanonicalPath()/normalize() canonicalize a path but do NOT
// confine it to a base directory, so a tainted path routed through them is STILL a traversal finding. This
// pins the sound choice to model no path sanitizer (a canonicalizer sanitizer would hide a real traversal).
func TestJavaCanonicalPathIsNotASanitizer(t *testing.T) {
	p := jPos()
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-clean", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-arg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"c"}}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{
		{FromID: "v-src", ToID: "v-clean", Kind: javaprogram.FlowExpression, Pos: p},
		{FromID: "v-clean", ToID: "v-arg", Kind: javaprogram.FlowAssignment, Pos: p},
	}
	calls := []javaprogram.Call{
		{ID: "c-src", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: p},
		{ID: "c-clean", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"f", "getCanonicalPath"}}, ResultID: "v-clean",
			Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, ValueID: "v-src", Pos: p}}, Pos: p},
		{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"File"}}, New: true,
			Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"c"}}, ValueID: "v-arg", Pos: p}}, Pos: p},
	}
	imports := []javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "java.io.File", Name: "File", Pos: p}}
	got := javaRules(t, javaSkeleton(nil, values, flows, calls, imports))
	if !got["java-taint-path-file"] {
		t.Errorf("getCanonicalPath does NOT confine to a base dir, so the traversal must STILL flag; got %v", got)
	}
}

// TestJavaNoFalsePositive: a benign flow (no source, or source into an unmodeled call) yields nothing.
func TestJavaNoFalsePositive(t *testing.T) {
	// A trusted literal (no source call) flowing into executeQuery must not flag.
	p := jPos()
	values := []javaprogram.Value{
		{ID: "v-lit", ScopeID: jHandID(), Kind: javaprogram.ValueLiteral, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}, Pos: p},
		{ID: "v-arg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"q"}}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{{FromID: "v-lit", ToID: "v-arg", Kind: javaprogram.FlowAssignment, Pos: p}}
	calls := []javaprogram.Call{{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"stmt", "executeQuery"}},
		Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"q"}}, ValueID: "v-arg", Pos: p}}, Pos: p}}
	if got := javaRules(t, javaSkeleton(nil, values, flows, calls, nil)); len(got) != 0 {
		t.Errorf("a constant query must not flag; got %v", got)
	}
}
