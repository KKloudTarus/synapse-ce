package taint

import (
	"strconv"
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
		{"xpath-evaluate", []string{"xp", "evaluate"}, false,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "javax.xml.xpath.XPath", Name: "XPath", Pos: jPos()}},
			"java-taint-xpath-expression"},
		{"xpath-compile", []string{"xp", "compile"}, false,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportOnDemand, Module: "javax.xml.xpath", Name: "", Pos: jPos()}},
			"java-taint-xpath-expression"},
		{"xss-writer-println", []string{"writer", "println"}, false,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "javax.servlet.http.HttpServletResponse", Name: "HttpServletResponse", Pos: jPos()}},
			"java-taint-xss-writer"},
		{"xss-writer-jakarta", []string{"writer", "write"}, false,
			[]javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportOnDemand, Module: "jakarta.servlet.http", Name: "", Pos: jPos()}},
			"java-taint-xss-writer"},
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

func TestJavaStrongUpdateConstantOverwriteSuppressesLaterSink(t *testing.T) {
	doc := javaStrongUpdateDoc(false, false)
	if paths := javaTaintPaths(t, doc); len(paths) != 0 {
		t.Fatalf("a definite constant overwrite must clear the later sink, got %#v", paths)
	}
}

func TestJavaConditionalOverwriteRetainsEarlierDefinitionAtJoin(t *testing.T) {
	doc := javaStrongUpdateDoc(true, false)
	paths := javaTaintPaths(t, doc)
	if !javaPathAtCall(paths, "c-late") {
		t.Fatalf("a conditional overwrite must retain the tainted definition at the join, got %#v", paths)
	}
}

func TestJavaStrongUpdatePreservesSinkBeforeOverwrite(t *testing.T) {
	doc := javaStrongUpdateDoc(false, true)
	paths := javaTaintPaths(t, doc)
	if !javaPathAtCall(paths, "c-early") {
		t.Fatalf("the sink before the overwrite must remain tainted, got %#v", paths)
	}
	if javaPathAtCall(paths, "c-late") {
		t.Fatalf("the definite overwrite must clear only the later sink, got %#v", paths)
	}
}

func javaStrongUpdateDoc(conditional, earlySink bool) javaprogram.Document {
	pos := func(line, column int) javaprogram.Position {
		return javaprogram.Position{File: javaTestFile, Line: line, Column: column}
	}
	ref := func(name string) javaprogram.Reference {
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{name}}
	}
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: pos(2, 9)},
		{ID: "v-tainted", ScopeID: jHandID(), Kind: javaprogram.ValueBinding, Name: "name", Ref: ref("name"), Pos: pos(2, 2)},
		{ID: "v-constant", ScopeID: jHandID(), Kind: javaprogram.ValueLiteral, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}, Pos: pos(3, 9)},
		{ID: "v-clean", ScopeID: jHandID(), Kind: javaprogram.ValueBinding, Name: "name", Ref: ref("name"), Pos: pos(3, 2)},
		{ID: "v-late", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: ref("name"), Pos: pos(4, 16)},
	}
	flows := []javaprogram.ValueFlow{
		{FromID: "v-src", ToID: "v-tainted", Kind: javaprogram.FlowAssignment, Pos: pos(2, 2)},
		{FromID: "v-constant", ToID: "v-clean", Kind: javaprogram.FlowAssignment, Pos: pos(3, 2)},
	}
	assignments := []javaprogram.Assignment{
		{ScopeID: jHandID(), Targets: []javaprogram.Reference{ref("name")}, TargetIDs: []string{"v-tainted"}, Value: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, ValueID: "v-src", Pos: pos(2, 2)},
		{ScopeID: jHandID(), Targets: []javaprogram.Reference{ref("name")}, TargetIDs: []string{"v-clean"}, Value: javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}, ValueID: "v-constant", StrongUpdate: !conditional, Pos: pos(3, 2)},
	}
	calls := []javaprogram.Call{
		{ID: "c-src", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: pos(2, 9)},
		{ID: "c-late", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"writer", "println"}}, Arguments: []javaprogram.Argument{{Value: ref("name"), ValueID: "v-late", Pos: pos(4, 16)}}, Pos: pos(4, 9)},
	}
	if earlySink {
		values = append(values, javaprogram.Value{ID: "v-early", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: ref("name"), Pos: pos(2, 30)})
		calls = append(calls, javaprogram.Call{ID: "c-early", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"writer", "println"}}, Arguments: []javaprogram.Argument{{Value: ref("name"), ValueID: "v-early", Pos: pos(2, 30)}}, Pos: pos(2, 23)})
	}
	imports := []javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "javax.servlet.http.HttpServletResponse", Name: "HttpServletResponse", Pos: jPos()}}
	doc := javaSkeleton(nil, values, flows, calls, imports)
	doc.Assignments = assignments
	return doc
}

func javaTaintPaths(t *testing.T, doc javaprogram.Document) []JavaTaintPath {
	t.Helper()
	graph, err := BuildJavaValueGraph(doc, DefaultJavaCatalog())
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	return graph.Vulnerabilities()
}

func javaPathAtCall(paths []JavaTaintPath, callID string) bool {
	for _, path := range paths {
		if path.CallID == callID {
			return true
		}
	}
	return false
}

// javaTaintSinkDoc models `<sink>(a0, a1, ...)` where the request source, optionally routed through a
// single-call sanitizer, reaches argument taintArg; the other arguments are constants. It is the rig for the
// LDAP filter battery (taintArg 1) and the class-specific check (a command sink at taintArg 0).
func javaTaintSinkDoc(sinkCallee []string, sinkArgCount, taintArg int, sanCallee []string, imports []javaprogram.Import) javaprogram.Document {
	p := jPos()
	ref := func(name string) javaprogram.Reference {
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{name}}
	}
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{}
	calls := []javaprogram.Call{
		{ID: "c-src", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: p},
	}
	taintFrom := "v-src"
	if len(sanCallee) > 0 {
		values = append(values,
			javaprogram.Value{ID: "v-sanarg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: ref("t"), Pos: p},
			javaprogram.Value{ID: "v-san", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		)
		flows = append(flows, javaprogram.ValueFlow{FromID: "v-src", ToID: "v-sanarg", Kind: javaprogram.FlowAssignment, Pos: p})
		sanKind := javaprogram.ReferenceAttribute
		if len(sanCallee) == 1 {
			sanKind = javaprogram.ReferenceName
		}
		calls = append(calls, javaprogram.Call{ID: "c-san", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: sanKind, Segments: sanCallee}, ResultID: "v-san",
			Arguments: []javaprogram.Argument{{Value: ref("t"), ValueID: "v-sanarg", Pos: p}}, Pos: p})
		taintFrom = "v-san"
	}
	var args []javaprogram.Argument
	for i := 0; i < sinkArgCount; i++ {
		if i == taintArg {
			values = append(values, javaprogram.Value{ID: "v-arg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: ref("a"), Pos: p})
			flows = append(flows, javaprogram.ValueFlow{FromID: taintFrom, ToID: "v-arg", Kind: javaprogram.FlowAssignment, Pos: p})
			args = append(args, javaprogram.Argument{Value: ref("a"), ValueID: "v-arg", Pos: p})
			continue
		}
		id := "v-const" + strconv.Itoa(i)
		values = append(values, javaprogram.Value{ID: id, ScopeID: jHandID(), Kind: javaprogram.ValueLiteral, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}, Pos: p})
		args = append(args, javaprogram.Argument{Value: javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}, ValueID: id, Pos: p})
	}
	sinkKind := javaprogram.ReferenceAttribute
	if len(sinkCallee) == 1 {
		sinkKind = javaprogram.ReferenceName
	}
	calls = append(calls, javaprogram.Call{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: sinkKind, Segments: sinkCallee}, Arguments: args, Pos: p})
	return javaSkeleton(nil, values, flows, calls, imports)
}

func namingImport(kind javaprogram.ImportKind, module, name string) []javaprogram.Import {
	return []javaprogram.Import{{ScopeID: jModID(), Kind: kind, Module: module, Name: name, Pos: jPos()}}
}

// TestJavaImportGatedSinksRequireAnchoringImport: LDAP .search (filter arg 1) / XPath .evaluate are
// receiver-name floors gated on the anchoring API's import. Without that import the method name is too
// generic to be a sink and must NOT flag; with it (single or on-demand wildcard) it must.
func TestJavaImportGatedSinksRequireAnchoringImport(t *testing.T) {
	cases := []struct {
		name    string
		sink    []string
		argN    int
		taint   int
		imports []javaprogram.Import
		rule    string
		want    bool
	}{
		{"ldap-with-import", []string{"ctx", "search"}, 2, 1, namingImport(javaprogram.ImportSingle, "javax.naming.directory.DirContext", "DirContext"), "java-taint-ldap-search", true},
		{"ldap-with-wildcard-import", []string{"ctx", "search"}, 2, 1, namingImport(javaprogram.ImportOnDemand, "javax.naming.directory", ""), "java-taint-ldap-search", true},
		{"ldap-no-import", []string{"ctx", "search"}, 2, 1, nil, "java-taint-ldap-search", false},
		{"ldap-unrelated-import", []string{"ctx", "search"}, 2, 1, namingImport(javaprogram.ImportSingle, "java.util.List", "List"), "java-taint-ldap-search", false},
		{"xpath-with-wildcard-import", []string{"xp", "evaluate"}, 1, 0, namingImport(javaprogram.ImportOnDemand, "javax.xml.xpath", ""), "java-taint-xpath-expression", true},
		{"xpath-no-import", []string{"xp", "evaluate"}, 1, 0, nil, "java-taint-xpath-expression", false},
		{"xss-with-servlet-import", []string{"writer", "println"}, 1, 0, namingImport(javaprogram.ImportSingle, "javax.servlet.http.HttpServletResponse", "HttpServletResponse"), "java-taint-xss-writer", true},
		{"xss-no-import", []string{"writer", "println"}, 1, 0, nil, "java-taint-xss-writer", false},
		{"xss-non-servlet-println-not-flagged", []string{"System", "out", "println"}, 1, 0, namingImport(javaprogram.ImportSingle, "java.util.List", "List"), "java-taint-xss-writer", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := javaRules(t, javaTaintSinkDoc(tc.sink, tc.argN, tc.taint, nil, tc.imports))
			if got[tc.rule] != tc.want {
				t.Errorf("%s: rule %q present=%v, want %v (got %v)", tc.name, tc.rule, got[tc.rule], tc.want, got)
			}
		})
	}
}

// TestJavaLdapEncoderSanitizer exercises the one modeled Java sanitizer (OWASP Encode.forLdap) on the LDAP
// filter argument across positive, wrong-context, class-specific, bypass, import-absent, and partial cases.
// It is import-anchored and clears ONLY CWE-90 on the value it returns.
func TestJavaLdapEncoderSanitizer(t *testing.T) {
	encAndNaming := []javaprogram.Import{
		{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "org.owasp.encoder.Encode", Name: "Encode", Pos: jPos()},
		{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "javax.naming.directory.DirContext", Name: "DirContext", Pos: jPos()},
	}
	namingOnly := []javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "javax.naming.directory.DirContext", Name: "DirContext", Pos: jPos()}}
	cases := []struct {
		name    string
		san     []string
		sink    []string
		argN    int
		taint   int
		imports []javaprogram.Import
		rule    string
		want    bool
	}{
		// positive: the filter is escaped by its exact escaper, so the search is not an LDAP finding.
		{"forLdap-sanitizes-filter", []string{"Encode", "forLdap"}, []string{"ctx", "search"}, 2, 1, encAndNaming, "java-taint-ldap-search", false},
		// wrong context: forDn escapes DN, not filter, metacharacters, so it is not a filter sanitizer and the
		// filter injection still flags. This is exactly the conflation the model refuses to make.
		{"forDn-does-not-sanitize-filter", []string{"Encode", "forDn"}, []string{"ctx", "search"}, 2, 1, encAndNaming, "java-taint-ldap-search", true},
		// class-specific: forLdap does NOT sanitize command injection, so a command sink still flags.
		{"forLdap-does-not-sanitize-command", []string{"Encode", "forLdap"}, []string{"rt", "exec"}, 1, 0, encAndNaming, "java-taint-command-exec", true},
		// bypass: forHtml is the wrong encoder and is not modeled as a sanitizer, so the flow still flags.
		{"forHtml-does-not-sanitize-filter", []string{"Encode", "forHtml"}, []string{"ctx", "search"}, 2, 1, encAndNaming, "java-taint-ldap-search", true},
		// import-absent: without the org.owasp.encoder.Encode import, forLdap does not resolve to the modeled
		// escaper (a same-named local method never counts), so the flow stays flagged.
		{"forLdap-unanchored-does-not-sanitize", []string{"Encode", "forLdap"}, []string{"ctx", "search"}, 2, 1, namingOnly, "java-taint-ldap-search", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := javaRules(t, javaTaintSinkDoc(tc.sink, tc.argN, tc.taint, tc.san, tc.imports))
			if got[tc.rule] != tc.want {
				t.Errorf("%s: rule %q present=%v, want %v (got %v)", tc.name, tc.rule, got[tc.rule], tc.want, got)
			}
		})
	}
}

// TestJavaLdapFilterPartialSanitizationFlags: a filter built from an escaped part AND a raw part is still
// injectable through the raw part, so it must flag. The filter value is fed by both the Encode.forLdap result
// and the raw source (a concatenation), and the raw path reaches the sink.
func TestJavaLdapFilterPartialSanitizationFlags(t *testing.T) {
	p := jPos()
	ref := func(name string) javaprogram.Reference {
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{name}}
	}
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-sanarg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: ref("t"), Pos: p},
		{ID: "v-san", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-filter", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: ref("filter"), Pos: p},
		{ID: "v-base", ScopeID: jHandID(), Kind: javaprogram.ValueLiteral, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{
		{FromID: "v-src", ToID: "v-sanarg", Kind: javaprogram.FlowAssignment, Pos: p},
		{FromID: "v-san", ToID: "v-filter", Kind: javaprogram.FlowExpression, Pos: p}, // escaped part
		{FromID: "v-src", ToID: "v-filter", Kind: javaprogram.FlowExpression, Pos: p}, // raw part (concatenation)
	}
	calls := []javaprogram.Call{
		{ID: "c-src", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: p},
		{ID: "c-san", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"Encode", "forLdap"}}, ResultID: "v-san",
			Arguments: []javaprogram.Argument{{Value: ref("t"), ValueID: "v-sanarg", Pos: p}}, Pos: p},
		{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"ctx", "search"}},
			Arguments: []javaprogram.Argument{
				{Value: ref("base"), ValueID: "v-base", Pos: p},
				{Value: ref("filter"), ValueID: "v-filter", Pos: p},
			}, Pos: p},
	}
	imports := []javaprogram.Import{
		{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "org.owasp.encoder.Encode", Name: "Encode", Pos: p},
		{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "javax.naming.directory.DirContext", Name: "DirContext", Pos: p},
	}
	got := javaRules(t, javaSkeleton(nil, values, flows, calls, imports))
	if !got["java-taint-ldap-search"] {
		t.Errorf("a filter with a raw (unescaped) part must still flag as LDAP injection; got %v", got)
	}
}

func TestJavaHTMLTextOutputProofSuppressesOnlyTheProvenXSSWrite(t *testing.T) {
	p := jPos()
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-arg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"name"}}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{{FromID: "v-src", ToID: "v-arg", Kind: javaprogram.FlowAssignment, Pos: p}}
	imports := []javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "javax.servlet.http.HttpServletResponse", Name: "HttpServletResponse", Pos: p}}
	base := []javaprogram.Call{
		{ID: "c-src", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: p},
		{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"writer", "println"}},
			Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"name"}}, ValueID: "v-arg", Pos: p}}, Pos: p},
	}
	withoutProof := javaRules(t, javaSkeleton(nil, values, flows, base, imports))
	if !withoutProof["java-taint-xss-writer"] {
		t.Fatalf("writer without proof must remain an XSS finding: %v", withoutProof)
	}
	withProof := append([]javaprogram.Call(nil), base...)
	withProof[1].OutputProof = javaprogram.OutputProofHTMLText
	if got := javaRules(t, javaSkeleton(nil, values, flows, withProof, imports)); got["java-taint-xss-writer"] {
		t.Fatalf("proven HTML-text writer remained an XSS finding: %v", got)
	}
	withProof[1].Callee = javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"rt", "exec"}}
	if got := javaRules(t, javaSkeleton(nil, values, flows, withProof, imports)); !got["java-taint-command-exec"] {
		t.Fatalf("HTML-text proof must not suppress a non-XSS sink: %v", got)
	}
}
