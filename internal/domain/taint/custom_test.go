package taint

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validCustom() CustomRules {
	return CustomRules{Python: CustomPythonRules{
		Sources: []CustomSource{{Modules: []string{"myframework"}, Names: []string{"read_body"}}},
		Sinks:   []CustomSink{{Modules: []string{"myorm"}, Names: []string{"raw_query"}, Class: "sql", CWE: "CWE-89", Rule: "myorm-sqli", Argument: 0}},
	}}
}

func TestCustomRulesValidate(t *testing.T) {
	if err := validCustom().Validate(); err != nil {
		t.Fatalf("valid rules must pass: %v", err)
	}
	// Unknown class is rejected.
	bad := validCustom()
	bad.Python.Sinks[0].Class = "not-a-class"
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown class must fail validation, got %v", err)
	}
	// Missing modules/names is rejected.
	bad2 := validCustom()
	bad2.Python.Sinks[0].Modules = nil
	if err := bad2.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing modules must fail validation")
	}
	// Bad CWE is rejected.
	bad3 := validCustom()
	bad3.Python.Sinks[0].CWE = "89"
	if err := bad3.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-CWE cwe must fail validation")
	}
	// Over the cap is rejected.
	big := CustomRules{}
	for i := 0; i < maxCustomTaintRules+1; i++ {
		big.Python.Sinks = append(big.Python.Sinks, CustomSink{Modules: []string{"m"}, Names: []string{"n"}, Class: "sql", CWE: "CWE-89", Rule: "r"})
	}
	if err := big.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("over-cap ruleset must fail validation")
	}
}

// The merge is additive: built-in sinks/sources/sanitizers are preserved and the custom ones are appended
// and matchable.
func TestWithCustomPythonIsAdditive(t *testing.T) {
	base := DefaultPythonCatalog()
	baseSinks, baseSources, baseSanitizers := len(base.Sinks), len(base.Sources), len(base.Sanitizers)

	merged := base.WithCustomPython(validCustom().Python)
	if len(merged.Sinks) != baseSinks+1 || len(merged.Sources) != baseSources+1 {
		t.Fatalf("merge must append exactly the custom entries: sinks %d->%d sources %d->%d", baseSinks, len(merged.Sinks), baseSources, len(merged.Sources))
	}
	if len(merged.Sanitizers) != baseSanitizers {
		t.Errorf("custom rules must not touch sanitizers (no suppression), got %d", len(merged.Sanitizers))
	}
	// A built-in sink still matches.
	if !anySink(merged, "python:subprocess:run", TaintCommand) {
		t.Error("a built-in sink must survive the merge")
	}
	// The custom sink matches.
	if !anySink(merged, "python:myorm:raw_query", TaintSQL) {
		t.Error("the custom sink must be modeled after the merge")
	}
}

func anySink(c PythonCatalog, callee string, class TaintClass) bool {
	for _, s := range c.Sinks {
		if s.Class == class && callMatches(s.Pattern, []string{callee}, "") {
			return true
		}
	}
	return false
}

// A custom sink fires end to end: a request parameter reaching a user-declared myorm.raw_query is a
// finding under the merged catalog, proving custom rules are not merely parsed but actually detect.
func TestCustomSinkFiresEndToEnd(t *testing.T) {
	catalog := DefaultPythonCatalog().WithCustomPython(CustomPythonRules{
		Sinks: []CustomSink{{Modules: []string{"myorm"}, Names: []string{"raw_query"}, Class: "sql", CWE: "CWE-89", Rule: "myorm-sqli", Argument: 0}},
	})
	doc := customSinkDocument()
	resolution, err := pythonprogram.Resolve(doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	graph, err := BuildPythonValueGraph(doc, resolution, catalog)
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	if _, found := pythonFindingFor(graph.Vulnerabilities(), TaintSQL, "myorm-sqli"); !found {
		t.Fatalf("the custom sink must produce a finding, got %+v", graph.Vulnerabilities())
	}
}

func customSinkDocument() pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	route.Parameters = []pythonprogram.Parameter{{Name: "request", Kind: pythonprogram.ParameterPositional, ValueID: "request", Pos: pyPos(2, 10)}}
	document.Symbols = append(document.Symbols, route)
	document.Imports = []pythonprogram.Import{{ScopeID: moduleID, Module: "myorm", Pos: pyPos(1, 0)}}
	document.Values = []pythonprogram.Value{
		pyValue("request", route.ID, pythonprogram.ValueParameter, "request", pyName("request"), 2, 10),
		pyValue("request-use", route.ID, pythonprogram.ValueReference, "", pyName("request"), 3, 20),
		pyValue("q-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("myorm", "raw_query"), 3, 4),
	}
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: route.ID, Callee: pyAttr("myorm", "raw_query"), Arguments: []pythonprogram.Argument{{Value: pyName("request"), ValueID: "request-use", Pos: pyPos(3, 20)}}, ResultID: "q-result", Pos: pyPos(3, 4)},
	}
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

// TestWithCustomJsIsAdditive: a custom JS source and sink are appended to the built-in catalog, and no
// sanitizer is added (custom rules can never suppress).
func TestWithCustomJsIsAdditive(t *testing.T) {
	base := DefaultJsCatalog()
	baseSinks, baseSources, baseSan := len(base.Sinks), len(base.Sources), len(base.Sanitizers)
	merged := base.WithCustomJs(CustomJsRules{
		Sources: []CustomSource{{Modules: []string{"myframework"}, Names: []string{"readBody"}}},
		Sinks:   []CustomSink{{Modules: []string{"myorm"}, Names: []string{"rawQuery"}, Class: "sql", CWE: "CWE-89", Rule: "myorm-js-sqli", Argument: 0}},
	})
	if len(merged.Sinks) != baseSinks+1 || len(merged.Sources) != baseSources+1 {
		t.Fatalf("merge must append exactly the custom entries: sinks %d->%d sources %d->%d", baseSinks, len(merged.Sinks), baseSources, len(merged.Sources))
	}
	if len(merged.Sanitizers) != baseSan {
		t.Errorf("custom rules must not touch sanitizers (no suppression), got %d", len(merged.Sanitizers))
	}
}

// TestCustomJsSinkFiresEndToEnd: a request value reaching a user-declared myorm.rawQuery is a finding under
// the merged JS catalog, proving custom JS rules are not merely parsed but actually detect.
func TestCustomJsSinkFiresEndToEnd(t *testing.T) {
	scope := jsModuleID()
	src := jsReqSource("v-src", "req", "body", "q")
	catalog := DefaultJsCatalog().WithCustomJs(CustomJsRules{
		Sinks: []CustomSink{{Modules: []string{"myorm"}, Names: []string{"rawQuery"}, Class: "sql", CWE: "CWE-89", Rule: "myorm-js-sqli", Argument: 0}},
	})
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: scope, Kind: jsprogram.ImportDefault, Module: "myorm", Alias: "myorm", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"myorm", "rawQuery"}, src.Ref, src.ID)},
	)
	graph, err := BuildJsValueGraph(doc, catalog)
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	if !jsFindingRules(graph)["myorm-js-sqli"] {
		t.Fatalf("the custom JS sink must produce a finding, got %v", jsFindingRules(graph))
	}
}

// TestCustomRulesValidateJsRejectsBadRule: a JS custom sink with an unknown class is rejected, with the
// error naming the js side.
func TestCustomRulesValidateJsRejectsBadRule(t *testing.T) {
	bad := CustomRules{JS: CustomJsRules{
		Sinks: []CustomSink{{Modules: []string{"m"}, Names: []string{"n"}, Class: "not-a-class", CWE: "CWE-1", Rule: "r", Argument: 0}},
	}}
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an unknown JS taint class must be rejected, got %v", err)
	}
	valid := CustomRules{JS: CustomJsRules{
		Sinks: []CustomSink{{Modules: []string{"m"}, Names: []string{"n"}, Class: "code", CWE: "CWE-94", Rule: "r", Argument: 0}},
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a well-formed JS rule must validate, got %v", err)
	}
}

// TestWithCustomJavaIsAdditive: a custom Java source and sink are appended, and no sanitizer is added.
func TestWithCustomJavaIsAdditive(t *testing.T) {
	base := DefaultJavaCatalog()
	baseSinks, baseSources, baseSan := len(base.Sinks), len(base.Sources), len(base.Sanitizers)
	merged := base.WithCustomJava(CustomJavaRules{
		Sources: []CustomSource{{Modules: []string{"com.acme.web"}, Names: []string{"readUntrusted"}}},
		Sinks:   []CustomSink{{Modules: []string{"com.acme.orm"}, Names: []string{"rawQuery"}, Class: "sql", CWE: "CWE-89", Rule: "acme-java-sqli", Argument: 0}},
	})
	if len(merged.Sinks) != baseSinks+1 || len(merged.Sources) != baseSources+1 {
		t.Fatalf("merge must append exactly the custom entries: sinks %d->%d sources %d->%d", baseSinks, len(merged.Sinks), baseSources, len(merged.Sources))
	}
	if len(merged.Sanitizers) != baseSan {
		t.Errorf("custom rules must not touch sanitizers (no suppression), got %d", len(merged.Sanitizers))
	}
}

// TestCustomJavaSinkFiresEndToEnd: a request value reaching a user-declared, import-anchored com.acme.orm
// rawQuery is a finding under the merged Java catalog.
func TestCustomJavaSinkFiresEndToEnd(t *testing.T) {
	p := jPos()
	catalog := DefaultJavaCatalog().WithCustomJava(CustomJavaRules{
		Sinks: []CustomSink{{Modules: []string{"com.acme.orm.Db"}, Names: []string{"rawQuery"}, Class: "sql", CWE: "CWE-89", Rule: "acme-java-sqli", Argument: 0}},
	})
	values := []javaprogram.Value{
		{ID: "v-src", ScopeID: jHandID(), Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: p},
		{ID: "v-arg", ScopeID: jHandID(), Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"r"}}, Pos: p},
	}
	flows := []javaprogram.ValueFlow{{FromID: "v-src", ToID: "v-arg", Kind: javaprogram.FlowAssignment, Pos: p}}
	calls := []javaprogram.Call{
		{ID: "c-src", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: p},
		{ID: "c-sink", CallerID: jHandID(), Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"Db", "rawQuery"}},
			Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"r"}}, ValueID: "v-arg", Pos: p}}, Pos: p},
	}
	imports := []javaprogram.Import{{ScopeID: jModID(), Kind: javaprogram.ImportSingle, Module: "com.acme.orm.Db", Name: "Db", Pos: p}}
	g, err := BuildJavaValueGraph(javaSkeleton(nil, values, flows, calls, imports), catalog)
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	found := false
	for _, v := range g.Vulnerabilities() {
		if v.Rule == "acme-java-sqli" {
			found = true
		}
	}
	if !found {
		t.Fatal("the custom Java sink must produce a finding")
	}
}

func TestCustomRulesValidateJavaRejectsBadRule(t *testing.T) {
	bad := CustomRules{Java: CustomJavaRules{
		Sinks: []CustomSink{{Modules: []string{"m"}, Names: []string{"n"}, Class: "not-a-class", CWE: "CWE-1", Rule: "r", Argument: 0}},
	}}
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an unknown Java taint class must be rejected, got %v", err)
	}
	valid := CustomRules{Java: CustomJavaRules{
		Sinks: []CustomSink{{Modules: []string{"m"}, Names: []string{"n"}, Class: "sql", CWE: "CWE-89", Rule: "r", Argument: 0}},
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a well-formed Java rule must validate, got %v", err)
	}
}
