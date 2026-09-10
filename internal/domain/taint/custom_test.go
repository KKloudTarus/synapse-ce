package taint

import (
	"errors"
	"testing"

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
