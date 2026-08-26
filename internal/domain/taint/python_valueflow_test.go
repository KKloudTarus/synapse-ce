package taint

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
)

func TestPythonValueFlowTracksArgumentsAndReturnsInterprocedurally(t *testing.T) {
	document := interproceduralPythonDocument()
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	findings := graph.Vulnerabilities()
	finding, ok := pythonFindingFor(findings, TaintCommand, "python-taint-command")
	if !ok {
		t.Fatalf("missing command flow: %+v", findings)
	}
	wantFrames := []string{"route#request", "route#request-use", "helper#value", "helper#value-use", "helper#return", "route#helper-result"}
	for _, frame := range wantFrames {
		if !containsValueFrame(finding.Path, frame) {
			t.Errorf("witness missing %q: %v", frame, finding.Path)
		}
	}
	if finding.CWE != "CWE-78" || finding.SinkPos.Line != 4 {
		t.Fatalf("finding metadata = %+v", finding)
	}
}

func TestPythonSanitizersAreClassSpecific(t *testing.T) {
	document := sanitizerPythonDocument()
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	findings := graph.Vulnerabilities()
	if _, ok := pythonFindingFor(findings, TaintCommand, "python-taint-command"); !ok {
		t.Fatalf("HTML escaping must not hide command injection: %+v", findings)
	}
	if _, ok := pythonFindingFor(findings, TaintXSS, "python-taint-xss"); ok {
		t.Fatalf("HTML escaping must stop XSS flow: %+v", findings)
	}
}

func TestPythonSinkArgumentModelsDoNotTaintParameterizedSQLText(t *testing.T) {
	document := sqlArgumentPythonDocument()
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	findings := graph.Vulnerabilities()
	count := 0
	for _, finding := range findings {
		if finding.Class == TaintSQL {
			count++
			if finding.CallID != "app.py:5:4" {
				t.Errorf("parameterized call was reported instead of raw query: %+v", finding)
			}
		}
	}
	if count != 1 {
		t.Fatalf("SQL findings = %d, want one raw-query flow (all: %+v)", count, findings)
	}
}

func TestPythonValueFlowDoesNotTreatSiblingCallsAsDataFlow(t *testing.T) {
	document := siblingCallsPythonDocument()
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if findings := graph.Vulnerabilities(); len(findings) != 0 {
		t.Fatalf("unused source and literal sink are sibling calls, not a value flow: %+v", findings)
	}
}

func TestPythonValueFlowIsDeterministic(t *testing.T) {
	document := interproceduralPythonDocument()
	resolution, _ := pythonprogram.Resolve(document)
	first, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for left, right := 0, len(document.Values)-1; left < right; left, right = left+1, right-1 {
		document.Values[left], document.Values[right] = document.Values[right], document.Values[left]
	}
	for left, right := 0, len(document.Calls)-1; left < right; left, right = left+1, right-1 {
		document.Calls[left], document.Calls[right] = document.Calls[right], document.Calls[left]
	}
	second, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(first.Vulnerabilities(), second.Vulnerabilities()) {
		t.Fatalf("value flow depends on fact order:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestPythonValueFlowBindsKeywordArgumentsAndTerminatesOnCycles(t *testing.T) {
	document := interproceduralPythonDocument()
	document.Calls[0].Arguments[0].Keyword = "value"
	// A recursive/fixpoint-shaped summary cycle must not spin or duplicate the sink witness.
	document.Flows = append(document.Flows, pythonprogram.ValueFlow{
		FromID: "helper#return", ToID: "helper#value", Kind: pythonprogram.FlowExpression, Pos: pyPos(11, 4),
	})
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range graph.Vulnerabilities() {
		if finding.Class == TaintCommand {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("keyword/cyclic flow produced %d command findings", count)
	}
}

func TestPythonSinkMatchesReorderedKeywordArgument(t *testing.T) {
	document := keywordSinkPythonDocument()
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pythonFindingFor(graph.Vulnerabilities(), TaintSSRF, "python-taint-ssrf"); !ok {
		t.Fatalf("reordered url= keyword did not reach SSRF sink: %+v", graph.Vulnerabilities())
	}
}

func TestPythonFrameworkRouteParameterIsSourceRegardlessOfName(t *testing.T) {
	document := interproceduralPythonDocument()
	document.Symbols[1].Parameters[0].Name = "user_id"
	document.Values[0].Name, document.Values[0].Ref = "user_id", pyName("user_id")
	document.Values[1].Ref = pyName("user_id")
	document.Calls[0].Arguments[0].Value = pyName("user_id")
	resolution, err := pythonprogram.Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildPythonValueGraph(document, resolution, DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pythonFindingFor(graph.Vulnerabilities(), TaintCommand, "python-taint-command"); !ok {
		t.Fatal("explicit Flask/Django/FastAPI route parameters must be treated as request sources")
	}
}

func interproceduralPythonDocument() pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	route.Parameters = []pythonprogram.Parameter{{Name: "request", Kind: pythonprogram.ParameterPositional, ValueID: "route#request", Pos: pyPos(2, 10)}}
	helper := pythonValueSymbol("python:app:helper", "helper", moduleID, pythonprogram.SymbolFunction, 10)
	helper.Parameters = []pythonprogram.Parameter{{Name: "value", Kind: pythonprogram.ParameterPositional, ValueID: "helper#value", Pos: pyPos(10, 11)}}
	document.Symbols = append(document.Symbols, route, helper)
	document.Imports = []pythonprogram.Import{{ScopeID: moduleID, Module: "os", Pos: pyPos(1, 0)}}
	document.Values = []pythonprogram.Value{
		pyValue("route#request", route.ID, pythonprogram.ValueParameter, "request", pyName("request"), 2, 10),
		pyValue("route#request-use", route.ID, pythonprogram.ValueReference, "", pyName("request"), 3, 11),
		pyValue("route#helper-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("helper"), 3, 4),
		pyValue("route#sink-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("os", "system"), 4, 4),
		pyValue("helper#value", helper.ID, pythonprogram.ValueParameter, "value", pyName("value"), 10, 11),
		pyValue("helper#value-use", helper.ID, pythonprogram.ValueReference, "", pyName("value"), 11, 11),
		pyValue("helper#return", helper.ID, pythonprogram.ValueReturn, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceUnknown}, 11, 4),
	}
	document.Flows = []pythonprogram.ValueFlow{{FromID: "helper#value-use", ToID: "helper#return", Kind: pythonprogram.FlowReturn, Pos: pyPos(11, 4)}}
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: route.ID, Callee: pyName("helper"), Arguments: []pythonprogram.Argument{{Value: pyName("request"), ValueID: "route#request-use", Pos: pyPos(3, 11)}}, ResultID: "route#helper-result", Pos: pyPos(3, 4)},
		{ID: "app.py:4:4", CallerID: route.ID, Callee: pyAttr("os", "system"), Arguments: []pythonprogram.Argument{{Value: pyCallRef("helper"), ValueID: "route#helper-result", Pos: pyPos(4, 14)}}, ResultID: "route#sink-result", Pos: pyPos(4, 4)},
	}
	document.Returns = []pythonprogram.Return{{ScopeID: helper.ID, Value: pyName("value"), ValueID: "helper#value-use", SlotID: "helper#return", Pos: pyPos(11, 4)}}
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

func sanitizerPythonDocument() pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	route.Parameters = []pythonprogram.Parameter{{Name: "request", Kind: pythonprogram.ParameterPositional, ValueID: "request", Pos: pyPos(2, 10)}}
	document.Symbols = append(document.Symbols, route)
	document.Imports = []pythonprogram.Import{
		{ScopeID: moduleID, Module: "html", Pos: pyPos(1, 0)},
		{ScopeID: moduleID, Module: "os", Pos: pyPos(1, 0)},
		{ScopeID: moduleID, Module: "flask", Name: "render_template_string", Pos: pyPos(1, 0)},
	}
	document.Values = []pythonprogram.Value{
		pyValue("request", route.ID, pythonprogram.ValueParameter, "request", pyName("request"), 2, 10),
		pyValue("request-use", route.ID, pythonprogram.ValueReference, "", pyName("request"), 3, 16),
		pyValue("escaped", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("html", "escape"), 3, 4),
		pyValue("command-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("os", "system"), 4, 4),
		pyValue("xss-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("render_template_string"), 5, 4),
	}
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: route.ID, Callee: pyAttr("html", "escape"), Arguments: []pythonprogram.Argument{{Value: pyName("request"), ValueID: "request-use", Pos: pyPos(3, 16)}}, ResultID: "escaped", Pos: pyPos(3, 4)},
		{ID: "app.py:4:4", CallerID: route.ID, Callee: pyAttr("os", "system"), Arguments: []pythonprogram.Argument{{Value: pyCallRef("html", "escape"), ValueID: "escaped", Pos: pyPos(4, 14)}}, ResultID: "command-result", Pos: pyPos(4, 4)},
		{ID: "app.py:5:4", CallerID: route.ID, Callee: pyName("render_template_string"), Arguments: []pythonprogram.Argument{{Value: pyCallRef("html", "escape"), ValueID: "escaped", Pos: pyPos(5, 27)}}, ResultID: "xss-result", Pos: pyPos(5, 4)},
	}
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

func sqlArgumentPythonDocument() pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	route.Parameters = []pythonprogram.Parameter{{Name: "request", Kind: pythonprogram.ParameterPositional, ValueID: "request", Pos: pyPos(2, 10)}}
	document.Symbols = append(document.Symbols, route)
	document.Imports = []pythonprogram.Import{{ScopeID: moduleID, Module: "sqlite3", Name: "Cursor", Pos: pyPos(1, 0)}}
	document.Values = []pythonprogram.Value{
		pyValue("request", route.ID, pythonprogram.ValueParameter, "request", pyName("request"), 2, 10),
		pyValue("request-use", route.ID, pythonprogram.ValueReference, "", pyName("request"), 4, 35),
		pyValue("query-literal", route.ID, pythonprogram.ValueLiteral, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, 4, 19),
		pyValue("parameterized-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("cursor", "execute"), 4, 4),
		pyValue("request-use-raw", route.ID, pythonprogram.ValueReference, "", pyName("request"), 5, 19),
		pyValue("raw-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("cursor", "execute"), 5, 4),
		pyValue("cursor", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("Cursor"), 3, 4),
	}
	document.Assignments = []pythonprogram.Assignment{{ScopeID: route.ID, Targets: []pythonprogram.Reference{pyName("cursor")}, Value: pyCallRef("Cursor"), ValueID: "cursor", Pos: pyPos(3, 4)}}
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: route.ID, Callee: pyName("Cursor"), ResultID: "cursor", Pos: pyPos(3, 4)},
		{ID: "app.py:4:4", CallerID: route.ID, Callee: pyAttr("cursor", "execute"), Arguments: []pythonprogram.Argument{
			{Value: pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, ValueID: "query-literal", Pos: pyPos(4, 19)},
			{Value: pyName("request"), ValueID: "request-use", Pos: pyPos(4, 35)},
		}, ResultID: "parameterized-result", Pos: pyPos(4, 4)},
		{ID: "app.py:5:4", CallerID: route.ID, Callee: pyAttr("cursor", "execute"), Arguments: []pythonprogram.Argument{{Value: pyName("request"), ValueID: "request-use-raw", Pos: pyPos(5, 19)}}, ResultID: "raw-result", Pos: pyPos(5, 4)},
	}
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

func siblingCallsPythonDocument() pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	document.Symbols = append(document.Symbols, route)
	document.Imports = []pythonprogram.Import{{ScopeID: moduleID, Module: "os", Pos: pyPos(1, 0)}}
	document.Values = []pythonprogram.Value{
		pyValue("source-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("request", "args", "get"), 3, 4),
		pyValue("literal", route.ID, pythonprogram.ValueLiteral, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, 4, 14),
		pyValue("sink-result", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("os", "system"), 4, 4),
	}
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: route.ID, Callee: pyAttr("request", "args", "get"), ResultID: "source-result", Pos: pyPos(3, 4)},
		{ID: "app.py:4:4", CallerID: route.ID, Callee: pyAttr("os", "system"), Arguments: []pythonprogram.Argument{{Value: pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, ValueID: "literal", Pos: pyPos(4, 14)}}, ResultID: "sink-result", Pos: pyPos(4, 4)},
	}
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

func keywordSinkPythonDocument() pythonprogram.Document {
	document, moduleID := basePythonValueDocument()
	route := pythonValueSymbol("python:app:route", "route", moduleID, pythonprogram.SymbolFunction, 2)
	document.Symbols = append(document.Symbols, route)
	document.Imports = []pythonprogram.Import{{ScopeID: moduleID, Module: "requests", Pos: pyPos(1, 0)}}
	document.Values = []pythonprogram.Value{
		pyValue("source", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("request", "args", "get"), 3, 4),
		pyValue("timeout", route.ID, pythonprogram.ValueLiteral, "", pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, 4, 25),
		pyValue("sink", route.ID, pythonprogram.ValueCallResult, "", pyCallRef("requests", "get"), 4, 4),
	}
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: route.ID, Callee: pyAttr("request", "args", "get"), ResultID: "source", Pos: pyPos(3, 4)},
		{ID: "app.py:4:4", CallerID: route.ID, Callee: pyAttr("requests", "get"), Arguments: []pythonprogram.Argument{
			{Keyword: "timeout", Value: pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}, ValueID: "timeout", Pos: pyPos(4, 25)},
			{Keyword: "url", Value: pyCallRef("request", "args", "get"), ValueID: "source", Pos: pyPos(4, 37)},
		}, ResultID: "sink", Pos: pyPos(4, 4)},
	}
	document.Entrypoints = []pythonprogram.EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}}
	return document
}

func basePythonValueDocument() (pythonprogram.Document, string) {
	moduleID := "python:app:<module>"
	return pythonprogram.Document{
		SchemaVersion: pythonprogram.SchemaVersion, FilesSeen: 1, FilesParsed: 1,
		Modules: []pythonprogram.Module{{Name: "app", File: "app.py", Pos: pyPos(1, 0)}},
		Symbols: []pythonprogram.Symbol{{ID: moduleID, Module: "app", QualifiedName: "<module>", Name: "app", Kind: pythonprogram.SymbolModule, Pos: pyPos(1, 0)}},
	}, moduleID
}

func pythonValueSymbol(id, name, parent string, kind pythonprogram.SymbolKind, line int) pythonprogram.Symbol {
	return pythonprogram.Symbol{ID: id, Module: "app", QualifiedName: name, Name: name, ParentID: parent, Kind: kind, Pos: pyPos(line, 0)}
}

func pyValue(id, scope string, kind pythonprogram.ValueKind, name string, ref pythonprogram.Reference, line, column int) pythonprogram.Value {
	return pythonprogram.Value{ID: id, ScopeID: scope, Kind: kind, Name: name, Ref: ref, Pos: pyPos(line, column)}
}

func pyPos(line, column int) pythonprogram.Position {
	return pythonprogram.Position{File: "app.py", Line: line, Column: column}
}

func pyName(name string) pythonprogram.Reference {
	return pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{name}}
}

func pyAttr(segments ...string) pythonprogram.Reference {
	return pythonprogram.Reference{Kind: pythonprogram.ReferenceAttribute, Segments: segments}
}

func pyCallRef(segments ...string) pythonprogram.Reference {
	return pythonprogram.Reference{Kind: pythonprogram.ReferenceCall, Segments: segments}
}

func pythonFindingFor(findings []PythonTaintPath, class TaintClass, rule string) (PythonTaintPath, bool) {
	for _, finding := range findings {
		if finding.Class == class && finding.Rule == rule {
			return finding, true
		}
	}
	return PythonTaintPath{}, false
}

func containsValueFrame(path []string, want string) bool {
	for _, frame := range path {
		if frame == want {
			return true
		}
	}
	return false
}
