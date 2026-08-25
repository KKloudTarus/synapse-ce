package pythonprogram

import (
	"reflect"
	"testing"
)

func TestResolveBuildsLocalImportedInheritedAndExternalEdges(t *testing.T) {
	document := resolverFixture()
	resolution, err := Resolve(document)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !resolution.Complete || len(resolution.Gaps) != 0 {
		t.Fatalf("resolution incomplete: %+v", resolution.Gaps)
	}
	caller := "python:app.api:route"
	for _, target := range []string{
		"python:app.service:save",
		"python:app.service:Child",
		"python:app.service:Base.run",
		"python:requests:get",
		"python:builtins:len",
	} {
		if !graphHasPythonEdge(resolution, caller, target) {
			t.Errorf("missing edge %s -> %s (graph: %+v)", caller, target, resolution.Graph.Edges)
		}
	}
	if path := resolution.Graph.PathTo("python:app.service:Base.run"); len(path) == 0 || path[len(path)-1] != "python:app.service:Base.run" {
		t.Errorf("inherited method path = %v", path)
	}
	if got := resolution.Graph.Positions["python:app.service:Base.run"]; got != "app/service.py:4" {
		t.Errorf("definition position = %q", got)
	}
	if callStatus(resolution, "app/api.py:9:4") != CallExternal {
		t.Errorf("requests.get must be classified external: %+v", resolution.Calls)
	}
}

func TestResolveModelsAmbiguityAndUnresolvedCallsAsCoverageGaps(t *testing.T) {
	document := minimalResolverDocument()
	moduleID := "python:app:<module>"
	classA := resolverSymbol("python:app:A", "app", "A", "A", moduleID, SymbolClass, 2)
	classB := resolverSymbol("python:app:B", "app", "B", "B", moduleID, SymbolClass, 5)
	classC := resolverSymbol("python:app:C", "app", "C", "C", moduleID, SymbolClass, 8)
	classC.Bases = []Reference{nameRef("A"), nameRef("B")}
	methodA := resolverSymbol("python:app:A.run", "app", "A.run", "run", classA.ID, SymbolMethod, 3)
	methodB := resolverSymbol("python:app:B.run", "app", "B.run", "run", classB.ID, SymbolMethod, 6)
	methodC := resolverSymbol("python:app:C.execute", "app", "C.execute", "execute", classC.ID, SymbolMethod, 9)
	document.Symbols = append(document.Symbols, classA, methodA, classB, methodB, classC, methodC)
	document.Calls = []Call{
		{ID: "app.py:10:4", CallerID: methodC.ID, Callee: attrRef("self", "run"), Pos: resolverPos("app.py", 10)},
		{ID: "app.py:11:4", CallerID: methodC.ID, Callee: nameRef("runtime_factory"), Pos: resolverPos("app.py", 11)},
	}
	document.Entrypoints = []EntrypointHint{{SymbolID: methodC.ID, Kind: "framework_route", Pos: methodC.Pos}}

	resolution, err := Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Complete {
		t.Fatal("ambiguous/unresolved calls must prevent a negative proof")
	}
	if status := callStatus(resolution, "app.py:10:4"); status != CallAmbiguous {
		t.Errorf("inherited call status = %q", status)
	}
	if status := callStatus(resolution, "app.py:11:4"); status != CallUnresolved {
		t.Errorf("unknown call status = %q", status)
	}
	for _, target := range []string{methodA.ID, methodB.ID} {
		if !graphHasPythonEdge(resolution, methodC.ID, target) {
			t.Errorf("ambiguous conservative target %q was dropped", target)
		}
	}
	if len(resolution.Gaps) != 2 {
		t.Fatalf("gaps = %+v", resolution.Gaps)
	}
}

func TestResolveIsDeterministicForUnsortedFacts(t *testing.T) {
	document := resolverFixture()
	first, err := Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	for left, right := 0, len(document.Symbols)-1; left < right; left, right = left+1, right-1 {
		document.Symbols[left], document.Symbols[right] = document.Symbols[right], document.Symbols[left]
	}
	for left, right := 0, len(document.Imports)-1; left < right; left, right = left+1, right-1 {
		document.Imports[left], document.Imports[right] = document.Imports[right], document.Imports[left]
	}
	for left, right := 0, len(document.Calls)-1; left < right; left, right = left+1, right-1 {
		document.Calls[left], document.Calls[right] = document.Calls[right], document.Calls[left]
	}
	second, err := Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("resolution depends on fact order:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestResolveRejectsInvalidFacts(t *testing.T) {
	document := minimalResolverDocument()
	document.Modules[0].File = "../app.py"
	if _, err := Resolve(document); err == nil {
		t.Fatal("resolver must validate facts even when called outside the provider")
	}
}

func TestResolveLexicalShadowingAndRecursion(t *testing.T) {
	document := minimalResolverDocument()
	moduleID := document.Symbols[0].ID
	run := resolverSymbol("python:app:run", "app", "run", "run", moduleID, SymbolFunction, 3)
	document.Symbols = append(document.Symbols, run)
	document.Imports = []Import{{ScopeID: moduleID, Module: "dependency", Name: "run", Pos: resolverPos("app.py", 1)}}
	document.Calls = []Call{{ID: "app.py:4:4", CallerID: run.ID, Callee: nameRef("run"), Pos: resolverPos("app.py", 4)}}

	resolution, err := Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.Complete || !graphHasPythonEdge(resolution, run.ID, run.ID) {
		t.Fatalf("recursive local shadow was not resolved: %+v", resolution)
	}
	if graphHasPythonEdge(resolution, run.ID, "python:dependency:run") {
		t.Fatal("an import shadowed by a lexical declaration must not remain a target")
	}
}

func TestResolvePropagatesExtractionCoverageAndExternalInheritance(t *testing.T) {
	document := minimalResolverDocument()
	moduleID := document.Symbols[0].ID
	view := resolverSymbol("python:app:View", "app", "View", "View", moduleID, SymbolClass, 3)
	view.Bases = []Reference{nameRef("ExternalView")}
	document.Symbols = append(document.Symbols, view)
	document.Imports = []Import{{ScopeID: moduleID, Module: "framework", Name: "ExternalView", Pos: resolverPos("app.py", 1)}}
	document.CoverageGaps = []CoverageGap{{Kind: GapDynamicExecution, SymbolID: moduleID, Detail: "dynamic_code", Pos: resolverPos("app.py", 5)}}

	resolution, err := Resolve(document)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Complete || !resolutionHasGap(resolution, GapDynamicExecution) || !resolutionHasGap(resolution, GapUnresolvedValue) {
		t.Fatalf("coverage gaps were lost: %+v", resolution.Gaps)
	}
}

func resolverFixture() Document {
	apiModule := "python:app.api:<module>"
	serviceModule := "python:app.service:<module>"
	route := resolverSymbol("python:app.api:route", "app.api", "route", "route", apiModule, SymbolFunction, 5)
	base := resolverSymbol("python:app.service:Base", "app.service", "Base", "Base", serviceModule, SymbolClass, 2)
	run := resolverSymbol("python:app.service:Base.run", "app.service", "Base.run", "run", base.ID, SymbolMethod, 4)
	child := resolverSymbol("python:app.service:Child", "app.service", "Child", "Child", serviceModule, SymbolClass, 7)
	child.Bases = []Reference{nameRef("Base")}
	save := resolverSymbol("python:app.service:save", "app.service", "save", "save", serviceModule, SymbolFunction, 10)
	document := Document{
		SchemaVersion: SchemaVersion,
		FilesSeen:     2,
		FilesParsed:   2,
		Modules: []Module{
			{Name: "app.api", File: "app/api.py", Pos: resolverPos("app/api.py", 1)},
			{Name: "app.service", File: "app/service.py", Pos: resolverPos("app/service.py", 1)},
		},
		Symbols: []Symbol{
			resolverSymbol(apiModule, "app.api", "<module>", "api", "", SymbolModule, 1),
			route,
			resolverSymbol(serviceModule, "app.service", "<module>", "service", "", SymbolModule, 1),
			base, run, child, save,
		},
		Imports: []Import{
			{ScopeID: apiModule, Module: "service", Name: "save", Level: 1, Pos: resolverPos("app/api.py", 1)},
			{ScopeID: apiModule, Module: "service", Name: "Child", Level: 1, Pos: resolverPos("app/api.py", 2)},
			{ScopeID: apiModule, Module: "requests", Pos: resolverPos("app/api.py", 3)},
		},
		Calls: []Call{
			{ID: "app/api.py:6:4", CallerID: route.ID, Callee: nameRef("save"), Pos: resolverPos("app/api.py", 6)},
			{ID: "app/api.py:7:10", CallerID: route.ID, Callee: nameRef("Child"), Pos: resolverPos("app/api.py", 7)},
			{ID: "app/api.py:8:4", CallerID: route.ID, Callee: attrRef("service", "run"), Pos: resolverPos("app/api.py", 8)},
			{ID: "app/api.py:9:4", CallerID: route.ID, Callee: attrRef("requests", "get"), Pos: resolverPos("app/api.py", 9)},
			{ID: "app/api.py:10:4", CallerID: route.ID, Callee: nameRef("len"), Pos: resolverPos("app/api.py", 10)},
		},
		Assignments: []Assignment{{
			ScopeID: route.ID, Targets: []Reference{nameRef("service")},
			Value: Reference{Kind: ReferenceCall, Segments: []string{"Child"}}, Pos: resolverPos("app/api.py", 7),
		}},
		Entrypoints: []EntrypointHint{{SymbolID: route.ID, Kind: "framework_route", Pos: route.Pos}},
	}
	return document
}

func minimalResolverDocument() Document {
	moduleID := "python:app:<module>"
	return Document{
		SchemaVersion: SchemaVersion,
		FilesSeen:     1,
		FilesParsed:   1,
		Modules:       []Module{{Name: "app", File: "app.py", Pos: resolverPos("app.py", 1)}},
		Symbols:       []Symbol{resolverSymbol(moduleID, "app", "<module>", "app", "", SymbolModule, 1)},
	}
}

func resolverSymbol(id, module, qualified, name, parent string, kind SymbolKind, line int) Symbol {
	file := "app.py"
	if module == "app.api" {
		file = "app/api.py"
	} else if module == "app.service" {
		file = "app/service.py"
	}
	return Symbol{ID: id, Module: module, QualifiedName: qualified, Name: name, ParentID: parent, Kind: kind, Pos: resolverPos(file, line)}
}

func resolverPos(file string, line int) Position { return Position{File: file, Line: line} }

func nameRef(name string) Reference { return Reference{Kind: ReferenceName, Segments: []string{name}} }

func attrRef(segments ...string) Reference {
	return Reference{Kind: ReferenceAttribute, Segments: segments}
}

func graphHasPythonEdge(resolution Resolution, caller, callee string) bool {
	for _, edge := range resolution.Graph.Edges {
		if edge.Caller != caller {
			continue
		}
		for _, target := range edge.Callees {
			if target == callee {
				return true
			}
		}
	}
	return false
}

func callStatus(resolution Resolution, callID string) CallResolutionStatus {
	for _, call := range resolution.Calls {
		if call.CallID == callID {
			return call.Status
		}
	}
	return ""
}

func resolutionHasGap(resolution Resolution, kind GapKind) bool {
	for _, gap := range resolution.Gaps {
		if gap.Kind == kind {
			return true
		}
	}
	return false
}
