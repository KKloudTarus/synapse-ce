package pyreach

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPythonSymbolSubjectRoundTripAndValidation(t *testing.T) {
	got, ok := SymbolSubject("pkg:pypi/requests@2.31.0", "requests.sessions.Session.request")
	if !ok {
		t.Fatal("valid Python symbol subject was rejected")
	}
	purl, symbol, ok := ParseSymbolSubject(got)
	if !ok || purl != "pkg:pypi/requests@2.31.0" || symbol != "requests.sessions.Session.request" {
		t.Fatalf("round trip = (%q,%q,%v)", purl, symbol, ok)
	}
	for _, invalid := range [][2]string{
		{"pkg:npm/requests@1", "requests.get"},
		{"pkg:pypi/requests", "requests.get"},
		{"pkg:pypi/requests@1", "requests.get()"},
		{"pkg:pypi/requests@1", "requests.*"},
		{"pkg:pypi/requests@1", " requests.get"},
	} {
		if subject, ok := SymbolSubject(invalid[0], invalid[1]); ok {
			t.Errorf("invalid subject accepted: %q", subject)
		}
	}
}

func TestFirstPartySymbolSubject(t *testing.T) {
	subject, ok := FirstPartySymbolSubject("main.py", "control_unreachable")
	if !ok || subject != "python:main:control_unreachable" {
		t.Fatalf("first-party Python subject = %q, %t", subject, ok)
	}
	for _, invalid := range [][2]string{
		{"../main.py", "target"}, {"main.txt", "target"}, {"main.py", "target()"}, {"main.py", ""},
	} {
		if subject, ok := FirstPartySymbolSubject(invalid[0], invalid[1]); ok {
			t.Fatalf("FirstPartySymbolSubject(%q, %q) accepted %q", invalid[0], invalid[1], subject)
		}
	}
}

func TestTier2AnalyzerProvesPositiveAndCompleteNegativeFromOneSnapshot(t *testing.T) {
	provider := &fakePythonFactsProvider{document: pythonTier2Fixture(false), available: true}
	analyzer, err := NewTier2Analyzer(provider)
	if err != nil {
		t.Fatal(err)
	}
	positive := mustPythonSubject(t, "requests.sessions.Session.request")
	negative := mustPythonSubject(t, "requests.sessions.safe")
	analysis, err := analyzer.Analyze(context.Background(), "/workspace", []string{positive, negative})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 2 || !analysis.Results[0].Reachable || analysis.Results[1].Reachable {
		t.Fatalf("analysis = %+v", analysis.Results)
	}
	if path := analysis.Results[0].Path; len(path) != 2 || path[1] != "python:requests:sessions.Session.request" {
		t.Fatalf("positive path = %v", path)
	}
	if _, err := analyzer.Analyze(context.Background(), "/workspace", []string{positive}); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("facts provider called %d times, want one immutable snapshot", provider.calls)
	}
}

func TestTier2AnswerabilityKeepsPartialPositiveAndDropsPartialNegative(t *testing.T) {
	provider := &fakePythonFactsProvider{document: pythonTier2Fixture(true), available: true}
	analyzer, _ := NewTier2Analyzer(provider)
	positive := mustPythonSubject(t, "Session.request") // uniquely placeable from the observed graph
	negative := mustPythonSubject(t, "requests.sessions.safe")
	subjects := []ports.ReachabilitySubject{
		{FindingID: shared.ID("positive"), Symbols: []string{positive}},
		{FindingID: shared.ID("negative"), Symbols: []string{negative}},
	}
	answerable, err := analyzer.answerableSubjects(context.Background(), "/workspace", subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(answerable) != 1 || answerable[0].FindingID != "positive" {
		t.Fatalf("answerable partial subjects = %+v", answerable)
	}
}

func TestTier2LiteralDispatchAllowsOnlyDisjointFirstPartyNegative(t *testing.T) {
	moduleID := "python:main:<module>"
	pos := func(line int) pythonprogram.Position { return pythonprogram.Position{File: "main.py", Line: line} }
	symbol := func(id, qualified string, line int) pythonprogram.Symbol {
		return pythonprogram.Symbol{ID: id, Module: "main", QualifiedName: qualified, Name: qualified, ParentID: moduleID, Kind: pythonprogram.SymbolFunction, Pos: pos(line)}
	}
	entry := symbol("python:main:entry", "entry", 3)
	positive := symbol("python:main:control_positive", "control_positive", 7)
	unreachable := symbol("python:main:control_unreachable", "control_unreachable", 10)
	dispatch := symbol("python:main:opaque_dispatch", "opaque_dispatch", 13)
	opaque := symbol("python:main:control_opaque", "control_opaque", 18)
	document := pythonprogram.Document{
		SchemaVersion: pythonprogram.SchemaVersion, FilesSeen: 1, FilesParsed: 1,
		Modules: []pythonprogram.Module{{Name: "main", File: "main.py", Pos: pos(1)}},
		Symbols: append([]pythonprogram.Symbol{{ID: moduleID, Module: "main", QualifiedName: "<module>", Name: "main", Kind: pythonprogram.SymbolModule, Pos: pos(1)}}, entry, positive, unreachable, dispatch, opaque),
		Calls: []pythonprogram.Call{
			{ID: "main.py:2:0", CallerID: moduleID, Callee: pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{"entry"}}, Pos: pos(2)},
			{ID: "main.py:4:4", CallerID: entry.ID, Callee: pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{"control_positive"}}, Pos: pos(4)},
			{ID: "main.py:5:4", CallerID: entry.ID, Callee: pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{"opaque_dispatch"}}, Pos: pos(5)},
			{ID: "main.py:15:8", CallerID: dispatch.ID, Callee: pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{"handler"}}, BoundedCallees: []pythonprogram.Reference{{Kind: pythonprogram.ReferenceName, Segments: []string{"control_opaque"}}}, Pos: pos(15)},
		},
	}
	analyzer, err := NewTier2Analyzer(&fakePythonFactsProvider{document: document, available: true})
	if err != nil {
		t.Fatal(err)
	}
	positiveSubject, _ := FirstPartySymbolSubject("main.py", "control_positive")
	unreachableSubject, _ := FirstPartySymbolSubject("main.py", "control_unreachable")
	opaqueSubject, _ := FirstPartySymbolSubject("main.py", "control_opaque")
	subjects := []ports.ReachabilitySubject{
		{FindingID: "positive", Symbols: []string{positiveSubject}},
		{FindingID: "unreachable", Symbols: []string{unreachableSubject}},
		{FindingID: "opaque", Symbols: []string{opaqueSubject}},
	}
	answerable, err := analyzer.AnswerableSubjects(context.Background(), "/workspace", subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(answerable) != 2 || answerable[0].FindingID != "positive" || answerable[1].FindingID != "unreachable" {
		t.Fatalf("answerable bounded-dispatch subjects = %+v", answerable)
	}
	analysis, err := analyzer.Analyze(context.Background(), "/workspace", []string{positiveSubject, unreachableSubject})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 2 || !analysis.Results[0].Reachable || analysis.Results[1].Reachable {
		t.Fatalf("bounded-dispatch analysis = %+v", analysis.Results)
	}
}

func TestTier2AnswerabilityRequiresEverySymbolForANegative(t *testing.T) {
	provider := &fakePythonFactsProvider{document: pythonTier2Fixture(false), available: true}
	analyzer, _ := NewTier2Analyzer(provider)
	answerable, err := analyzer.answerableSubjects(context.Background(), "/workspace", []ports.ReachabilitySubject{{
		FindingID: "finding", Symbols: []string{
			mustPythonSubject(t, "requests.sessions.safe"),
			mustPythonSubject(t, "unqualified_missing"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(answerable) != 0 {
		t.Fatalf("an unplaceable advisory symbol must prevent a negative: %+v", answerable)
	}
}

// TestTier2EveryUnboundedDynamicDispatchConstructForcesRaiseOnly is the hard-bar guard for Python: a
// symbol that the graph does not statically reach must NOT be answerable-as-negative when an unbounded
// dynamic-dispatch construct left a coverage gap, because it could reach the symbol out of view. The separate
// finite literal-map case is covered above and only permits a negative outside its candidate closure.
func TestTier2EveryUnboundedDynamicDispatchConstructForcesRaiseOnly(t *testing.T) {
	for _, gap := range []pythonprogram.GapKind{
		pythonprogram.GapDynamicAttribute,
		pythonprogram.GapDynamicImport,
		pythonprogram.GapDynamicExecution,
		pythonprogram.GapUnsupportedDecorator,
		pythonprogram.GapWildcardImport,
		pythonprogram.GapParseRecovery,
	} {
		t.Run(string(gap), func(t *testing.T) {
			document := pythonTier2Fixture(false)
			document.CoverageGaps = []pythonprogram.CoverageGap{{Kind: gap, SymbolID: "python:app.api:<module>", Detail: "x", Pos: pythonprogram.Position{File: "app/api.py", Line: 9}}}
			analyzer, _ := NewTier2Analyzer(&fakePythonFactsProvider{document: document, available: true})
			negative := mustPythonSubject(t, "requests.sessions.safe") // placeable, but never statically reached
			answerable, err := analyzer.answerableSubjects(context.Background(), "/workspace", []ports.ReachabilitySubject{
				{FindingID: "finding", Symbols: []string{negative}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(answerable) != 0 {
				t.Fatalf("gap %q must force raise-only (drop the negative), got answerable=%+v", gap, answerable)
			}
		})
	}
}

func TestTier2AnalyzerUnavailableIsNoCoverage(t *testing.T) {
	analyzer, _ := NewTier2Analyzer(&fakePythonFactsProvider{})
	if _, err := analyzer.Analyze(context.Background(), "/workspace", []string{mustPythonSubject(t, "requests.get")}); err == nil {
		t.Fatal("an unavailable sidecar must not become a negative")
	}
}

type fakePythonFactsProvider struct {
	document  pythonprogram.Document
	available bool
	err       error
	calls     int
}

func (p *fakePythonFactsProvider) PythonFacts(context.Context, string) (pythonprogram.Document, bool, error) {
	p.calls++
	return p.document, p.available, p.err
}

func pythonTier2Fixture(incomplete bool) pythonprogram.Document {
	moduleID := "python:app.api:<module>"
	routeID := "python:app.api:route"
	pos := func(line int) pythonprogram.Position { return pythonprogram.Position{File: "app/api.py", Line: line} }
	document := pythonprogram.Document{
		SchemaVersion: pythonprogram.SchemaVersion,
		FilesSeen:     1,
		FilesParsed:   1,
		Modules:       []pythonprogram.Module{{Name: "app.api", File: "app/api.py", Pos: pos(1)}},
		Symbols: []pythonprogram.Symbol{
			{ID: moduleID, Module: "app.api", QualifiedName: "<module>", Name: "api", Kind: pythonprogram.SymbolModule, Pos: pos(1)},
			{ID: routeID, Module: "app.api", QualifiedName: "route", Name: "route", ParentID: moduleID, Kind: pythonprogram.SymbolFunction, Pos: pos(4)},
		},
		Imports: []pythonprogram.Import{{ScopeID: moduleID, Module: "requests", Pos: pos(2)}},
		Calls: []pythonprogram.Call{{
			ID: "app/api.py:5:4", CallerID: routeID,
			Callee: pythonprogram.Reference{Kind: pythonprogram.ReferenceAttribute, Segments: []string{"requests", "sessions", "Session", "request"}}, Pos: pos(5),
		}},
		Entrypoints: []pythonprogram.EntrypointHint{{SymbolID: routeID, Kind: "framework_route", Pos: pos(4)}},
	}
	if incomplete {
		document.CoverageGaps = []pythonprogram.CoverageGap{{Kind: pythonprogram.GapDynamicExecution, SymbolID: moduleID, Detail: "dynamic_code", Pos: pos(8)}}
	}
	return document
}

func mustPythonSubject(t *testing.T, symbol string) string {
	t.Helper()
	subject, ok := SymbolSubject("pkg:pypi/requests@2.31.0", symbol)
	if !ok {
		t.Fatalf("invalid fixture symbol %q", symbol)
	}
	return subject
}

func TestTier2AnswerableSubjectsPreservesSafeCandidatesAndInput(t *testing.T) {
	positive := mustPythonSubject(t, "requests.sessions.Session.request")
	negative := mustPythonSubject(t, "requests.sessions.safe")
	unplaceable := mustPythonSubject(t, "unqualified_missing")
	subjects := []ports.ReachabilitySubject{
		{FindingID: "positive", Symbols: []string{positive}},
		{FindingID: "negative", Symbols: []string{negative}},
		{FindingID: "unplaceable", Symbols: []string{unplaceable}},
	}
	original := append([]ports.ReachabilitySubject(nil), subjects...)
	for index := range original {
		original[index].Symbols = append([]string(nil), subjects[index].Symbols...)
	}

	analyzer, err := NewTier2Analyzer(&fakePythonFactsProvider{document: pythonTier2Fixture(false), available: true})
	if err != nil {
		t.Fatal(err)
	}
	answerable, err := analyzer.AnswerableSubjects(context.Background(), "/workspace", subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(answerable) != 2 || answerable[0].FindingID != "positive" || answerable[1].FindingID != "negative" {
		t.Fatalf("answerable subjects = %+v", answerable)
	}
	for index := range subjects {
		if subjects[index].FindingID != original[index].FindingID || len(subjects[index].Symbols) != len(original[index].Symbols) || subjects[index].Symbols[0] != original[index].Symbols[0] {
			t.Fatalf("input mutated: got %+v want %+v", subjects, original)
		}
	}
}

func TestTier2AnswerableSubjectsDropsIncompleteNegativeAndPropagatesCancellation(t *testing.T) {
	negative := mustPythonSubject(t, "requests.sessions.safe")
	positive := mustPythonSubject(t, "requests.sessions.Session.request")
	analyzer, err := NewTier2Analyzer(&fakePythonFactsProvider{document: pythonTier2Fixture(true), available: true})
	if err != nil {
		t.Fatal(err)
	}
	answerable, err := analyzer.AnswerableSubjects(context.Background(), "/workspace", []ports.ReachabilitySubject{
		{FindingID: "negative", Symbols: []string{negative}},
		{FindingID: "positive", Symbols: []string{positive}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(answerable) != 1 || answerable[0].FindingID != "positive" {
		t.Fatalf("incomplete answerable subjects = %+v", answerable)
	}

	cancelled, err := NewTier2Analyzer(&fakePythonFactsProvider{err: context.Canceled})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cancelled.AnswerableSubjects(context.Background(), "/workspace", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}
