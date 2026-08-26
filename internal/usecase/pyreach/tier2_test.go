package pyreach

import (
	"context"
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
