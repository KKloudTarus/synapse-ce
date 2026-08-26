package taintscan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

type fakePythonFacts struct {
	document  pythonprogram.Document
	available bool
	err       error
}

func (f *fakePythonFacts) PythonFacts(context.Context, string) (pythonprogram.Document, bool, error) {
	return f.document, f.available, f.err
}

func TestPythonScanProposesValueFlowWithBoundedEvidence(t *testing.T) {
	provider := &fakePythonFacts{document: pythonCommandDocument(), available: true}
	proposals, audit := &fakeProposer{}, &fakeAudit{}
	coordinator, err := NewPythonCoordinator(provider, proposals, taint.DefaultPythonCatalog(), audit, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := coordinator.Scan(context.Background(), engID, "/work/target")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 || len(proposals.calls) != 1 {
		t.Fatalf("python proposals = %d/%d, want one", n, len(proposals.calls))
	}
	proposal := proposals.calls[0]
	claim, ok := proposal.claim.(judgment.SASTClaim)
	if !ok {
		t.Fatalf("claim type = %T", proposal.claim)
	}
	if proposal.proposer != pythonProposerActor || proposal.capability != judgment.CapSAST || proposal.subjectKind != judgment.SubjectDataFlow {
		t.Fatalf("proposal lifecycle = %+v", proposal)
	}
	if claim.CWE != "CWE-78" || claim.Rule != "python-taint-command" || claim.Location != "app.py:4:4" {
		t.Fatalf("claim = %+v", claim)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "judgment.python_taint_proposed" {
		t.Fatalf("audit = %+v", audit.entries)
	}
	metadata := audit.entries[0].Metadata
	if metadata["coverage_complete"] != "false" || metadata["source_pos"] != "app.py:3:4" || metadata["sink_pos"] != "app.py:4:4" {
		t.Fatalf("coverage/positions = %+v", metadata)
	}
	if !strings.Contains(metadata["path"], "app.py:3:4") || !strings.Contains(metadata["path"], "app.py:4:4") {
		t.Fatalf("witness path = %q", metadata["path"])
	}
}

func TestPythonScanSanitizerProducesNoXSSProposal(t *testing.T) {
	document := pythonCommandDocument()
	document.Imports = []pythonprogram.Import{
		{ScopeID: "python:app:<module>", Module: "html", Pos: pyScanPos(1, 0)},
		{ScopeID: "python:app:<module>", Module: "flask", Name: "render_template_string", Pos: pyScanPos(1, 0)},
	}
	document.Values = []pythonprogram.Value{
		pyScanValue("source", pythonprogram.ValueCallResult, pyScanCallRef("request", "args", "get"), 3, 4),
		pyScanValue("escaped", pythonprogram.ValueCallResult, pyScanCallRef("html", "escape"), 4, 4),
		pyScanValue("sink", pythonprogram.ValueCallResult, pyScanCallRef("render_template_string"), 5, 4),
	}
	document.Calls = []pythonprogram.Call{
		{ID: "app.py:3:4", CallerID: "python:app:route", Callee: pyScanAttr("request", "args", "get"), ResultID: "source", Pos: pyScanPos(3, 4)},
		{ID: "app.py:4:4", CallerID: "python:app:route", Callee: pyScanAttr("html", "escape"), Arguments: []pythonprogram.Argument{{Value: pyScanCallRef("request", "args", "get"), ValueID: "source", Pos: pyScanPos(4, 16)}}, ResultID: "escaped", Pos: pyScanPos(4, 4)},
		{ID: "app.py:5:4", CallerID: "python:app:route", Callee: pyScanName("render_template_string"), Arguments: []pythonprogram.Argument{{Value: pyScanCallRef("html", "escape"), ValueID: "escaped", Pos: pyScanPos(5, 27)}}, ResultID: "sink", Pos: pyScanPos(5, 4)},
	}
	proposals := &fakeProposer{}
	coordinator, _ := NewPythonCoordinator(&fakePythonFacts{document: document, available: true}, proposals, taint.DefaultPythonCatalog(), &fakeAudit{}, fixedClock{})
	if n, err := coordinator.Scan(context.Background(), engID, "/work/target"); err != nil || n != 0 || len(proposals.calls) != 0 {
		t.Fatalf("sanitized XSS must stay clean, proposals=%d calls=%d err=%v", n, len(proposals.calls), err)
	}
}

func TestPythonScanNoCoverageProposesNothing(t *testing.T) {
	for _, provider := range []*fakePythonFacts{
		{available: false},
		{available: true, err: errors.New("parser failed")},
	} {
		proposals, audit := &fakeProposer{}, &fakeAudit{}
		coordinator, _ := NewPythonCoordinator(provider, proposals, taint.DefaultPythonCatalog(), audit, fixedClock{})
		if n, err := coordinator.Scan(context.Background(), engID, "/work/target"); err == nil || n != 0 || len(proposals.calls) != 0 || len(audit.entries) != 0 {
			t.Fatalf("no coverage must propose nothing: n=%d err=%v calls=%d audit=%d", n, err, len(proposals.calls), len(audit.entries))
		}
	}
}

func TestPythonTaintDeduplicatesPerSinkClassAndChoosesShortestPath(t *testing.T) {
	paths := []taint.PythonTaintPath{
		{CallID: "call", Class: taint.TaintSQL, Rule: "python-taint-sqli", SourceID: "b", Path: []string{"b", "x", "sink"}},
		{CallID: "call", Class: taint.TaintSQL, Rule: "python-taint-sqli", SourceID: "a", Path: []string{"a", "sink"}},
		{CallID: "call", Class: taint.TaintCommand, Rule: "python-taint-command", SourceID: "c", Path: []string{"c", "sink"}},
	}
	got := deduplicatePythonTaintPaths(paths)
	if len(got) != 2 {
		t.Fatalf("deduplicated paths = %+v", got)
	}
	for _, path := range got {
		if path.Class == taint.TaintSQL && path.SourceID != "a" {
			t.Fatalf("did not retain shortest SQL witness: %+v", path)
		}
	}
}

func TestPythonTaintSubjectIsStableAndTenantScoped(t *testing.T) {
	finding := taint.PythonTaintPath{CallID: "app.py:4:4", Class: taint.TaintCommand, Rule: "python-taint-command"}
	first := pythonFlowSubjectID("eng-1", finding)
	if first.IsZero() || first != pythonFlowSubjectID("eng-1", finding) || first == pythonFlowSubjectID("eng-2", finding) {
		t.Fatalf("subject stability/scope failed: %q", first)
	}
}

func TestNewPythonCoordinatorValidatesDependencies(t *testing.T) {
	provider, proposals, audit := &fakePythonFacts{}, &fakeProposer{}, &fakeAudit{}
	catalog := taint.DefaultPythonCatalog()
	if _, err := NewPythonCoordinator(nil, proposals, catalog, audit, fixedClock{}); err == nil {
		t.Error("nil provider must fail")
	}
	if _, err := NewPythonCoordinator(provider, nil, catalog, audit, fixedClock{}); err == nil {
		t.Error("nil proposer must fail")
	}
	if _, err := NewPythonCoordinator(provider, proposals, taint.PythonCatalog{}, audit, fixedClock{}); err == nil {
		t.Error("empty catalog must fail")
	}
}

func pythonCommandDocument() pythonprogram.Document {
	const module, route = "python:app:<module>", "python:app:route"
	return pythonprogram.Document{
		SchemaVersion: pythonprogram.SchemaVersion, FilesSeen: 1, FilesParsed: 1,
		Modules: []pythonprogram.Module{{Name: "app", File: "app.py", Pos: pyScanPos(1, 0)}},
		Symbols: []pythonprogram.Symbol{
			{ID: module, Module: "app", QualifiedName: "<module>", Name: "app", Kind: pythonprogram.SymbolModule, Pos: pyScanPos(1, 0)},
			{ID: route, Module: "app", QualifiedName: "route", Name: "route", ParentID: module, Kind: pythonprogram.SymbolFunction, Pos: pyScanPos(2, 0)},
		},
		Imports: []pythonprogram.Import{{ScopeID: module, Module: "os", Pos: pyScanPos(1, 0)}},
		Values: []pythonprogram.Value{
			pyScanValue("source", pythonprogram.ValueCallResult, pyScanCallRef("request", "args", "get"), 3, 4),
			pyScanValue("sink", pythonprogram.ValueCallResult, pyScanCallRef("os", "system"), 4, 4),
		},
		Calls: []pythonprogram.Call{
			{ID: "app.py:3:4", CallerID: route, Callee: pyScanAttr("request", "args", "get"), ResultID: "source", Pos: pyScanPos(3, 4)},
			{ID: "app.py:4:4", CallerID: route, Callee: pyScanAttr("os", "system"), Arguments: []pythonprogram.Argument{{Value: pyScanCallRef("request", "args", "get"), ValueID: "source", Pos: pyScanPos(4, 14)}}, ResultID: "sink", Pos: pyScanPos(4, 4)},
		},
		Entrypoints: []pythonprogram.EntrypointHint{{SymbolID: route, Kind: "framework_route", Pos: pyScanPos(2, 0)}},
	}
}

func pyScanValue(id string, kind pythonprogram.ValueKind, ref pythonprogram.Reference, line, column int) pythonprogram.Value {
	return pythonprogram.Value{ID: id, ScopeID: "python:app:route", Kind: kind, Ref: ref, Pos: pyScanPos(line, column)}
}

func pyScanPos(line, column int) pythonprogram.Position {
	return pythonprogram.Position{File: "app.py", Line: line, Column: column}
}

func pyScanName(name string) pythonprogram.Reference {
	return pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{name}}
}

func pyScanAttr(segments ...string) pythonprogram.Reference {
	return pythonprogram.Reference{Kind: pythonprogram.ReferenceAttribute, Segments: segments}
}

func pyScanCallRef(segments ...string) pythonprogram.Reference {
	return pythonprogram.Reference{Kind: pythonprogram.ReferenceCall, Segments: segments}
}
