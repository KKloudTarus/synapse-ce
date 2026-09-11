package taintscan

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeJavaFacts struct {
	document  javaprogram.Document
	available bool
	err       error
}

func (f *fakeJavaFacts) JavaFacts(context.Context, string) (javaprogram.Document, bool, error) {
	return f.document, f.available, f.err
}

// javaSQLDocument is a minimal, valid one-module document with a request.getParameter -> stmt.executeQuery
// SQL injection, used to exercise the coordinator's propose-only lifecycle end to end.
func javaSQLDocument() javaprogram.Document {
	const module, file = "app", "app.java"
	pos := javaprogram.Position{File: file, Line: 3, Column: 2}
	modID := javaprogram.CanonicalSymbolID(module, "<module>")
	clsID := javaprogram.CanonicalSymbolID(module, "App")
	mID := javaprogram.CanonicalSymbolID(module, "App.handle")
	return javaprogram.Document{
		SchemaVersion: javaprogram.SchemaVersion,
		Modules:       []javaprogram.Module{{Name: module, File: file, Pos: pos}},
		Symbols: []javaprogram.Symbol{
			{ID: modID, Module: module, QualifiedName: "<module>", Name: module, Kind: javaprogram.SymbolModule, Pos: pos},
			{ID: clsID, Module: module, QualifiedName: "App", Name: "App", ParentID: modID, Kind: javaprogram.SymbolClass, Pos: pos},
			{ID: mID, Module: module, QualifiedName: "App.handle", Name: "handle", ParentID: clsID, Kind: javaprogram.SymbolMethod, Pos: pos},
		},
		Values: []javaprogram.Value{
			{ID: "v-src", ScopeID: mID, Kind: javaprogram.ValueCallResult, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceExpression}, Pos: pos},
			{ID: "v-arg", ScopeID: mID, Kind: javaprogram.ValueReference, Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"q"}}, Pos: pos},
		},
		Flows: []javaprogram.ValueFlow{{FromID: "v-src", ToID: "v-arg", Kind: javaprogram.FlowAssignment, Pos: pos}},
		Calls: []javaprogram.Call{
			{ID: "c-src", CallerID: mID, Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"request", "getParameter"}}, ResultID: "v-src", Pos: pos},
			{ID: "c-sink", CallerID: mID, Callee: javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: []string{"stmt", "executeQuery"}},
				Arguments: []javaprogram.Argument{{Value: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"q"}}, ValueID: "v-arg", Pos: pos}}, Pos: pos},
		},
		// A gap keeps this document PARTIAL, as the real extractor would when it cannot type the receiver.
		CoverageGaps: []javaprogram.CoverageGap{{Kind: javaprogram.GapUnresolvedCall, SymbolID: mID, Detail: "receiver_type", Pos: pos}},
		FilesSeen:    1,
		FilesParsed:  1,
	}
}

func newJavaCoordinator(t *testing.T, provider *fakeJavaFacts, proposals *fakeProposer, audit *fakeAudit) *JavaCoordinator {
	t.Helper()
	c, err := NewJavaCoordinator(provider, proposals, taint.DefaultJavaCatalog(), audit, fixedClock{})
	if err != nil {
		t.Fatalf("NewJavaCoordinator: %v", err)
	}
	return c
}

func TestJavaScanProposesValueFlowWithWitness(t *testing.T) {
	proposals, audit := &fakeProposer{}, &fakeAudit{}
	c := newJavaCoordinator(t, &fakeJavaFacts{document: javaSQLDocument(), available: true}, proposals, audit)
	outcome, err := c.ScanWithCoverage(context.Background(), shared.ID("eng-1"), "/ws")
	if err != nil {
		t.Fatalf("ScanWithCoverage: %v", err)
	}
	if outcome.Proposed != 1 || len(proposals.calls) != 1 {
		t.Fatalf("want 1 proposal, got proposed=%d calls=%d", outcome.Proposed, len(proposals.calls))
	}
	if outcome.Coverage.Status != ports.AnalysisCoveragePartial || outcome.Coverage.Complete {
		t.Fatalf("want partial+incomplete coverage, got status=%q complete=%v", outcome.Coverage.Status, outcome.Coverage.Complete)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "judgment.java_taint_proposed" {
		t.Fatalf("want one java taint audit entry, got %+v", audit.entries)
	}
}

func TestJavaScanNoCoverageProposesNothing(t *testing.T) {
	for name, provider := range map[string]*fakeJavaFacts{
		"sidecar unavailable": {available: false},
		"extraction failed":   {err: errors.New("parser detail")},
	} {
		t.Run(name, func(t *testing.T) {
			proposals := &fakeProposer{}
			c := newJavaCoordinator(t, provider, proposals, &fakeAudit{})
			outcome, err := c.ScanWithCoverage(context.Background(), shared.ID("eng-1"), "/ws")
			if err == nil {
				t.Fatal("want a no-coverage error")
			}
			if outcome.Proposed != 0 || len(proposals.calls) != 0 {
				t.Fatalf("want zero proposals on no coverage, got %d", outcome.Proposed)
			}
		})
	}
}

func TestJavaScanEmptySourceIsNotApplicable(t *testing.T) {
	proposals := &fakeProposer{}
	c := newJavaCoordinator(t, &fakeJavaFacts{available: true, document: javaprogram.Document{SchemaVersion: javaprogram.SchemaVersion}}, proposals, &fakeAudit{})
	outcome, err := c.ScanWithCoverage(context.Background(), shared.ID("eng-1"), "/ws")
	if err != nil {
		t.Fatalf("ScanWithCoverage: %v", err)
	}
	if outcome.Proposed != 0 || outcome.Coverage.Status != ports.AnalysisCoverageNotApplicable {
		t.Fatalf("want not-applicable with zero proposals, got proposed=%d status=%q", outcome.Proposed, outcome.Coverage.Status)
	}
}

func TestNewJavaCoordinatorValidatesDependencies(t *testing.T) {
	provider, proposals, audit := &fakeJavaFacts{}, &fakeProposer{}, &fakeAudit{}
	if _, err := NewJavaCoordinator(nil, proposals, taint.DefaultJavaCatalog(), audit, fixedClock{}); err == nil {
		t.Error("nil provider must be rejected")
	}
	if _, err := NewJavaCoordinator(provider, nil, taint.DefaultJavaCatalog(), audit, fixedClock{}); err == nil {
		t.Error("nil proposer must be rejected")
	}
	if _, err := NewJavaCoordinator(provider, proposals, taint.JavaCatalog{}, audit, fixedClock{}); err == nil {
		t.Error("empty catalog must be rejected")
	}
}
