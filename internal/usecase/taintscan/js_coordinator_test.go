package taintscan

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeJsFacts struct {
	document  jsprogram.Document
	available bool
	err       error
}

func (f *fakeJsFacts) JsFacts(context.Context, string) (jsprogram.Document, bool, error) {
	return f.document, f.available, f.err
}

// jsCommandDocument is a minimal, valid one-module document with a request → child_process.exec command
// injection, used to exercise the coordinator's propose-only lifecycle end to end.
func jsCommandDocument() jsprogram.Document {
	const module, file = "app", "app.js"
	pos := jsprogram.Position{File: file, Line: 1, Column: 0}
	moduleID := jsprogram.CanonicalSymbolID(module, "<module>")
	source := jsprogram.Value{
		ID: "v-src", ScopeID: moduleID, Kind: jsprogram.ValueReference,
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceAttribute, Segments: []string{"req", "query", "cmd"}},
		Pos: jsprogram.Position{File: file, Line: 2, Column: 10},
	}
	return jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules:       []jsprogram.Module{{Name: module, File: file, Pos: pos}},
		Symbols: []jsprogram.Symbol{
			{ID: moduleID, Module: module, QualifiedName: "<module>", Name: module, Kind: jsprogram.SymbolModule, Pos: pos},
		},
		Imports: []jsprogram.Import{
			{ScopeID: moduleID, Kind: jsprogram.ImportNamed, Module: "child_process", Name: "exec", Alias: "exec", Pos: jsprogram.Position{File: file, Line: 1, Column: 0}},
		},
		Values: []jsprogram.Value{source},
		Calls: []jsprogram.Call{{
			ID: "c1", CallerID: moduleID,
			Callee:    jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"exec"}},
			Arguments: []jsprogram.Argument{{Value: source.Ref, ValueID: source.ID, Pos: jsprogram.Position{File: file, Line: 2, Column: 10}}},
			Pos:       jsprogram.Position{File: file, Line: 2, Column: 0},
		}},
		// A dynamic-execution gap keeps this document PARTIAL, matching what the real extractor emits, so the
		// coordinator records a positive on partial coverage without ever claiming completeness.
		CoverageGaps: []jsprogram.CoverageGap{{Kind: jsprogram.GapUnresolvedCall, SymbolID: moduleID, Detail: "call_target", Pos: jsprogram.Position{File: file, Line: 2, Column: 0}}},
		FilesSeen:    1,
		FilesParsed:  1,
	}
}

func newJsCoordinator(t *testing.T, provider *fakeJsFacts, proposals *fakeProposer, audit *fakeAudit) *JsCoordinator {
	t.Helper()
	c, err := NewJsCoordinator(provider, proposals, taint.DefaultJsCatalog(), audit, fixedClock{})
	if err != nil {
		t.Fatalf("NewJsCoordinator: %v", err)
	}
	return c
}

func TestJsScanProposesValueFlowWithWitness(t *testing.T) {
	proposals, audit := &fakeProposer{}, &fakeAudit{}
	c := newJsCoordinator(t, &fakeJsFacts{document: jsCommandDocument(), available: true}, proposals, audit)
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
	if len(audit.entries) != 1 || audit.entries[0].Action != "judgment.js_taint_proposed" {
		t.Fatalf("want one js taint audit entry, got %+v", audit.entries)
	}
}

func TestJsScanNoCoverageProposesNothing(t *testing.T) {
	for name, provider := range map[string]*fakeJsFacts{
		"sidecar unavailable": {available: false},
		"extraction failed":   {err: errors.New("parser detail")},
	} {
		t.Run(name, func(t *testing.T) {
			proposals := &fakeProposer{}
			c := newJsCoordinator(t, provider, proposals, &fakeAudit{})
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

func TestJsScanEmptySourceIsNotApplicable(t *testing.T) {
	proposals := &fakeProposer{}
	c := newJsCoordinator(t, &fakeJsFacts{available: true, document: jsprogram.Document{SchemaVersion: jsprogram.SchemaVersion}}, proposals, &fakeAudit{})
	outcome, err := c.ScanWithCoverage(context.Background(), shared.ID("eng-1"), "/ws")
	if err != nil {
		t.Fatalf("ScanWithCoverage: %v", err)
	}
	if outcome.Proposed != 0 || outcome.Coverage.Status != ports.AnalysisCoverageNotApplicable {
		t.Fatalf("want not-applicable with zero proposals, got proposed=%d status=%q", outcome.Proposed, outcome.Coverage.Status)
	}
}

func TestNewJsCoordinatorValidatesDependencies(t *testing.T) {
	provider, proposals, audit := &fakeJsFacts{}, &fakeProposer{}, &fakeAudit{}
	cases := []struct {
		name     string
		provider ports.JsFactsProvider
		proposer proposer
		audit    ports.AuditLogger
		clock    ports.Clock
	}{
		{"nil provider", nil, proposals, audit, fixedClock{}},
		{"nil proposer", provider, nil, audit, fixedClock{}},
		{"nil audit", provider, proposals, nil, fixedClock{}},
		{"nil clock", provider, proposals, audit, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewJsCoordinator(tc.provider, tc.proposer, taint.DefaultJsCatalog(), tc.audit, tc.clock); err == nil {
				t.Fatal("want a validation error")
			}
		})
	}
}
