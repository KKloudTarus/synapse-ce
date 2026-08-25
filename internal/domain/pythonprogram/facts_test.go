package pythonprogram

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validDocument() Document {
	modulePos := Position{File: "app/api.py", Line: 1}
	moduleID := "python:app.api:<module>"
	functionID := "python:app.api:create_user"
	return Document{
		SchemaVersion: SchemaVersion,
		Modules:       []Module{{Name: "app.api", File: modulePos.File, Pos: modulePos}},
		Symbols: []Symbol{
			{ID: moduleID, Module: "app.api", QualifiedName: "<module>", Name: "api", Kind: SymbolModule, Pos: modulePos},
			{ID: functionID, Module: "app.api", QualifiedName: "create_user", Name: "create_user", ParentID: moduleID, Kind: SymbolFunction, Pos: Position{File: modulePos.File, Line: 3}, Parameters: []Parameter{{Name: "request", Kind: ParameterPositional, Pos: Position{File: modulePos.File, Line: 3}}}},
		},
		Calls:     []Call{{ID: "app/api.py:4:11", CallerID: functionID, Callee: Reference{Kind: ReferenceAttribute, Segments: []string{"db", "execute"}}, Pos: Position{File: modulePos.File, Line: 4, Column: 11}}},
		FilesSeen: 1, FilesParsed: 1, NodesSeen: 12,
	}
}

func TestDocumentValidateAndComplete(t *testing.T) {
	doc := validDocument()
	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !doc.Complete() {
		t.Fatal("a fully parsed gap-free document must be complete")
	}
	doc.CoverageGaps = []CoverageGap{{Kind: GapDynamicImport, Pos: Position{File: "app/api.py", Line: 8}}}
	if doc.Complete() {
		t.Fatal("a coverage gap must make a negative proof incomplete")
	}
}

func TestDocumentValidateRejectsUnsafeOrUnboundedFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Document)
	}{
		{"schema", func(d *Document) { d.SchemaVersion++ }},
		{"absolute path", func(d *Document) { d.Modules[0].File, d.Modules[0].Pos.File = "/secret/app.py", "/secret/app.py" }},
		{"parent path", func(d *Document) { d.Modules[0].File, d.Modules[0].Pos.File = "../app.py", "../app.py" }},
		{"unknown parent", func(d *Document) { d.Symbols[1].ParentID = "python:missing:x" }},
		{"noncanonical symbol id", func(d *Document) { d.Symbols[1].ID = "python:app.api:other" }},
		{"cross-file symbol", func(d *Document) { d.Symbols[1].Pos.File = "other.py" }},
		{"missing module symbol", func(d *Document) { d.Symbols = d.Symbols[1:] }},
		{"opaque source text", func(d *Document) {
			d.Calls[0].Callee = Reference{Kind: ReferenceUnknown, Segments: []string{"do", "not", "leak"}}
		}},
		{"absolute call path", func(d *Document) { d.Calls[0].Pos.File = "C:/target/app.py" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDocument()
			tt.mutate(&doc)
			if err := doc.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("Validate error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestSortCanonical(t *testing.T) {
	doc := validDocument()
	doc.Calls = append(doc.Calls, Call{ID: "app/api.py:2:1", CallerID: doc.Symbols[0].ID, Callee: Reference{Kind: ReferenceName, Segments: []string{"boot"}}, Pos: Position{File: "app/api.py", Line: 2, Column: 1}})
	doc.Modules = append(doc.Modules, Module{Name: "app", File: "app/__init__.py", Pos: Position{File: "app/__init__.py", Line: 1}})
	doc.SortCanonical()
	if doc.Modules[0].File != "app/__init__.py" || doc.Calls[0].ID != "app/api.py:2:1" {
		t.Fatalf("canonical order not applied: modules=%+v calls=%+v", doc.Modules, doc.Calls)
	}
}
