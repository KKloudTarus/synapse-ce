package javaprogram

import "testing"

// validDoc builds a minimal, referentially-consistent one-module document: a class with a method whose
// parameter is a tainted @RequestParam, a value slot for it, a call, and an intra-procedural flow.
func validDoc() Document {
	const mod = "src/main/java/com/acme/App"
	file := mod + ".java"
	pos := Position{File: file, Line: 1, Column: 0}
	modID := CanonicalSymbolID(mod, "<module>")
	clsID := CanonicalSymbolID(mod, "App")
	mID := CanonicalSymbolID(mod, "App.handle")
	return Document{
		SchemaVersion: SchemaVersion,
		Modules:       []Module{{Name: mod, File: file, Pos: pos}},
		Symbols: []Symbol{
			{ID: modID, Module: mod, QualifiedName: "<module>", Name: "App", Kind: SymbolModule, Pos: pos},
			{ID: clsID, Module: mod, QualifiedName: "App", Name: "App", ParentID: modID, Kind: SymbolClass, Pos: pos},
			{ID: mID, Module: mod, QualifiedName: "App.handle", Name: "handle", ParentID: clsID, Kind: SymbolMethod, Pos: pos,
				Parameters: []Parameter{{Name: "id", Kind: ParameterPositional, ValueID: "v-id", Pos: pos,
					Annotations: []Reference{{Kind: ReferenceName, Segments: []string{"RequestParam"}}}}}},
		},
		Values: []Value{
			{ID: "v-id", ScopeID: mID, Kind: ValueParameter, Name: "id", Ref: Reference{Kind: ReferenceName, Segments: []string{"id"}}, Pos: pos},
			{ID: "v-arg", ScopeID: mID, Kind: ValueReference, Ref: Reference{Kind: ReferenceName, Segments: []string{"id"}}, Pos: pos},
		},
		Flows: []ValueFlow{{FromID: "v-id", ToID: "v-arg", Kind: FlowExpression, Pos: pos}},
		Calls: []Call{{ID: "c1", CallerID: mID, Callee: Reference{Kind: ReferenceAttribute, Segments: []string{"stmt", "executeQuery"}},
			Arguments: []Argument{{Value: Reference{Kind: ReferenceName, Segments: []string{"id"}}, ValueID: "v-arg", Pos: pos}}, Pos: pos}},
		Imports:     []Import{{ScopeID: modID, Kind: ImportSingle, Module: "java.sql.Statement", Name: "Statement", Pos: pos}},
		FilesSeen:   1,
		FilesParsed: 1,
	}
}

func TestValidateAcceptsValidDocument(t *testing.T) {
	d := validDoc()
	if err := d.Validate(); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	if !d.Complete() {
		t.Error("a fully-parsed gap-free document must be Complete")
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Document)
	}{
		{"bad schema", func(d *Document) { d.SchemaVersion = 2 }},
		{"symbol id mismatch", func(d *Document) { d.Symbols[1].ID = "java:wrong" }},
		{"parent crosses module", func(d *Document) { d.Symbols[2].Module = "other/mod" }},
		{"flow crosses scope", func(d *Document) { d.Values[1].ScopeID = CanonicalSymbolID("src/main/java/com/acme/App", "App") }},
		{"call arg value missing", func(d *Document) { d.Calls[0].Arguments[0].ValueID = "nope" }},
		{"absolute position", func(d *Document) { d.Modules[0].Pos.File = "/etc/passwd"; d.Modules[0].File = "/etc/passwd" }},
		{"bad import target", func(d *Document) { d.Imports[0].Module = "java sql" }},
		{"parsed exceeds seen", func(d *Document) { d.FilesParsed = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validDoc()
			tc.mutate(&d)
			if err := d.Validate(); err == nil {
				t.Errorf("%s: expected Validate to reject", tc.name)
			}
		})
	}
}

func TestIncompleteWhenTruncatedOrGapped(t *testing.T) {
	d := validDoc()
	d.Truncated = true
	if d.Complete() {
		t.Error("a truncated document must not be Complete")
	}
	d = validDoc()
	d.CoverageGaps = []CoverageGap{{Kind: GapDynamicExecution, Pos: Position{File: "x.java"}}}
	if d.Complete() {
		t.Error("a document with a coverage gap must not be Complete")
	}
}
