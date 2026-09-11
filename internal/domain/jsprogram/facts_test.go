package jsprogram

import (
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validDoc() Document {
	pos := Position{File: "src/app.js", Line: 1}
	moduleID := CanonicalSymbolID("src/app", "<module>")
	fnID := CanonicalSymbolID("src/app", "$init")
	fnPos := Position{File: "src/app.js", Line: 2, Column: 0}
	paramValue := fnID + "#param:0:$el"
	return Document{
		SchemaVersion: SchemaVersion,
		Modules:       []Module{{Name: "src/app", File: "src/app.js", Pos: pos}},
		Symbols: []Symbol{
			{ID: moduleID, Module: "src/app", QualifiedName: "<module>", Name: "app", Kind: SymbolModule, Pos: pos},
			{ID: fnID, Module: "src/app", QualifiedName: "$init", Name: "$init", ParentID: moduleID, Kind: SymbolFunction, Pos: fnPos,
				Parameters: []Parameter{{Name: "$el", Kind: ParameterPositional, ValueID: paramValue, Pos: fnPos}}},
		},
		Values: []Value{
			{ID: paramValue, ScopeID: fnID, Kind: ValueParameter, Name: "$el", Ref: Reference{Kind: ReferenceName, Segments: []string{"$el"}}, Pos: fnPos},
		},
		Imports: []Import{
			{ScopeID: moduleID, Kind: ImportNamed, Module: "@scope/pkg", Name: "query", Alias: "q", Pos: pos},
			{ScopeID: moduleID, Kind: ImportRequire, Module: "./util", Alias: "util", Pos: pos},
		},
		FilesSeen:   1,
		FilesParsed: 1,
	}
}

func TestValidateAcceptsValidDocumentWithDollarIdentifiers(t *testing.T) {
	d := validDoc()
	if err := d.Validate(); err != nil {
		t.Fatalf("valid document (with $ identifiers) rejected: %v", err)
	}
	if !d.Complete() {
		t.Errorf("document with no gaps and seen==parsed must be Complete")
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := map[string]func(*Document){
		"wrong schema":           func(d *Document) { d.SchemaVersion = 99 },
		"parsed exceeds seen":    func(d *Document) { d.FilesParsed = 5 },
		"bad module path":        func(d *Document) { d.Modules[0].Name = "src/../app"; d.Symbols[0].Module = "src/../app" },
		"module file mismatch":   func(d *Document) { d.Modules[0].File = "other.js" },
		"missing module symbol":  func(d *Document) { d.Symbols = d.Symbols[1:] },
		"symbol crosses module":  func(d *Document) { d.Symbols[1].Module = "src/other" },
		"bad value name":         func(d *Document) { d.Values[0].Name = "has space" },
		"bad import kind":        func(d *Document) { d.Imports[0].Kind = "bogus" },
		"bad import specifier":   func(d *Document) { d.Imports[0].Module = "bad specifier!" },
		"absolute position file": func(d *Document) { d.Modules[0].Pos.File = "/etc/passwd"; d.Modules[0].File = "/etc/passwd" },
		"reference with control": func(d *Document) { d.Values[0].Ref = Reference{Kind: ReferenceName, Segments: []string{"a\x00b"}} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := validDoc()
			mutate(&d)
			err := d.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %q", name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("error must wrap shared.ErrValidation, got %v", err)
			}
		})
	}
}

func TestValidModulePath(t *testing.T) {
	ok := []string{"index", "src/app", "src/routes/user", "a-b/c.d", "$x/_y"}
	bad := []string{"", "src//app", "../lib", "src/./x", "a b", "a:b"}
	for _, v := range ok {
		if !validModulePath(v) {
			t.Errorf("expected %q to be a valid module path", v)
		}
	}
	for _, v := range bad {
		if validModulePath(v) {
			t.Errorf("expected %q to be an invalid module path", v)
		}
	}
}

func TestValidNameAllowsDollar(t *testing.T) {
	for _, v := range []string{"$", "$x", "jQuery", "_x9", "$_$"} {
		if !validName(v) {
			t.Errorf("expected %q to be a valid JS identifier", v)
		}
	}
	for _, v := range []string{"", "1x", "a-b", "a.b", "*"} {
		if validName(v) {
			t.Errorf("expected %q to be an invalid JS identifier", v)
		}
	}
}

func TestSortCanonicalDeterministic(t *testing.T) {
	a := validDoc()
	b := validDoc()
	// Reverse b's independent slices; after SortCanonical both must be identical.
	for i, j := 0, len(b.Symbols)-1; i < j; i, j = i+1, j-1 {
		b.Symbols[i], b.Symbols[j] = b.Symbols[j], b.Symbols[i]
	}
	for i, j := 0, len(b.Imports)-1; i < j; i, j = i+1, j-1 {
		b.Imports[i], b.Imports[j] = b.Imports[j], b.Imports[i]
	}
	a.SortCanonical()
	b.SortCanonical()
	if !reflect.DeepEqual(a, b) {
		t.Errorf("SortCanonical is not order-independent:\n%+v\n%+v", a, b)
	}
}

func TestValidQualifiedAcceptsDisambiguated(t *testing.T) {
	ok := []string{"<module>", "f", "C.m", "C.m@6_2", "outer.inner", "C@1_0.m", "<fn@3_5>", "C.<fn@9_2>"}
	bad := []string{"", "C.m@", "C.m@x_2", "C.m@6", "C.m@6_", "a b", "1x.y", "C.m@6_2_3"}
	for _, v := range ok {
		if !validQualified(v) {
			t.Errorf("expected qualified %q to be valid", v)
		}
	}
	for _, v := range bad {
		if validQualified(v) {
			t.Errorf("expected qualified %q to be invalid", v)
		}
	}
}
