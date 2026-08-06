package modulegraph

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeRepositoryPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "slash form", input: "src/app.ts", want: "src/app.ts"},
		{name: "dot and backslash", input: `.\\src\\app.ts`, want: "src/app.ts"},
		{name: "clean segments", input: "src/lib/../app.ts", want: "src/app.ts"},
		{name: "empty", input: "", wantErr: true},
		{name: "dot", input: ".", wantErr: true},
		{name: "unix absolute", input: "/src/app.ts", wantErr: true},
		{name: "windows absolute", input: `C:\\src\\app.ts`, wantErr: true},
		{name: "root escape", input: "../app.ts", wantErr: true},
		{name: "cleaned root escape", input: "src/../../app.ts", wantErr: true},
		{name: "nul", input: "src/\x00app.ts", wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeRepositoryPath(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("NormalizeRepositoryPath(%q) error = nil", test.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeRepositoryPath(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("NormalizeRepositoryPath(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestDialectForPathAndDeclaration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path        string
		dialect     Dialect
		declaration bool
	}{
		{path: "a.js", dialect: DialectJavaScript},
		{path: "a.mjs", dialect: DialectJavaScript},
		{path: "a.cjs", dialect: DialectJavaScript},
		{path: "a.jsx", dialect: DialectJSX},
		{path: "a.ts", dialect: DialectTypeScript},
		{path: "a.mts", dialect: DialectTypeScript},
		{path: "a.cts", dialect: DialectTypeScript},
		{path: "a.tsx", dialect: DialectTSX},
		{path: "a.d.ts", dialect: DialectTypeScript, declaration: true},
		{path: "a.d.mts", dialect: DialectTypeScript, declaration: true},
		{path: "a.d.cts", dialect: DialectTypeScript, declaration: true},
	}

	for _, test := range tests {
		got, ok := DialectForPath(test.path)
		if !ok || got != test.dialect {
			t.Fatalf("DialectForPath(%q) = %q, %v; want %q, true", test.path, got, ok, test.dialect)
		}
		if got := IsDeclarationPath(test.path); got != test.declaration {
			t.Fatalf("IsDeclarationPath(%q) = %v, want %v", test.path, got, test.declaration)
		}
	}

	if _, ok := DialectForPath("README.md"); ok {
		t.Fatal("DialectForPath(README.md) unexpectedly supported")
	}
}

func TestNormalizeDeterministicAndNonMutating(t *testing.T) {
	t.Parallel()

	bindingA := Binding{Imported: "z", Local: "localZ"}
	bindingB := Binding{Imported: "a", Local: "localA", TypeOnly: true}
	edge := Edge{
		From:      `.\\src\\entry.ts`,
		To:        "src/lib.ts",
		Specifier: "./lib.js",
		Kind:      ImportESMStatic,
		Bindings:  []Binding{bindingA, bindingB, bindingA},
		Position:  Position{Line: 3, Column: 1},
	}
	input := Graph{
		Modules: []Module{
			{Path: "types/index.d.ts", Dialect: DialectTypeScript, DeclarationOnly: true},
			{Path: "src/lib.ts", Dialect: DialectTypeScript},
			{Path: `.\\src\\entry.ts`, Dialect: DialectTypeScript},
			{Path: "src/lib.ts", Dialect: DialectTypeScript},
		},
		Edges: []Edge{
			edge,
			{From: "src/entry.ts", Specifier: "pkg", Kind: ImportESMDynamic, Position: Position{Line: 8, Column: 7}},
			edge,
		},
		Roots: []string{"do/not/trust/input.ts"},
		Coverage: []CoverageIssue{
			{Kind: CoverageDynamicImport, Path: `.\\src\\entry.ts`, Line: 9, Detail: "computed specifier"},
			{Kind: CoverageDynamicImport, Path: "src/entry.ts", Line: 9, Detail: "computed specifier"},
		},
		FilesScanned: 3,
		BytesScanned: 128,
	}
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	var canonical []byte
	for i := 0; i < 100; i++ {
		got, err := Normalize(input)
		if err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			canonical = encoded
		} else if !reflect.DeepEqual(encoded, canonical) {
			t.Fatalf("run %d produced non-deterministic output\nfirst: %s\n got: %s", i, canonical, encoded)
		}

		wantRoots := []string{"src/entry.ts", "types/index.d.ts"}
		if !reflect.DeepEqual(got.Roots, wantRoots) {
			t.Fatalf("Roots = %#v, want %#v", got.Roots, wantRoots)
		}
		if len(got.Modules) != 3 || len(got.Edges) != 2 || len(got.Coverage) != 1 {
			t.Fatalf("dedup counts = modules:%d edges:%d coverage:%d", len(got.Modules), len(got.Edges), len(got.Coverage))
		}
		if got.Edges[1].Bindings[0] != bindingB || got.Edges[1].Bindings[1] != bindingA {
			t.Fatalf("bindings not normalized: %#v", got.Edges[1].Bindings)
		}
	}

	after, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("Normalize mutated input\nbefore: %s\n after: %s", before, after)
	}
}

func TestNormalizeCycleHasNoStructuralRoot(t *testing.T) {
	t.Parallel()

	got, err := Normalize(Graph{
		Modules: []Module{
			{Path: "a.ts", Dialect: DialectTypeScript},
			{Path: "b.ts", Dialect: DialectTypeScript},
		},
		Edges: []Edge{
			{From: "a.ts", To: "b.ts", Specifier: "./b", Kind: ImportESMStatic},
			{From: "b.ts", To: "a.ts", Specifier: "./a", Kind: ImportESMStatic},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Roots) != 0 {
		t.Fatalf("Roots = %#v, want none", got.Roots)
	}
}

func TestNormalizeRejectsContractViolations(t *testing.T) {
	t.Parallel()

	validModule := Module{Path: "a.ts", Dialect: DialectTypeScript}
	tests := []struct {
		name  string
		graph Graph
		part  string
	}{
		{name: "negative files", graph: Graph{FilesScanned: -1}, part: "negative files"},
		{name: "negative bytes", graph: Graph{BytesScanned: -1}, part: "negative bytes"},
		{name: "unsupported extension", graph: Graph{Modules: []Module{{Path: "a.go", Dialect: DialectTypeScript}}}, part: "unsupported source extension"},
		{name: "dialect mismatch", graph: Graph{Modules: []Module{{Path: "a.ts", Dialect: DialectJavaScript}}}, part: "does not match"},
		{name: "declaration mismatch", graph: Graph{Modules: []Module{{Path: "a.d.ts", Dialect: DialectTypeScript}}}, part: "declaration-only"},
		{name: "invalid kind", graph: Graph{Modules: []Module{validModule}, Edges: []Edge{{From: "a.ts", Kind: "mystery"}}}, part: "invalid import kind"},
		{name: "missing source", graph: Graph{Modules: []Module{validModule}, Edges: []Edge{{From: "missing.ts", Kind: ImportESMStatic}}}, part: "not a known module"},
		{name: "missing target", graph: Graph{Modules: []Module{validModule}, Edges: []Edge{{From: "a.ts", To: "missing.ts", Kind: ImportESMStatic}}}, part: "not a known module"},
		{name: "invalid coverage kind", graph: Graph{Modules: []Module{validModule}, Coverage: []CoverageIssue{{Kind: "mystery"}}}, part: "invalid coverage issue kind"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Normalize(test.graph)
			if err == nil || !strings.Contains(err.Error(), test.part) {
				t.Fatalf("Normalize error = %v, want substring %q", err, test.part)
			}
		})
	}
}
