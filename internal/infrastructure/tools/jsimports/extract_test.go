package jsimports

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// extractSpecifiers is a test helper returning the specifier/kind/type-only triple of every import.
type extracted struct {
	specifier string
	kind      modulegraph.ImportKind
	typeOnly  bool
	line      int
}

func extractAll(t *testing.T, src string) extraction {
	t.Helper()
	return newExtractor([]byte(src), false).run()
}

// extractJSX runs the extractor with JSX element handling enabled (the .jsx/.tsx dialects).
func extractJSX(t *testing.T, src string) extraction {
	t.Helper()
	return newExtractor([]byte(src), true).run()
}

func specifiersOf(t *testing.T, src string) []extracted {
	t.Helper()
	result := extractAll(t, src)
	out := make([]extracted, 0, len(result.imports))
	for _, imp := range result.imports {
		out = append(out, extracted{specifier: imp.specifier, kind: imp.kind, typeOnly: imp.typeOnly, line: imp.position.Line})
	}
	return out
}

func hazardKindsOf(t *testing.T, src string) map[hazardKind]bool {
	t.Helper()
	out := map[hazardKind]bool{}
	for _, h := range extractAll(t, src).hazards {
		out[h.kind] = true
	}
	return out
}

func TestExtractImportForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want []extracted
	}{
		{
			name: "side-effect import",
			src:  `import "polyfill";`,
			want: []extracted{{specifier: "polyfill", kind: modulegraph.ImportESMStatic, line: 1}},
		},
		{
			name: "default import",
			src:  `import lodash from "lodash";`,
			want: []extracted{{specifier: "lodash", kind: modulegraph.ImportESMStatic, line: 1}},
		},
		{
			name: "named imports",
			src:  `import { map, filter as f } from "lodash/fp";`,
			want: []extracted{{specifier: "lodash/fp", kind: modulegraph.ImportESMStatic, line: 1}},
		},
		{
			name: "namespace import",
			src:  `import * as path from "node:path";`,
			want: []extracted{{specifier: "node:path", kind: modulegraph.ImportESMStatic, line: 1}},
		},
		{
			name: "default plus named",
			src:  `import React, { useState } from "react";`,
			want: []extracted{{specifier: "react", kind: modulegraph.ImportESMStatic, line: 1}},
		},
		{
			name: "scoped package with subpath",
			src:  `import x from "@scope/pkg/deep/path";`,
			want: []extracted{{specifier: "@scope/pkg/deep/path", kind: modulegraph.ImportESMStatic, line: 1}},
		},
		{
			name: "commonjs require",
			src:  `const parser = require("@scope/parser");`,
			want: []extracted{{specifier: "@scope/parser", kind: modulegraph.ImportCommonJS, line: 1}},
		},
		{
			name: "dynamic import literal",
			src:  `await import("chart.js");`,
			want: []extracted{{specifier: "chart.js", kind: modulegraph.ImportESMDynamic, line: 1}},
		},
		{
			name: "dynamic import substitution-free template",
			src:  "await import(`chart.js`);",
			want: []extracted{{specifier: "chart.js", kind: modulegraph.ImportESMDynamic, line: 1}},
		},
		{
			name: "re-export named",
			src:  `export { a, b } from "./local";`,
			want: []extracted{{specifier: "./local", kind: modulegraph.ImportReExport, line: 1}},
		},
		{
			name: "re-export star",
			src:  `export * from "shared-lib";`,
			want: []extracted{{specifier: "shared-lib", kind: modulegraph.ImportReExport, line: 1}},
		},
		{
			name: "re-export star as namespace",
			src:  `export * as helpers from "shared-lib";`,
			want: []extracted{{specifier: "shared-lib", kind: modulegraph.ImportReExport, line: 1}},
		},
		{
			name: "typescript import equals",
			src:  `import fs = require("fs");`,
			want: []extracted{{specifier: "fs", kind: modulegraph.ImportTypeScriptEqual, line: 1}},
		},
		{
			name: "multiline import clause keeps keyword line",
			src:  "import {\n  a,\n  b,\n} from \"multi\";",
			want: []extracted{{specifier: "multi", kind: modulegraph.ImportESMStatic, line: 1}},
		},
		{
			name: "several imports across lines",
			src:  "import a from \"one\";\nimport b from \"two\";",
			want: []extracted{
				{specifier: "one", kind: modulegraph.ImportESMStatic, line: 1},
				{specifier: "two", kind: modulegraph.ImportESMStatic, line: 2},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := specifiersOf(t, test.src)
			if len(got) != len(test.want) {
				t.Fatalf("extracted %d imports, want %d: %+v", len(got), len(test.want), got)
			}
			for i := range test.want {
				if got[i] != test.want[i] {
					t.Fatalf("import[%d] = %+v, want %+v", i, got[i], test.want[i])
				}
			}
		})
	}
}

func TestExtractTypeOnlyClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		src          string
		wantTypeOnly bool
	}{
		{name: "import type clause", src: `import type { T } from "pkg";`, wantTypeOnly: true},
		{name: "import type default", src: `import type T from "pkg";`, wantTypeOnly: true},
		{name: "export type clause", src: `export type { T } from "pkg";`, wantTypeOnly: true},
		// An all-inline-type binding list is NOT fully erased: under verbatimModuleSyntax tsc emits
		// `import "pkg";`, a real side-effect module load. Only a keyword-level `import type` is erased,
		// so treating this as type-only would drop a runtime dependency edge.
		{name: "all inline type members stay runtime", src: `import { type A, type B } from "pkg";`, wantTypeOnly: false},
		{name: "mixed inline members stay runtime", src: `import { type A, b } from "pkg";`, wantTypeOnly: false},
		{name: "value import", src: `import { a } from "pkg";`, wantTypeOnly: false},
		// A binding literally named "type" is a VALUE import, not a type-only modifier. Reading it as
		// type-only would drop a real runtime dependency edge.
		{name: "default binding named type", src: `import type from "pkg";`, wantTypeOnly: false},
		{name: "binding named type with named clause", src: `import type, { a } from "pkg";`, wantTypeOnly: false},
		{name: "member named type", src: `import { type } from "pkg";`, wantTypeOnly: false},
		{name: "member type aliased", src: `import { type as kind } from "pkg";`, wantTypeOnly: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := specifiersOf(t, test.src)
			if len(got) != 1 {
				t.Fatalf("expected exactly one import, got %+v", got)
			}
			if got[0].typeOnly != test.wantTypeOnly {
				t.Fatalf("typeOnly = %v, want %v (src %q)", got[0].typeOnly, test.wantTypeOnly, test.src)
			}
		})
	}
}

func TestExtractNoEdgeForLocalDeclarations(t *testing.T) {
	t.Parallel()

	sources := []string{
		`export const x = 1;`,
		`export default function main() {}`,
		`export { local };`,
		`export type Alias = string;`,
		`import X = Namespace.Inner;`,
		`const meta = import.meta.url;`,
		`obj.require("not-the-loader");`,
		`obj.import("also-not");`,
	}
	for _, src := range sources {
		src := src
		t.Run(src, func(t *testing.T) {
			t.Parallel()
			if got := specifiersOf(t, src); len(got) != 0 {
				t.Fatalf("expected no import edge for %q, got %+v", src, got)
			}
		})
	}
}

func TestExtractHazards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want hazardKind
	}{
		{name: "non-literal require", src: `require(name);`, want: hazardDynamicRequire},
		{name: "concatenated require", src: `require("a" + b);`, want: hazardDynamicRequire},
		{name: "template require with substitution", src: "require(`pkg/${name}`);", want: hazardDynamicRequire},
		{name: "non-literal dynamic import", src: `import(spec);`, want: hazardDynamicImport},
		{name: "template dynamic import with substitution", src: "import(`./pages/${page}`);", want: hazardDynamicImport},
		{name: "eval", src: `eval("code");`, want: hazardEval},
		{name: "new Function", src: `new Function("return 1")();`, want: hazardNewFunction},
		{name: "require.context", src: `require.context("./dir", true);`, want: hazardRequireContext},
		{name: "require.ensure", src: `require.ensure([], function () {});`, want: hazardRequireContext},
		{name: "import.meta.glob", src: `import.meta.glob("./mods/*.ts");`, want: hazardImportMetaGlob},
		{name: "createRequire", src: `const req = createRequire(import.meta.url);`, want: hazardModuleCreateRequire},
		{name: "computed require.resolve", src: `require.resolve(name);`, want: hazardUnsupportedLoader},
		{name: "unterminated string", src: `import a from "unterminated`, want: hazardMalformedSource},
		{name: "unterminated block comment", src: "/* never closed", want: hazardMalformedSource},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := hazardKindsOf(t, test.src)
			if !got[test.want] {
				t.Fatalf("expected hazard %v for %q, got %+v", test.want, test.src, got)
			}
		})
	}
}

func TestExtractIgnoresNonGlobalEvalAndRequire(t *testing.T) {
	t.Parallel()

	// A member access is not the global loader/evaluator: flagging it would degrade coverage for every
	// project that happens to have a method called eval or require.
	sources := []string{`sandbox.eval("x");`, `vm.require("x");`, `a?.eval("x");`}
	for _, src := range sources {
		src := src
		t.Run(src, func(t *testing.T) {
			t.Parallel()
			got := hazardKindsOf(t, src)
			if got[hazardEval] || got[hazardDynamicRequire] {
				t.Fatalf("member access must not raise a global loader hazard for %q: %+v", src, got)
			}
		})
	}
}

func TestExtractLexerHostileSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		src           string
		wantSpecifier string
		wantCount     int
	}{
		{
			name:          "import inside line comment is ignored",
			src:           "// import evil from \"attacker\";\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "import inside block comment is ignored",
			src:           "/* import evil from \"attacker\"; */ import ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "import inside string literal is ignored",
			src:           "const s = \"import evil from 'attacker'\";\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "import inside template literal is ignored",
			src:           "const s = `import evil from \"attacker\"`;\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "regex containing quotes does not break lexing",
			src:           "const re = /[\"']import.*from/g;\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "regex containing a slash in a character class",
			src:           "const re = /[/]/;\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "division is not a regex",
			src:           "const ratio = a / b / c;\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "escaped quote inside string",
			src:           "const s = \"he said \\\"import\\\"\";\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "nested template substitution with braces",
			src:           "const s = `${ {a: `${b}`} }`;\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "shebang line",
			src:           "#!/usr/bin/env node\nimport ok from \"real\";",
			wantSpecifier: "real",
			wantCount:     1,
		},
		{
			name:          "jsx does not confuse the lexer",
			src:           "import ok from \"real\";\nconst el = <div a=\"b\">{x < y ? 1 : 2}</div>;",
			wantSpecifier: "real",
			wantCount:     1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := specifiersOf(t, test.src)
			if len(got) != test.wantCount {
				t.Fatalf("extracted %d imports, want %d: %+v (src %q)", len(got), test.wantCount, got, test.src)
			}
			if test.wantCount > 0 && got[0].specifier != test.wantSpecifier {
				t.Fatalf("specifier = %q, want %q", got[0].specifier, test.wantSpecifier)
			}
		})
	}
}

func TestExtractComputedSpecifierProducesNoEdge(t *testing.T) {
	t.Parallel()

	// A concatenated or interpolated specifier must produce NO edge. Recording the first literal
	// fragment ("pkg/") as the module would be a silently wrong dependency edge, and the runtime target
	// is unobservable — so the only honest output is a hazard and no edge.
	sources := []string{
		`require("pkg/" + name);`,
		`import("pkg/" + name);`,
		"require(`pkg/${name}`);",
		"import(`./pages/${page}.js`);",
		`import mod = require("pkg/" + name);`,
	}
	for _, src := range sources {
		src := src
		t.Run(src, func(t *testing.T) {
			t.Parallel()
			result := extractAll(t, src)
			if len(result.imports) != 0 {
				t.Fatalf("computed specifier must yield no edge, got %+v", result.imports)
			}
			if len(result.hazards) == 0 {
				t.Fatalf("computed specifier must yield a hazard so coverage degrades")
			}
		})
	}
}

func TestExtractImportAttributesKeepLiteralSpecifier(t *testing.T) {
	t.Parallel()

	// ESM import attributes add a second argument; the specifier is still a literal.
	got := specifiersOf(t, `await import("data.json", { with: { type: "json" } });`)
	if len(got) != 1 || got[0].specifier != "data.json" {
		t.Fatalf("expected the literal specifier to survive import attributes, got %+v", got)
	}
}

func TestExtractDeterministicAcrossRuns(t *testing.T) {
	t.Parallel()

	src := `
import a from "one";
import { b } from "two";
const c = require("three");
await import("four");
export * from "five";
require(dynamic);
`
	first := extractAll(t, src)
	second := extractAll(t, src)
	if len(first.imports) != len(second.imports) || len(first.hazards) != len(second.hazards) {
		t.Fatalf("extraction is not deterministic: %d/%d vs %d/%d imports/hazards",
			len(first.imports), len(first.hazards), len(second.imports), len(second.hazards))
	}
	for i := range first.imports {
		if first.imports[i].specifier != second.imports[i].specifier || first.imports[i].kind != second.imports[i].kind {
			t.Fatalf("import[%d] differs between runs", i)
		}
	}
}
