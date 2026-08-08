package jsimports

import (
	"strings"
	"testing"
)

// The tests in this file are the anti-false-negative gate. Each case is a construct that really loads a
// module (or really can) but that this scanner does not extract a specifier from. Every one MUST produce a
// hazard, because a silent miss becomes "no import edge", which a later analyzer is allowed to read as
// proof the dependency is unused — suppressing a real vulnerability.

func TestIndirectRequireIsNeverSilent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{name: "aliased require", src: `const r = require; r("lodash");`},
		{name: "sequence-expression indirection", src: `(0, require)("lodash");`},
		{name: "require passed as a value", src: `register(require);`},
		{name: "require in a typeof guard", src: `if (typeof require !== "undefined") {}`},
		{name: "module receiver", src: `module.require("lodash");`},
		{name: "require.main receiver", src: `require.main.require("lodash");`},
		{name: "require.cache access", src: `delete require.cache[key];`},
		{name: "unknown require property", src: `require.somethingElse("lodash");`},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := extractAll(t, test.src)
			if len(result.hazards) == 0 {
				t.Fatalf("indirect require must degrade coverage, got no hazard for %q", test.src)
			}
		})
	}
}

func TestOptionalCallRequireStillYieldsAnEdge(t *testing.T) {
	t.Parallel()

	// `require?.("pkg")` loads the module, so it is a real edge rather than merely a hazard.
	got := specifiersOf(t, `require?.("lodash");`)
	if len(got) != 1 || got[0].specifier != "lodash" {
		t.Fatalf("optional-call require must produce an edge, got %+v", got)
	}
}

func TestEscapedIdentifierIsNeverSilent(t *testing.T) {
	t.Parallel()

	// A unicode-escaped identifier is valid JavaScript, so `require(...)` is a real require the
	// keyword matcher cannot see.
	for _, src := range []string{`\u0072equire("lodash");`, `\u0065val(payload);`} {
		src := src
		t.Run(src, func(t *testing.T) {
			t.Parallel()
			result := extractAll(t, src)
			if len(result.hazards) == 0 {
				t.Fatalf("escaped identifier must degrade coverage: %q", src)
			}
		})
	}
}

func TestGlobalEvaluatorShapesAreNeverSilent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{name: "aliased eval", src: `const e = eval; e(payload);`},
		{name: "sequence eval", src: `(0, eval)(payload);`},
		{name: "globalThis eval", src: `globalThis.eval(payload);`},
		{name: "window eval", src: `window.eval(payload);`},
		{name: "Function without new", src: `Function('return require("lodash")')();`},
		{name: "aliased Function", src: `const F = Function; F(src)();`},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := extractAll(t, test.src)
			if len(result.hazards) == 0 {
				t.Fatalf("a global evaluator reference must degrade coverage: %q", test.src)
			}
		})
	}
}

func TestUnrelatedMethodsNamedLikeLoadersStaySilent(t *testing.T) {
	t.Parallel()

	// The converse of the tests above: a method that merely shares a loader's NAME is not a loader, and
	// flagging it would degrade coverage for every project that has one.
	for _, src := range []string{`sandbox.eval("x");`, `vm.require("x");`, `db.define("users", {});`} {
		src := src
		t.Run(src, func(t *testing.T) {
			t.Parallel()
			if result := extractAll(t, src); len(result.hazards) != 0 {
				t.Fatalf("an unrelated method must not raise a hazard: %q → %+v", src, result.hazards)
			}
		})
	}
}

func TestIndirectLoaderFamiliesAreNeverSilent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{name: "amd define", src: `define(["lodash"], function (l) {});`},
		{name: "requirejs", src: `requirejs(["lodash"], cb);`},
		{name: "worker importScripts", src: `importScripts("./worker-dep.js");`},
		{name: "webpack escape hatch", src: `__non_webpack_require__("lodash");`},
		{name: "webpack runtime", src: `__webpack_require__("lodash");`},
		{name: "systemjs", src: `System.import("lodash");`},
		{name: "jest requireActual", src: `jest.requireActual("lodash");`},
		{name: "worker constructor", src: `new Worker(new URL("./worker.js", import.meta.url));`},
		{name: "native addon", src: `process.dlopen(module, "./addon.node");`},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := extractAll(t, test.src)
			if len(result.hazards) == 0 {
				t.Fatalf("an indirect loader must degrade coverage: %q", test.src)
			}
		})
	}
}

func TestUndecodedEscapeSpecifierYieldsNoEdge(t *testing.T) {
	t.Parallel()

	// A specifier containing an escape this lexer does not decode must NOT become an edge: decoding
	// "\154odash" as "l154odash" would name a package that does not exist while the real dependency
	// (lodash) gets no edge at all — a silently wrong graph.
	result := extractAll(t, `require("\154odash");`)
	if len(result.imports) != 0 {
		t.Fatalf("an undecoded-escape specifier must not become an edge, got %+v", result.imports)
	}
	if len(result.hazards) == 0 {
		t.Fatal("an undecoded-escape specifier must degrade coverage")
	}
}

func TestJSXTextDoesNotSwallowLoaders(t *testing.T) {
	t.Parallel()

	// The apostrophe in "Bob's" would open a string literal that closes at the apostrophe in "that's",
	// swallowing the expression container between them — including its require call. With JSX element
	// handling the text is skipped as text, so the container is still lexed as code.
	src := `export const A = () => <p>Bob's {require("lodash")} — that's it</p>;`

	result := extractJSX(t, src)
	found := false
	for _, imp := range result.imports {
		if imp.specifier == "lodash" {
			found = true
		}
	}
	if !found {
		t.Fatalf("jsx prose must not swallow a loader call, got imports %+v hazards %+v", result.imports, result.hazards)
	}
}

func TestJSXProseProducesNoFalseCoverage(t *testing.T) {
	t.Parallel()

	// Valid JSX whose text contains apostrophes, quotes and a closing tag on its own line must be
	// completely clean: a single apostrophe in UI copy must not make the whole project incomplete.
	src := strings.Join([]string{
		`import React from "react";`,
		`export function Panel() {`,
		`  return (`,
		`    <div className="panel">`,
		`      <p>This engagement's scope can't be edited — it "belongs" to the client.</p>`,
		`      <span>{count} items</span>`,
		`    </div>`,
		`  );`,
		`}`,
	}, "\n")

	result := extractJSX(t, src)
	if len(result.hazards) != 0 {
		t.Fatalf("valid jsx prose must produce no hazards, got %+v", result.hazards)
	}
	if len(result.imports) != 1 || result.imports[0].specifier != "react" {
		t.Fatalf("expected the react import to survive, got %+v", result.imports)
	}
}

func TestJSXClosingTagDoesNotStartARegex(t *testing.T) {
	t.Parallel()

	// The '/' of a closing tag must not be lexed as a regex opener: the old behaviour consumed to the
	// newline and then discarded the remainder of the file, losing every later import.
	src := strings.Join([]string{
		`export function View() {`,
		`  return (`,
		`    <div>`,
		`    </div>`,
		`  );`,
		`}`,
		`const late = require("late-pkg");`,
		`export const lazy = () => import("heavy-chart");`,
	}, "\n")

	for _, jsxAware := range []bool{true, false} {
		jsxAware := jsxAware
		t.Run(map[bool]string{true: "jsx dialect", false: "non-jsx dialect"}[jsxAware], func(t *testing.T) {
			t.Parallel()
			result := newExtractor([]byte(src), jsxAware).run()
			specs := map[string]bool{}
			for _, imp := range result.imports {
				specs[imp.specifier] = true
			}
			if !specs["late-pkg"] || !specs["heavy-chart"] {
				t.Fatalf("imports after a closing tag must survive, got %+v (hazards %+v)", result.imports, result.hazards)
			}
		})
	}
}

func TestDivisionAfterComparisonIsNotARegex(t *testing.T) {
	t.Parallel()

	// `a > b / c` and `a < b / c` must lex as division; treating '/' as a regex opener would consume to
	// the newline and swallow the following statement.
	src := "const ok = a > b / c;\nconst also = a < b / c;\nconst late = require(\"late-pkg\");"
	result := extractAll(t, src)
	if len(result.imports) != 1 || result.imports[0].specifier != "late-pkg" {
		t.Fatalf("division must not swallow the following import, got %+v", result.imports)
	}
	if len(result.hazards) != 0 {
		t.Fatalf("division must not raise a hazard, got %+v", result.hazards)
	}
}

func TestDeeplyNestedTemplatesAreBounded(t *testing.T) {
	t.Parallel()

	// A hostile file of nested template substitutions must not exhaust the memory of this in-process
	// scanner; it must terminate and degrade coverage instead.
	// Genuine nesting: each `${ opens a substitution that contains the next template.
	depth := maxFrameDepth + 20
	src := "const x = " + strings.Repeat("`${", depth) + "a" + strings.Repeat("}`", depth) + ";"
	result := extractAll(t, src)
	if len(result.hazards) == 0 {
		t.Fatal("template nesting past the depth bound must degrade coverage")
	}
}

func TestObjectKeyNamedImportIsNotADeclaration(t *testing.T) {
	t.Parallel()

	if result := extractAll(t, `const opts = { import: 1, export: 2 };`); len(result.hazards) != 0 {
		t.Fatalf("an object key named import must not raise a hazard, got %+v", result.hazards)
	}
}

// --- second-round anti-false-negative gate: regions the lexer must LEX rather than skip ---

func TestTemplateSubstitutionIsLexedAsCode(t *testing.T) {
	t.Parallel()

	// A loader inside `${ ... }` must be seen. Consuming the substitution byte-wise would hide
	// `require("./package.json").version` in a version banner — a real-world pattern.
	t.Run("require inside a substitution yields an edge", func(t *testing.T) {
		t.Parallel()
		result := extractAll(t, "const banner = `myapp v${require(\"lodash\").version}`;")
		found := false
		for _, imp := range result.imports {
			if imp.specifier == "lodash" {
				found = true
			}
		}
		if !found {
			t.Fatalf("a require inside a template substitution must yield an edge, got %+v (hazards %+v)", result.imports, result.hazards)
		}
	})

	t.Run("dynamic import inside a substitution yields an edge", func(t *testing.T) {
		t.Parallel()
		result := extractAll(t, "const html = `${await import(\"./tpl.js\")}`;")
		if len(result.imports) == 0 {
			t.Fatalf("an import inside a template substitution must be observed, got hazards %+v", result.hazards)
		}
	})

	t.Run("eval inside a substitution degrades coverage", func(t *testing.T) {
		t.Parallel()
		if result := extractAll(t, "const boom = `${eval(payload)}`;"); len(result.hazards) == 0 {
			t.Fatal("an eval inside a template substitution must degrade coverage")
		}
	})

	t.Run("substitution-free template stays a literal specifier", func(t *testing.T) {
		t.Parallel()
		got := specifiersOf(t, "await import(`chart.js`);")
		if len(got) != 1 || got[0].specifier != "chart.js" {
			t.Fatalf("a substitution-free template must remain a literal specifier, got %+v", got)
		}
	})

	t.Run("template escapes never become a specifier", func(t *testing.T) {
		t.Parallel()
		// Template escapes are not decoded, so the value is not the runtime specifier.
		result := extractAll(t, "require(`\\154odash`);")
		for _, imp := range result.imports {
			if imp.specifier == "154odash" {
				t.Fatalf("an undecoded template escape must not become an edge: %+v", result.imports)
			}
		}
		if len(result.hazards) == 0 {
			t.Fatal("an undecoded template escape must degrade coverage")
		}
	})
}

func TestJSXAttributeExpressionIsLexedAsCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		src       string
		wantEdge  string
		wantHazrd bool
	}{
		{name: "lazy route import keeps its edge", src: `<Route element={lazy(() => import("./pages/Admin"))} />`, wantEdge: "./pages/Admin"},
		{name: "spread require keeps its edge", src: `<Foo {...require("./defaults")} />`, wantEdge: "./defaults"},
		{name: "eval in an attribute degrades coverage", src: `<Foo onClick={() => eval(payload)} />`, wantHazrd: true},
		{name: "webpack require in an attribute degrades coverage", src: `<Foo x={__webpack_require__(4)} />`, wantHazrd: true},
		{name: "requireActual in an attribute degrades coverage", src: `<Foo x={jest.requireActual("lodash")} />`, wantHazrd: true},
		{name: "createRequire in an attribute degrades coverage", src: `<Foo x={createRequire(import.meta.url)} />`, wantHazrd: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := extractJSX(t, test.src)
			if test.wantEdge != "" {
				found := false
				for _, imp := range result.imports {
					if imp.specifier == test.wantEdge {
						found = true
					}
				}
				if !found {
					t.Fatalf("expected edge %q from an attribute expression, got %+v (hazards %+v)", test.wantEdge, result.imports, result.hazards)
				}
			}
			if test.wantHazrd && len(result.hazards) == 0 {
				t.Fatalf("expected a hazard from %q", test.src)
			}
		})
	}
}

func TestJSXInPlainJavaScriptIsHandled(t *testing.T) {
	t.Parallel()

	// JSX in a .js file is the majority of the React ecosystem. Scanning it non-JSX re-opens the
	// apostrophe-pair silent miss, so every dialect except plain TypeScript is JSX-aware.
	src := `export const A = () => <p>Bob's {require("lodash")} — that's it</p>;`
	result := newExtractor([]byte(src), true).run()
	found := false
	for _, imp := range result.imports {
		if imp.specifier == "lodash" {
			found = true
		}
	}
	if !found {
		t.Fatalf("jsx in plain javascript must not swallow a loader, got %+v (hazards %+v)", result.imports, result.hazards)
	}
}

func TestLoaderAliasingIsNeverSilent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{name: "webpack require aliased", src: `const wr = __webpack_require__; wr(4);`},
		{name: "importScripts aliased", src: `const is = importScripts; is("./dep.js");`},
		{name: "createRequire aliased", src: `const cr = createRequire; const r = cr(import.meta.url);`},
		{name: "requirejs aliased", src: `const rj = requirejs; rj(["lodash"], cb);`},
		{name: "require.context aliased", src: `const ctx = require.context;`},
		{name: "require.ensure aliased", src: `const ens = require.ensure;`},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if result := extractAll(t, test.src); len(result.hazards) == 0 {
				t.Fatalf("aliasing a loader must degrade coverage: %q", test.src)
			}
		})
	}
}

func TestComputedLoaderAccessIsNeverSilent(t *testing.T) {
	t.Parallel()

	for _, src := range []string{
		`module["require"]("lodash");`,
		`globalThis["eval"](payload);`,
		`process["dlopen"](module, path);`,
	} {
		src := src
		t.Run(src, func(t *testing.T) {
			t.Parallel()
			if result := extractAll(t, src); len(result.hazards) == 0 {
				t.Fatalf("a computed loader access must degrade coverage: %q", src)
			}
		})
	}
}

func TestCarriageReturnLineEndings(t *testing.T) {
	t.Parallel()

	// CR is an ECMAScript line terminator. Treating only LF as one made a CR-only file's first line
	// comment run to EOF, silently discarding the whole file.
	t.Run("cr terminates a line comment", func(t *testing.T) {
		t.Parallel()
		src := "// header\rconst lodash = require(\"lodash\");\rmodule.exports = lodash;"
		got := specifiersOf(t, src)
		if len(got) != 1 || got[0].specifier != "lodash" {
			t.Fatalf("a CR-terminated comment must not swallow the file, got %+v", got)
		}
	})

	t.Run("crlf is one line break", func(t *testing.T) {
		t.Parallel()
		src := "import a from \"one\";\r\nimport b from \"two\";"
		got := specifiersOf(t, src)
		if len(got) != 2 {
			t.Fatalf("expected both imports, got %+v", got)
		}
		if got[1].line != 2 {
			t.Fatalf("CRLF must count as one line break; second import reported at line %d", got[1].line)
		}
	})

	t.Run("unicode line separator terminates a comment", func(t *testing.T) {
		t.Parallel()
		src := "// note const x = require(\"lodash\");"
		got := specifiersOf(t, src)
		if len(got) != 1 {
			t.Fatalf("U+2028 must terminate a line comment, got %+v", got)
		}
	})
}

func TestTypeScriptGenericArrowIsNotJSX(t *testing.T) {
	t.Parallel()

	// Reading `<T,>(x) => x` as a JSX element would consume the function body as element text.
	tests := []string{
		"const identity = <T,>(x: T): T => x;\nconst late = require(\"late-pkg\");",
		"const id2 = <T extends unknown>(x: T) => x;\nconst late = require(\"late-pkg\");",
		"const id3 = <T>(x: T) => x;\nconst late = require(\"late-pkg\");",
	}
	for _, src := range tests {
		src := src
		t.Run(src[:24], func(t *testing.T) {
			t.Parallel()
			result := newExtractor([]byte(src), true).run()
			found := false
			for _, imp := range result.imports {
				if imp.specifier == "late-pkg" {
					found = true
				}
			}
			if !found {
				t.Fatalf("a generic arrow must not be read as JSX, got %+v (hazards %+v)", result.imports, result.hazards)
			}
		})
	}
}

func TestHTMLLikeCommentsProduceNoFalseEdge(t *testing.T) {
	t.Parallel()

	// Annex-B HTML-like comments are line comments to a real engine, so lexing them as code would
	// invent an edge from commented-out source.
	src := "<!-- require(\"commented-out\")\nconst real = require(\"real-pkg\");\n--> require(\"also-commented\")"
	result := extractAll(t, src)
	for _, imp := range result.imports {
		if imp.specifier == "commented-out" || imp.specifier == "also-commented" {
			t.Fatalf("a commented-out loader must not become an edge: %+v", result.imports)
		}
	}
}

func TestJSXProseContainingLoaderWordsProducesNoFalseCoverage(t *testing.T) {
	t.Parallel()

	// English words that merely CONTAIN a loader name must not degrade coverage: a bare "require"
	// signature matches "required", which would mark every project with that word in its UI as
	// permanently incomplete and make a negative reachability proof impossible.
	sources := []string{
		`<span>Approvals required ({approvals.length})</span>`,
		`<p>This import is a requirement of the export process.</p>`,
		`<td>Evaluation of the function requires review</td>`,
		`<p>Data imported from "the archive" was defined earlier.</p>`,
	}
	for _, src := range sources {
		src := src
		t.Run(src[:24], func(t *testing.T) {
			t.Parallel()
			if result := extractJSX(t, src); len(result.hazards) != 0 {
				t.Fatalf("prose containing a loader word must not raise a hazard: %q → %+v", src, result.hazards)
			}
		})
	}
}
