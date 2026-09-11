//go:build cgo

package astwalk

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

func TestJsFactsForExtractsSemanticFactsDeterministically(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app/api.js", ""+
		"const express = require('express');\n"+
		"import { execSync } from 'child_process';\n"+
		"import lodash from 'lodash';\n"+
		"import * as fs from 'fs';\n"+
		"const app = express();\n"+
		"app.get('/x', (req, res) => {\n"+
		"  const id = req.query.id;\n"+
		"  const q = `select * from t where id=${id}`;\n"+
		"  db.query(q);\n"+
		"  res.send(id);\n"+
		"});\n")
	writeFile(t, root, "app/util.js", ""+
		"function helper(name, ...rest) {\n"+
		"  const { a, b } = name;\n"+
		"  return a;\n"+
		"}\n"+
		"function withOpts({ host, port }) {\n"+
		"  return host;\n"+
		"}\n"+
		"class Svc extends Base {\n"+
		"  handle(x) { return x; }\n"+
		"}\n")

	first, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	second, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor second run: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		l, _ := json.Marshal(first)
		r, _ := json.Marshal(second)
		t.Fatalf("facts are not deterministic:\n%s\n%s", l, r)
	}
	if !first.Complete() || first.FilesSeen != 2 || first.FilesParsed != 2 {
		t.Fatalf("coverage seen=%d parsed=%d complete=%v gaps=%+v", first.FilesSeen, first.FilesParsed, first.Complete(), first.CoverageGaps)
	}

	// Imports: kind + specifier + local binding.
	wantImports := []jsprogram.Import{
		{Kind: jsprogram.ImportRequire, Module: "express", Alias: "express"},
		{Kind: jsprogram.ImportNamed, Module: "child_process", Name: "execSync", Alias: "execSync"},
		{Kind: jsprogram.ImportDefault, Module: "lodash", Name: "default", Alias: "lodash"},
		{Kind: jsprogram.ImportNamespace, Module: "fs", Alias: "fs"},
	}
	for _, want := range wantImports {
		if !hasJsImport(first, want) {
			t.Errorf("missing import %+v (imports: %+v)", want, first.Imports)
		}
	}

	// Symbols with parameter kinds.
	helper, ok := jsSymbolByQualified(first, "app/util", "helper")
	if !ok || helper.Kind != jsprogram.SymbolFunction || len(helper.Parameters) != 2 {
		t.Fatalf("helper = %+v ok=%v", helper, ok)
	}
	if helper.Parameters[0].Kind != jsprogram.ParameterPositional || helper.Parameters[1].Kind != jsprogram.ParameterRest {
		t.Errorf("helper params should be [positional, rest], got %+v", helper.Parameters)
	}
	// Destructured PARAMETERS (not a body destructuring) bind each contained name.
	withOpts, ok := jsSymbolByQualified(first, "app/util", "withOpts")
	if !ok || len(withOpts.Parameters) != 2 {
		t.Fatalf("withOpts params = %+v ok=%v", withOpts.Parameters, ok)
	}
	for _, p := range withOpts.Parameters {
		if p.Kind != jsprogram.ParameterDestructured || (p.Name != "host" && p.Name != "port") {
			t.Errorf("withOpts param should be destructured host/port, got %+v", p)
		}
	}
	svc, ok := jsSymbolByQualified(first, "app/util", "Svc")
	if !ok || svc.Kind != jsprogram.SymbolClass || len(svc.Bases) != 1 || joinJsRef(svc.Bases[0]) != "Base" {
		t.Errorf("Svc class/extends = %+v ok=%v", svc, ok)
	}
	if _, ok := jsSymbolByQualified(first, "app/util", "Svc.handle"); !ok {
		t.Errorf("missing method Svc.handle (symbols: %+v)", first.Symbols)
	}
	// The request handler arrow carries req/res as parameters (the taint sources PR2 will mark).
	if !hasJsArrowWithParam(first, "req") || !hasJsArrowWithParam(first, "res") {
		t.Errorf("request-handler arrow should bind req and res params")
	}

	// Calls: receiver + argument captured.
	if !hasJsCall(first, "db.query") || !hasJsCall(first, "res.send") {
		t.Errorf("missing db.query / res.send calls (calls: %+v)", first.Calls)
	}

	// Template-literal substitution flow: the tainted `id` reaches the template value, which is the
	// assignment source for q. This is the SQLi flow PR2 relies on.
	qValueID := jsAssignmentValueID(first, "q")
	if qValueID == "" {
		t.Fatalf("no assignment for q found")
	}
	if !jsFlowReaches(first, "id", qValueID) {
		t.Errorf("id must flow into the template literal assigned to q (flows: %+v)", first.Flows)
	}
}

func TestJsFactsForContainerGranularSubscript(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "s.js", ""+
		"function f(input) {\n"+
		"  const d = {};\n"+
		"  d['k'] = input;\n"+
		"  return d['other'];\n"+
		"}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	// A subscript WRITE d['k']=input binds the container `d` (never a synthetic field), and a subscript READ
	// d['other'] reads the same container — the conservative, no-false-positive model.
	if !hasJsBindingTarget(doc, "d") {
		t.Errorf("subscript write must bind the container d (assignments: %+v)", doc.Assignments)
	}
}

func TestJsFactsForRecordsDynamicGaps(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want jsprogram.GapKind
	}{
		{"eval", "function f(x){ eval(x); }\n", jsprogram.GapDynamicExecution},
		{"new Function", "function f(x){ const g = new Function(x); return g; }\n", jsprogram.GapDynamicExecution},
		{"dynamic import", "async function f(m){ await import(m); }\n", jsprogram.GapDynamicImport},
		{"dynamic require", "function f(m){ const x = require(m); return x; }\n", jsprogram.GapDynamicImport},
		{"with", "function f(o){ with (o) { return q; } }\n", jsprogram.GapDynamicAttribute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "d.js", tc.src)
			doc, err := JsFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("JsFactsFor: %v", err)
			}
			if !hasJsGap(doc, tc.want) {
				t.Errorf("expected coverage gap %q for %q; gaps=%+v", tc.want, tc.name, doc.CoverageGaps)
			}
			if doc.Complete() {
				t.Errorf("a document with a dynamic gap must not be Complete")
			}
		})
	}
}

func TestJsFactsForParseRecoveryGap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "broken.js", "function f( { return\n") // unbalanced, forces parser recovery
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if doc.Complete() {
		t.Fatal("a recovered parse must not support a negative proof")
	}
	if !hasJsGap(doc, jsprogram.GapParseRecovery) {
		t.Errorf("expected a parse-recovery gap, got %+v", doc.CoverageGaps)
	}
}

func TestJsFactsForTypeScriptAndTsx(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "h.ts", ""+
		"export function handler(req: Request, res: Response): void {\n"+
		"  const id: string = req.params.id;\n"+
		"  res.end(id);\n"+
		"}\n")
	writeFile(t, root, "c.tsx", "const App = (props: Props) => { const x = props.name; return null; };\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if doc.FilesSeen != 2 || doc.FilesParsed != 2 || !doc.Complete() {
		t.Fatalf("ts/tsx coverage seen=%d parsed=%d complete=%v gaps=%+v", doc.FilesSeen, doc.FilesParsed, doc.Complete(), doc.CoverageGaps)
	}
	if _, ok := jsSymbolByQualified(doc, "h", "handler"); !ok {
		t.Errorf("missing TypeScript function handler (symbols: %+v)", doc.Symbols)
	}
	// The TS handler's typed params (req/res) must be extracted despite the annotations.
	h, _ := jsSymbolByQualified(doc, "h", "handler")
	if len(h.Parameters) != 2 || h.Parameters[0].Name != "req" {
		t.Errorf("TS typed params not unwrapped: %+v", h.Parameters)
	}
	if !hasJsCall(doc, "res.end") {
		t.Errorf("missing res.end call in the .ts file")
	}
}

func TestJsFactsForDestructuredRequire(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "r.js", "const { exec, spawn } = require('child_process');\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	for _, name := range []string{"exec", "spawn"} {
		if !hasJsImport(doc, jsprogram.Import{Kind: jsprogram.ImportRequire, Module: "child_process", Name: name, Alias: name}) {
			t.Errorf("missing destructured require binding %q (imports: %+v)", name, doc.Imports)
		}
	}
}

// --- test helpers ---

func hasJsImport(doc jsprogram.Document, want jsprogram.Import) bool {
	for _, im := range doc.Imports {
		if im.Kind == want.Kind && im.Module == want.Module && im.Name == want.Name && im.Alias == want.Alias {
			return true
		}
	}
	return false
}

func jsSymbolByQualified(doc jsprogram.Document, module, qualified string) (jsprogram.Symbol, bool) {
	for _, s := range doc.Symbols {
		if s.Module == module && s.QualifiedName == qualified {
			return s, true
		}
	}
	return jsprogram.Symbol{}, false
}

func hasJsArrowWithParam(doc jsprogram.Document, param string) bool {
	for _, s := range doc.Symbols {
		if s.Kind != jsprogram.SymbolArrow {
			continue
		}
		for _, p := range s.Parameters {
			if p.Name == param {
				return true
			}
		}
	}
	return false
}

func hasJsCall(doc jsprogram.Document, callee string) bool {
	for _, c := range doc.Calls {
		if joinJsRef(c.Callee) == callee {
			return true
		}
	}
	return false
}

func hasJsBindingTarget(doc jsprogram.Document, name string) bool {
	for _, a := range doc.Assignments {
		for _, target := range a.Targets {
			if joinJsRef(target) == name {
				return true
			}
		}
	}
	return false
}

func hasJsGap(doc jsprogram.Document, kind jsprogram.GapKind) bool {
	for _, g := range doc.CoverageGaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}

func jsAssignmentValueID(doc jsprogram.Document, target string) string {
	for _, a := range doc.Assignments {
		for _, tref := range a.Targets {
			if joinJsRef(tref) == target {
				return a.ValueID
			}
		}
	}
	return ""
}

// jsFlowReaches reports whether a value referencing `fromName` reaches `toValueID` along the intra-procedural
// value flows (a small BFS over the flow edges).
func jsFlowReaches(doc jsprogram.Document, fromName, toValueID string) bool {
	adj := map[string][]string{}
	for _, f := range doc.Flows {
		adj[f.FromID] = append(adj[f.FromID], f.ToID)
	}
	seen := map[string]bool{}
	var queue []string
	for _, v := range doc.Values {
		if len(v.Ref.Segments) >= 1 && v.Ref.Segments[len(v.Ref.Segments)-1] == fromName {
			queue = append(queue, v.ID)
			seen[v.ID] = true
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == toValueID {
			return true
		}
		for _, nxt := range adj[cur] {
			if !seen[nxt] {
				seen[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	return false
}

func joinJsRef(ref jsprogram.Reference) string {
	out := ""
	for _, s := range ref.Segments {
		if out != "" {
			out += "."
		}
		out += s
	}
	return out
}

// TestJsFactsForDuplicateSymbolsNotRejected guards review finding 6: valid source with duplicate/overloaded
// declarations (a TS overload set, a duplicate method name) must NOT have its whole facts document rejected;
// each colliding declaration keeps a distinct, position-disambiguated symbol id.
func TestJsFactsForDuplicateSymbolsNotRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "o.ts", ""+
		"export function f(a: string): string;\n"+ // TS overload signatures (no body): not emitted as symbols
		"export function f(a: number): string;\n"+
		"export function f(a: any): string { return String(a); }\n"+
		"function g(x) { return x; }\n"+
		"function g(y) { return y; }\n"+ // a real duplicate top-level function (valid; the second shadows)
		"class C {\n"+
		"  m() { return 1; }\n"+
		"  m() { return 2; }\n"+ // a duplicate method name (valid to parse)
		"}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("valid duplicate/overloaded declarations must not be rejected: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("extracted document must validate: %v", err)
	}
	// The colliding declarations (two `g`, two `C.m`) each keep a distinct symbol rather than being dropped.
	gCount, mCount := 0, 0
	seen := map[string]bool{}
	for _, s := range doc.Symbols {
		if seen[s.ID] {
			t.Errorf("duplicate symbol id %q must not appear twice", s.ID)
		}
		seen[s.ID] = true
		if s.Name == "g" {
			gCount++
		}
		if s.Name == "m" {
			mCount++
		}
	}
	if gCount != 2 || mCount != 2 {
		t.Errorf("expected 2 g + 2 m distinct symbols, got g=%d m=%d (symbols: %+v)", gCount, mCount, doc.Symbols)
	}
}

// TestJsFactsForBoundedHostileConstruct guards review finding 5: a valid file with a construct that exceeds a
// per-item bound (a very deep member chain) still yields a VALID document, capped, rather than an emitted
// fact that fails Validate and drops every fact for the file.
func TestJsFactsForBoundedHostileConstruct(t *testing.T) {
	root := t.TempDir()
	// A multi-line member chain deeper than the 256-segment reference bound (multi-line so it is not treated
	// as generated/minified and is actually parsed).
	chain := "a"
	for i := 0; i < 300; i++ {
		chain += "\n  .b"
	}
	writeFile(t, root, "chain.js", "function f() {\n  return "+chain+";\n}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("a deep member chain must not reject the document: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("document must validate: %v", err)
	}
	if doc.FilesSeen != 1 || doc.FilesParsed != 1 {
		t.Fatalf("the file must be seen and parsed (seen=%d parsed=%d)", doc.FilesSeen, doc.FilesParsed)
	}
	for _, v := range doc.Values {
		if len(v.Ref.Segments) > 256 {
			t.Fatalf("reference segment cap breached: %d segments", len(v.Ref.Segments))
		}
	}
}

// TestJsFactsForDynamicRequireInAnyPosition guards review finding 3: require(expr) with a non-string-literal
// argument, in ANY call position, is a dependency loaded invisibly and must be a GapDynamicImport.
func TestJsFactsForDynamicRequireInAnyPosition(t *testing.T) {
	cases := map[string]string{
		"nested-in-call": "function f(m){ return wrap(require(m)); }\n",
		"module.exports": "function f(m){ module.exports = require(m); }\n",
		"member-of-req":  "function f(m){ return require(m).thing; }\n",
		"dynamic-import": "async function f(m){ return await import(m); }\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "d.js", src)
			doc, err := JsFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("JsFactsFor: %v", err)
			}
			if !hasJsGap(doc, jsprogram.GapDynamicImport) {
				t.Errorf("%s: expected GapDynamicImport; gaps=%+v", name, doc.CoverageGaps)
			}
		})
	}
	// require('literal') is a known dependency and must NOT be gapped as dynamic.
	root := t.TempDir()
	writeFile(t, root, "s.js", "const x = wrap(require('express'));\n")
	doc, _ := JsFactsFor(context.Background(), root)
	if hasJsGap(doc, jsprogram.GapDynamicImport) {
		t.Errorf("require('express') is static and must not be a dynamic-import gap; gaps=%+v", doc.CoverageGaps)
	}
}

// TestJsFactsForComputedMemberGap guards review finding 1: a computed member with a dynamic key records a
// GapDynamicAttribute (the specific property is unresolved) while a literal-key access does not.
func TestJsFactsForComputedMemberGap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "c.js", "function f(o, k){ return o[k]; }\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if !hasJsGap(doc, jsprogram.GapDynamicAttribute) {
		t.Errorf("dynamic computed key o[k] must record GapDynamicAttribute; gaps=%+v", doc.CoverageGaps)
	}

	root2 := t.TempDir()
	writeFile(t, root2, "s.js", "function f(o){ return o['name'] + o[0]; }\n")
	doc2, err := JsFactsFor(context.Background(), root2)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if hasJsGap(doc2, jsprogram.GapDynamicAttribute) {
		t.Errorf("literal-key access must NOT gap; gaps=%+v", doc2.CoverageGaps)
	}
}

// TestJsFactsForUnknownCalleeGap guards review finding 4: a call whose callee is not statically expressible
// (a computed-property call) records GapUnresolvedCall, so absence is never read as proof.
func TestJsFactsForUnknownCalleeGap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "u.js", "function f(o, k){ return o[k](); }\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if !hasJsGap(doc, jsprogram.GapUnresolvedCall) {
		t.Errorf("a computed-property call must record GapUnresolvedCall; gaps=%+v", doc.CoverageGaps)
	}
}

// TestJsFactsForByteIdenticalDeterminism confirms two extractions serialize to identical JSON bytes.
func TestJsFactsForByteIdenticalDeterminism(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.js", "const e = require('express');\nfunction h(req){ const q = `x${req.query.id}`; db.query(q); }\n")
	writeFile(t, root, "b.ts", "export class S { run(x: string) { return x; } }\n")
	first, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatalf("facts are not byte-identical across runs:\n%s\n%s", a, b)
	}
}

// TestJsFactsForDestructuringTargetsFlow guards review finding 5: object/array destructuring assignment
// targets carry the RHS flow (container-granular), so `const { a: b } = source` and `const [x, ...rest] =
// source` do not silently lose the assignment (a false negative for taint).
func TestJsFactsForDestructuringTargetsFlow(t *testing.T) {
	cases := map[string][]string{
		"const { a: b } = source":     {"b"},
		"const { a } = source":        {"a"},
		"const { a = 1 } = source":    {"a"},
		"const [x, ...rest] = source": {"x", "rest"},
		"const { p: { q } } = source": {"q"},
	}
	for src, want := range cases {
		root := t.TempDir()
		writeFile(t, root, "d.js", "function f(source){ "+src+"; }\n")
		doc, err := JsFactsFor(context.Background(), root)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		for _, w := range want {
			if !hasJsBindingTarget(doc, w) {
				t.Errorf("%s: destructured target %q must be bound to the RHS; assignments=%+v", src, w, doc.Assignments)
			}
		}
	}
}

// TestJsFactsForThisMemberWrite guards review finding 6: `this.x = value` is not dropped; it binds the
// container `this` (sound, intra-procedural, container-granular) rather than being silently lost.
func TestJsFactsForThisMemberWrite(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "t.js", "class C { m(input) { this.x = input; return this.x; } }\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if !hasJsBindingTarget(doc, "this") {
		t.Errorf("this.x = input must bind the container `this`; assignments=%+v", doc.Assignments)
	}
}

// TestJsFactsForOverlongChainIsIncomplete guards review finding 1: a member chain deeper than the reference
// bound must make the document honestly incomplete (a gap), not silently Complete().
func TestJsFactsForOverlongChainIsIncomplete(t *testing.T) {
	chain := "a"
	for i := 0; i < 300; i++ {
		chain += "\n  .b"
	}
	root := t.TempDir()
	writeFile(t, root, "ch.js", "function f() {\n  const y = "+chain+";\n  return y;\n}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("document must validate: %v", err)
	}
	if doc.Complete() {
		t.Errorf("an over-long member chain must make the document incomplete")
	}
}

// TestJsFactsForValidateNeverRejectsValidSource is the by-construction invariant: for ANY parseable JS/TS
// input, JsFactsFor either returns a document Validate ACCEPTS (possibly Complete()==false) or an error only
// for a genuine parse/IO failure. It feeds large and edge-case valid files and asserts Validate accepts.
func TestJsFactsForValidateNeverRejectsValidSource(t *testing.T) {
	deepNest := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString("function f" + itoaTest(i) + "() {\n")
		}
		b.WriteString("return 1;\n")
		for i := 0; i < n; i++ {
			b.WriteString("}\n")
		}
		return b.String()
	}
	deepChain := func(n int) string {
		s := "a"
		for i := 0; i < n; i++ {
			s += "\n.b"
		}
		return "function g(){ return " + s + "; }\n"
	}
	bigDestructure := func(n int) string {
		var names []string
		for i := 0; i < n; i++ {
			names = append(names, "k"+itoaTest(i))
		}
		return "function h(source){ const { " + strings.Join(names, ", ") + " } = source; return source; }\n"
	}

	cases := map[string]string{
		"escaped-ident":      "function \\u0066oo(){ return 1; }\n",
		"unicode-ident":      "function café(){ const naïve = 1; return naïve; }\n",
		"deep-nesting":       deepNest(300),
		"deep-member-chain":  deepChain(400),
		"big-destructure":    bigDestructure(200),
		"this-writes":        "class C { a(x){ this.a = x; } b(y){ this.b = y; return this.a; } }\n",
		"computed-members":   "function f(o, k){ o[k] = o[k+1]; return o['x'][k]; }\n",
		"duplicate-decls":    "function d(){} function d(){} class E { g(){} g(){} }\n",
		"ts-generics":        "export function id<T>(x: T): T { return x; }\nclass Box<T> { constructor(private v: T) {} get(): T { return this.v; } }\n",
		"overlong-ident":     "const " + strings.Repeat("a", 4097) + " = 1;\n",
		"overlong-specifier": "import x from '" + strings.Repeat("a", 4097) + "';\n",
		"escaped-binding":    "function f(){ const \\u0061 = source(); sink(\\u0061); }\n",
		"destructure-deflt":  "function f(){ const { x = source() } = {}; sink(x); }\n",
		"moderate-longname":  "function f(){ const " + strings.Repeat("z", 300) + " = 1;\n  return " + strings.Repeat("z", 300) + "; }\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			ext := ".js"
			if strings.Contains(name, "ts") {
				ext = ".ts"
			}
			root := t.TempDir()
			writeFile(t, root, "f"+ext, src)
			doc, err := JsFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("valid source must not error: %v", err)
			}
			if err := doc.Validate(); err != nil {
				t.Fatalf("INVARIANT VIOLATED: Validate rejected a valid-source document: %v", err)
			}
		})
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestJsFactsForEscapedBindingConnects guards review counterexample 3: an escaped-identifier binding is not
// dropped; its write and read sanitize to the same segment, so the flow connects and the doc validates.
func TestJsFactsForEscapedBindingConnects(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "e.js", "function f(){ const \\u0061 = source(); sink(\\u0061); }\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("document must validate: %v", err)
	}
	if len(doc.Assignments) == 0 {
		t.Fatalf("escaped binding must not be dropped (no assignment recorded)")
	}
	// The write's binding name and the read's reference name must be identical (consistent sanitization),
	// so PR2's name-based def-use connects them.
	bindName := ""
	for _, a := range doc.Assignments {
		for _, tref := range a.Targets {
			bindName = joinJsRef(tref)
		}
	}
	readName := false
	for _, v := range doc.Values {
		if v.Kind == jsprogram.ValueReference && len(v.Ref.Segments) == 1 && v.Ref.Segments[0] == bindName {
			readName = true
		}
	}
	if bindName == "" || !readName {
		t.Errorf("escaped write name %q must match a read reference (values: %+v)", bindName, doc.Values)
	}
}

// TestJsFactsForDestructuringDefaultFlow guards review counterexample 4: a destructuring default initializer
// flows into the bound name (so `const { x = source() } = {}` taints x), rather than being lost.
func TestJsFactsForDestructuringDefaultFlow(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "d.js", "function f(){ const { x = source() } = {}; sink(x); }\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	xBind := ""
	for _, v := range doc.Values {
		if v.Kind == jsprogram.ValueBinding && v.Name == "x" {
			xBind = v.ID
		}
	}
	if xBind == "" {
		t.Fatalf("x binding not found; values=%+v", doc.Values)
	}
	incoming := 0
	for _, fl := range doc.Flows {
		if fl.ToID == xBind {
			incoming++
		}
	}
	if incoming == 0 {
		t.Errorf("the default initializer must flow into x; flows=%+v", doc.Flows)
	}
}

// TestJsFactsForBudgetLeavesNoDanglingId guards review counterexample 5: when the fact budget is crossed
// mid-structure, no emitted fact references a value id that was not appended. Lowering the budget and
// feeding a normal file, the resulting document must still be accepted by Validate (and be incomplete).
func TestJsFactsForBudgetLeavesNoDanglingId(t *testing.T) {
	restore := jsFactBudget
	jsFactBudget = 12 // tiny, so the budget is crossed partway through the first function body
	defer func() { jsFactBudget = restore }()

	root := t.TempDir()
	writeFile(t, root, "b.js", ""+
		"function handler(req, res) {\n"+
		"  const a = req.query.id;\n"+
		"  const b = a + '-' + req.body.name;\n"+
		"  const c = { x: a, y: b };\n"+
		"  db.query(b);\n"+
		"  res.send(c);\n"+
		"  return c;\n"+
		"}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("INVARIANT VIOLATED: a budget-truncated document must still validate (no dangling id): %v", err)
	}
	if doc.Complete() {
		t.Errorf("a budget-truncated document must be incomplete")
	}
}

// TestJsFactsForOverlongImportAliasNotRejected guards the round-5 fix: an over-long import alias goes through
// the bounded segment sanitizer, so the Import fact does not exceed the validator's bound and the whole
// document is not rejected.
func TestJsFactsForOverlongImportAliasNotRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "i.js", "import "+strings.Repeat("a", 4097)+" from 'm';\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if verr := doc.Validate(); verr != nil {
		t.Fatalf("an over-long import alias must not make Validate reject the document: %v", verr)
	}
}

// TestJsFactsForComplexClassHeritageGapped guards the round-5 fix: a computed superclass (`extends
// mixin(...)`) carries calls/flows this walk does not analyze, so it is recorded as a coverage gap rather
// than silently dropped.
func TestJsFactsForComplexClassHeritageGapped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "c.js", "function mixin(x){ return class {}; }\nclass C extends mixin(taint()) {}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	found := false
	for _, g := range doc.CoverageGaps {
		if g.Kind == jsprogram.GapUnresolvedValue && g.Detail == "class_heritage" {
			found = true
		}
	}
	if !found {
		t.Errorf("a computed class heritage must be recorded as a class_heritage gap; gaps=%+v", doc.CoverageGaps)
	}
	if doc.Complete() {
		t.Errorf("a document with an unanalyzed heritage must not be Complete")
	}
}

// TestJsFactsForEscapedIdentifierDecodes guards the round-5 fix: an escaped identifier binding (a) decodes to
// its plain identifier (a), so its write segment matches a plain-spelled read and the flow connects instead
// of being silently lost. The escaped binding target must be the decoded name "a", never the raw "u0061".
func TestJsFactsForEscapedIdentifierDecodes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "e.js", "const \\u0061 = source();\nsink(a);\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if verr := doc.Validate(); verr != nil {
		t.Fatalf("Validate: %v", verr)
	}
	targetA := false
	for _, a := range doc.Assignments {
		for _, tgt := range a.Targets {
			if len(tgt.Segments) == 1 && tgt.Segments[0] == "a" {
				targetA = true
			}
			if len(tgt.Segments) == 1 && tgt.Segments[0] == "u0061" {
				t.Errorf("escaped binding must decode to \"a\", not the raw \"u0061\"")
			}
		}
	}
	if !targetA {
		t.Errorf("escaped binding \\u0061 must bind the decoded name \"a\"; assignments=%+v", doc.Assignments)
	}
}

// TestJsFactsForComputedMethodNameWalked guards the round-6 fix: a computed method name expression
// ([sink(source())]) executes at class definition, so its calls must be recorded (not silently dropped).
func TestJsFactsForComputedMethodNameWalked(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "m.js", "function source(){ return 1; }\nfunction sink(x){}\nclass C {\n  [sink(source())]() {}\n}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if verr := doc.Validate(); verr != nil {
		t.Fatalf("Validate: %v", verr)
	}
	// The computed-name expression's calls (sink, source) must appear among the recorded calls.
	sawSink, sawSource := false, false
	for _, c := range doc.Calls {
		if len(c.Callee.Segments) == 1 {
			switch c.Callee.Segments[0] {
			case "sink":
				sawSink = true
			case "source":
				sawSource = true
			}
		}
	}
	if !sawSink || !sawSource {
		t.Errorf("computed method name calls must be recorded (sink=%v source=%v); calls=%+v", sawSink, sawSource, doc.Calls)
	}
}

// TestJsFactsForDecoratorExpressionsWalked guards the round-7 fix: a class or method @decorator executes at
// definition and must have its calls recorded and any nested dynamic construct gapped, never silently dropped.
func TestJsFactsForDecoratorExpressionsWalked(t *testing.T) {
	root := t.TempDir()
	// A class decorator with a call, and a method decorator with a nested dynamic import.
	writeFile(t, root, "d.ts", ""+
		"function dec(x: any) { return x; }\n"+
		"function source() { return 1; }\n"+
		"@dec(source())\n"+
		"class C {\n"+
		"  @dec(source())\n"+
		"  m() {}\n"+
		"}\n")
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if verr := doc.Validate(); verr != nil {
		t.Fatalf("Validate: %v", verr)
	}
	sawSource := 0
	for _, c := range doc.Calls {
		if len(c.Callee.Segments) == 1 && c.Callee.Segments[0] == "source" {
			sawSource++
		}
	}
	if sawSource < 2 {
		t.Errorf("both decorator source() calls (class + method) must be recorded, saw %d; calls=%+v", sawSource, doc.Calls)
	}

	// A decorator carrying a dynamic import must produce a GapDynamicImport, not a silent drop.
	root2 := t.TempDir()
	writeFile(t, root2, "e.ts", "function dec(x: any){ return x; }\n@dec(import(name))\nclass D {}\n")
	doc2, err := JsFactsFor(context.Background(), root2)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	if !hasJsGap(doc2, jsprogram.GapDynamicImport) {
		t.Errorf("a dynamic import inside a decorator must be gapped; gaps=%+v", doc2.CoverageGaps)
	}
}

// TestJsFactsForBroadenedDynamicExecGaps guards the round-8 fix: dynamic code construction/execution is
// gapped for Function() without new, a receiver-qualified eval (globalThis.eval), and vm.runInContext.
func TestJsFactsForBroadenedDynamicExecGaps(t *testing.T) {
	cases := map[string]string{
		"Function-no-new":  "function f(s){ Function(s)(); }\n",
		"globalThis.eval":  "function f(s){ globalThis.eval(s); }\n",
		"vm.runInContext":  "const vm = require('vm');\nfunction f(s, c){ vm.runInContext(s, c); }\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "d.js", src)
			doc, err := JsFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("JsFactsFor: %v", err)
			}
			if !hasJsGap(doc, jsprogram.GapDynamicExecution) {
				t.Errorf("%s must be gapped as dynamic execution; gaps=%+v", name, doc.CoverageGaps)
			}
		})
	}
}

// TestJsFactsForChainedCallsNotRejected guards a fact-id-collision bug: a chained call (f()(), curry(a)(b))
// has an outer and inner call that share a start position, so a start-only fact id collided and made the
// whole facts document invalid. Both calls must be recorded and the document must validate.
func TestJsFactsForChainedCallsNotRejected(t *testing.T) {
	for _, src := range []string{"curry(a)(b);\n", "getHandler()(req);\n", "require('x')(cfg);\n", "a.b()();\n"} {
		root := t.TempDir()
		writeFile(t, root, "d.js", src)
		doc, err := JsFactsFor(context.Background(), root)
		if err != nil {
			t.Errorf("chained call %q must not be rejected: %v", src, err)
			continue
		}
		if verr := doc.Validate(); verr != nil {
			t.Errorf("chained call %q must validate: %v", src, verr)
		}
		if len(doc.Calls) < 2 {
			t.Errorf("chained call %q must record both calls, got %d", src, len(doc.Calls))
		}
	}
}

// TestJsFactsForIndirectEvalGapped guards the round-9 fix: eval.call / Function.apply (indirect invocation of
// dynamic code) is gapped. Deeper indirections are a documented recall limitation.
func TestJsFactsForIndirectEvalGapped(t *testing.T) {
	for _, src := range []string{"function f(s){ eval.call(null, s); }\n", "function f(s){ Function.apply(null, [s]); }\n"} {
		root := t.TempDir()
		writeFile(t, root, "d.js", src)
		doc, err := JsFactsFor(context.Background(), root)
		if err != nil {
			t.Fatalf("JsFactsFor: %v", err)
		}
		if !hasJsGap(doc, jsprogram.GapDynamicExecution) {
			t.Errorf("indirect eval %q must be gapped; gaps=%+v", src, doc.CoverageGaps)
		}
	}
}
