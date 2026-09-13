package jsprogram

import "testing"

// docBuilder assembles a valid single- or multi-module facts Document for resolver tests without the
// tree-sitter extractor. It keeps positions consistent (every symbol/call in a module shares that module's
// file) so Document.Validate passes, and every module gets its canonical "<module>" symbol.
type docBuilder struct {
	doc      Document
	moduleID map[string]string // module name -> module symbol id
	callSeq  int
}

func newDoc() *docBuilder {
	return &docBuilder{doc: Document{SchemaVersion: SchemaVersion}, moduleID: map[string]string{}}
}

func (b *docBuilder) module(name string) string {
	file := name + ".js"
	pos := Position{File: file, Line: 1}
	b.doc.Modules = append(b.doc.Modules, Module{Name: name, File: file, Pos: pos})
	id := CanonicalSymbolID(name, "<module>")
	b.doc.Symbols = append(b.doc.Symbols, Symbol{ID: id, Module: name, QualifiedName: "<module>", Name: name, Kind: SymbolModule, Pos: pos})
	b.moduleID[name] = id
	b.doc.FilesSeen++
	b.doc.FilesParsed++
	return id
}

func (b *docBuilder) fn(module, qualified, name, parentID string, kind SymbolKind) string {
	id := CanonicalSymbolID(module, qualified)
	b.doc.Symbols = append(b.doc.Symbols, Symbol{ID: id, Module: module, QualifiedName: qualified, Name: name, ParentID: parentID, Kind: kind, Pos: Position{File: module + ".js", Line: 2}})
	return id
}

func (b *docBuilder) class(module, name, parentID string, bases ...Reference) string {
	id := CanonicalSymbolID(module, name)
	b.doc.Symbols = append(b.doc.Symbols, Symbol{ID: id, Module: module, QualifiedName: name, Name: name, ParentID: parentID, Kind: SymbolClass, Pos: Position{File: module + ".js", Line: 2}, Bases: bases})
	return id
}

func (b *docBuilder) call(module, callerID string, callee Reference, isNew bool) {
	b.callSeq++
	b.doc.Calls = append(b.doc.Calls, Call{
		ID: "c" + itoa(b.callSeq), CallerID: callerID, Callee: callee, New: isNew,
		Pos: Position{File: module + ".js", Line: 3},
	})
}

func (b *docBuilder) assign(module, scopeID string, target, value Reference) {
	b.doc.Assignments = append(b.doc.Assignments, Assignment{ScopeID: scopeID, Targets: []Reference{target}, Value: value, Pos: Position{File: module + ".js", Line: 3}})
}

func (b *docBuilder) imp(module, scopeID string, kind ImportKind, specifier, name, alias string) {
	b.doc.Imports = append(b.doc.Imports, Import{ScopeID: scopeID, Kind: kind, Module: specifier, Name: name, Alias: alias, Pos: Position{File: module + ".js", Line: 1}})
}

func name(segs ...string) Reference    { return Reference{Kind: ReferenceName, Segments: segs} }
func attr(segs ...string) Reference    { return Reference{Kind: ReferenceAttribute, Segments: segs} }
func callref(segs ...string) Reference { return Reference{Kind: ReferenceCall, Segments: segs} }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func resolveOrFatal(t *testing.T, b *docBuilder) Resolution {
	t.Helper()
	res, err := Resolve(b.doc)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

func TestResolveLexicalFunctionAndTransitive(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	handler := b.fn("app", "handler", "handler", mod, SymbolFunction)
	step := b.fn("app", "step", "step", mod, SymbolFunction)
	sink := b.fn("app", "sink", "sink", mod, SymbolFunction)
	b.fn("app", "unused", "unused", mod, SymbolFunction) // defined, never called
	b.call("app", mod, name("handler"), false)           // top-level handler()
	b.call("app", handler, name("step"), false)          // handler -> step
	b.call("app", step, name("sink"), false)             // step -> sink (transitive)

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("expected complete resolution, gaps=%v", res.Gaps)
	}
	if !res.Graph.Reaches(sink) {
		t.Errorf("sink must be reachable transitively from the module entrypoint")
	}
	if res.Graph.Reaches(CanonicalSymbolID("app", "unused")) {
		t.Errorf("unused must not be reachable")
	}
}

func TestResolveThisMethodAndReceiverType(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	runner := b.class("app", "Runner", mod)
	run := b.fn("app", "Runner.run", "run", runner, SymbolMethod)
	do := b.fn("app", "Runner.do", "do", runner, SymbolMethod)
	b.fn("app", "Runner.unused", "unused", runner, SymbolMethod)
	// class Runner { run(){ this.do() } do(){...} }
	b.call("app", run, attr("this", "do"), false)
	// top level: const r = new Runner(); r.run()
	b.assign("app", mod, name("r"), callref("Runner"))
	b.call("app", mod, name("Runner"), true) // new Runner()
	b.call("app", mod, attr("r", "run"), false)

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("expected complete resolution, gaps=%v", res.Gaps)
	}
	if !res.Graph.Reaches(do) {
		t.Errorf("Runner.do must be reachable via r.run() -> this.do()")
	}
	if res.Graph.Reaches(CanonicalSymbolID("app", "Runner.unused")) {
		t.Errorf("Runner.unused is never called and must not be reachable")
	}
}

func TestResolveCrossModuleNamedImport(t *testing.T) {
	b := newDoc()
	appMod := b.module("app")
	helperMod := b.module("helper")
	work := b.fn("helper", "work", "work", helperMod, SymbolFunction)
	b.fn("helper", "unused", "unused", helperMod, SymbolFunction)
	// app: import {work} from './helper'; work()
	b.imp("app", appMod, ImportNamed, "./helper", "work", "")
	b.call("app", appMod, name("work"), false)

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("expected complete resolution, gaps=%v", res.Gaps)
	}
	if !res.Graph.Reaches(work) {
		t.Errorf("helper.work must be reachable via the named cross-module import")
	}
	if res.Graph.Reaches(CanonicalSymbolID("helper", "unused")) {
		t.Errorf("helper.unused is imported-nowhere and must not be reachable")
	}
}

func TestResolveCrossModuleNamespaceImport(t *testing.T) {
	b := newDoc()
	appMod := b.module("app")
	helperMod := b.module("helper")
	work := b.fn("helper", "work", "work", helperMod, SymbolFunction)
	// app: import * as h from './helper'; h.work()
	b.imp("app", appMod, ImportNamespace, "./helper", "", "h")
	b.call("app", appMod, attr("h", "work"), false)

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("expected complete, gaps=%v", res.Gaps)
	}
	if !res.Graph.Reaches(work) {
		t.Errorf("helper.work must be reachable via namespace import member call")
	}
}

func TestResolveImportedButUncalledIsNotReached(t *testing.T) {
	b := newDoc()
	appMod := b.module("app")
	helperMod := b.module("helper")
	work := b.fn("helper", "work", "work", helperMod, SymbolFunction)
	// app: import {work} from './helper' but never call it.
	b.imp("app", appMod, ImportNamed, "./helper", "work", "")

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("expected complete, gaps=%v", res.Gaps)
	}
	if res.Graph.Reaches(work) {
		t.Errorf("an imported-but-uncalled export must not be reachable (import != reach)")
	}
}

func TestResolveThirdPartyCallIsExternalLeafNotGap(t *testing.T) {
	b := newDoc()
	appMod := b.module("app")
	// import axios from 'axios'; axios.get() — third-party, resolves to no in-document symbol, external leaf.
	b.imp("app", appMod, ImportDefault, "axios", "default", "axios")
	b.call("app", appMod, attr("axios", "get"), false)

	res := resolveOrFatal(t, b)
	// A third-party call is an external leaf, not an unresolved gap, so a negative stays provable.
	if !res.Complete {
		t.Fatalf("a resolved third-party external call must not defeat Complete, gaps=%v", res.Gaps)
	}
}

func TestResolveUnresolvedCallDefeatsComplete(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	// A bare call to a name that is neither a local function nor an import: unresolved -> gap -> incomplete.
	b.call("app", mod, name("mysteryGlobal"), false)

	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("an unresolved call must defeat Complete so a negative is not claimed over a hole")
	}
}

func TestResolveDynamicGapFromExtractorDefeatsComplete(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	b.fn("app", "handler", "handler", mod, SymbolFunction)
	b.call("app", mod, name("handler"), false)
	// The extractor recorded a dynamic-dispatch gap (e.g. a computed member obj[name]()).
	b.doc.CoverageGaps = append(b.doc.CoverageGaps, CoverageGap{Kind: GapDynamicAttribute, SymbolID: mod, Detail: "computed_member", Pos: Position{File: "app.js", Line: 4}})

	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("an extractor dynamic-dispatch gap must force incomplete (raise-only)")
	}
	// Positive evidence still works: handler is reachable even though the document is incomplete.
	if !res.Graph.Reaches(CanonicalSymbolID("app", "handler")) {
		t.Error("positive reachability must still hold on an incomplete document")
	}
}

func TestResolveCallbackEscapeDefeatsComplete(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	cb := b.fn("app", "cb", "cb", mod, SymbolFunction)
	// items.forEach(cb) — cb is a first-party function handed to a library higher-order call, which may
	// invoke it out of view. A negative over this program is unsafe, so it must be incomplete.
	b.callSeq++
	b.doc.Calls = append(b.doc.Calls, Call{
		ID: "c1", CallerID: mod, Callee: attr("items", "forEach"),
		Arguments: []Argument{{Value: name("cb")}}, Pos: Position{File: "app.js", Line: 3},
	})
	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("a first-party callback passed to a higher-order call must force incomplete (call/apply incompleteness)")
	}
	_ = cb
}

func TestResolveTruncatedDocumentIsIncomplete(t *testing.T) {
	b := newDoc()
	b.module("app")
	b.doc.Truncated = true
	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("a truncated document can never support a negative")
	}
}
