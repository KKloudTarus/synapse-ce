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
	leaf := name
	if i := lastSlash(name); i >= 0 {
		leaf = name[i+1:]
	}
	b.doc.Symbols = append(b.doc.Symbols, Symbol{ID: id, Module: name, QualifiedName: "<module>", Name: leaf, Kind: SymbolModule, Pos: pos})
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

func (b *docBuilder) positionalParams(symbolID string, names ...string) {
	for index := range b.doc.Symbols {
		if b.doc.Symbols[index].ID != symbolID {
			continue
		}
		for _, name := range names {
			b.doc.Symbols[index].Parameters = append(b.doc.Symbols[index].Parameters, Parameter{
				Name: name, Kind: ParameterPositional, Pos: b.doc.Symbols[index].Pos,
			})
		}
		return
	}
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

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

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
	// The external call now carries a canonical leaf node so a consumer can ask whether first-party code
	// reaches a call into the package. The call is at module top level (an entrypoint), so it is reached.
	if !res.Graph.Reaches(ExternalSymbolID("axios", "default.get")) {
		t.Errorf("a first-party call into a third-party package must reach its external node")
	}
	// The external node is a leaf in edges, never a first-party Positions entry.
	if _, ok := res.Graph.Positions[ExternalSymbolID("axios", "default.get")]; ok {
		t.Errorf("an external node must not appear in Positions (first-party namespace only)")
	}
}

func TestResolveExternalImportReachabilityByKind(t *testing.T) {
	// A named and a namespace/require third-party import each resolve their call into a distinct external
	// node under the package specifier, reachable when the calling first-party code is reached.
	t.Run("named", func(t *testing.T) {
		b := newDoc()
		appMod := b.module("app")
		b.imp("app", appMod, ImportNamed, "lodash", "template", "")
		b.call("app", appMod, name("template"), false)
		res := resolveOrFatal(t, b)
		if !res.Complete {
			t.Fatalf("named third-party import call must stay complete, gaps=%v", res.Gaps)
		}
		if !res.Graph.Reaches(ExternalSymbolID("lodash", "template")) {
			t.Errorf("a reached call to a named third-party export must reach jsnpm:lodash:template")
		}
	})
	t.Run("namespace member", func(t *testing.T) {
		b := newDoc()
		appMod := b.module("app")
		b.imp("app", appMod, ImportNamespace, "lodash", "", "_")
		b.call("app", appMod, attr("_", "merge"), false)
		res := resolveOrFatal(t, b)
		if !res.Complete {
			t.Fatalf("namespace third-party member call must stay complete, gaps=%v", res.Gaps)
		}
		if !res.Graph.Reaches(ExternalSymbolID("lodash", "merge")) {
			t.Errorf("a reached namespace member call must reach jsnpm:lodash:merge")
		}
	})
	t.Run("destructured require", func(t *testing.T) {
		// const { template } = require('lodash'); template() — the extractor emits ImportRequire carrying the
		// binding name, so a bare call must still resolve to a named external export, not be dropped.
		b := newDoc()
		appMod := b.module("app")
		b.imp("app", appMod, ImportRequire, "lodash", "template", "template")
		b.call("app", appMod, name("template"), false)
		res := resolveOrFatal(t, b)
		if !res.Graph.Reaches(ExternalSymbolID("lodash", "template")) {
			t.Errorf("a destructured require call must reach jsnpm:lodash:template")
		}
	})
	t.Run("uncalled import is not reached", func(t *testing.T) {
		b := newDoc()
		appMod := b.module("app")
		b.imp("app", appMod, ImportNamed, "lodash", "template", "")
		// imported but never called: no external node reached (import != reach).
		res := resolveOrFatal(t, b)
		if res.Graph.Reaches(ExternalSymbolID("lodash", "template")) {
			t.Errorf("an imported-but-uncalled third-party export must not be reachable")
		}
	})
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

func TestResolveDirectLocalFunctionAlias(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	target := b.fn("app", "target", "target", mod, SymbolFunction)
	b.assign("app", mod, name("alias"), name("target"))
	b.call("app", mod, name("alias"), false)

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("a unique preceding direct alias must resolve completely, gaps=%v", res.Gaps)
	}
	if !res.Graph.Reaches(target) {
		t.Fatal("target must be reached through a direct local alias")
	}
}

func TestResolveUniqueSynchronousCallback(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	entry := b.fn("app", "entry", "entry", mod, SymbolFunction)
	invoke := b.fn("app", "invoke", "invoke", mod, SymbolFunction)
	b.positionalParams(invoke, "callback")
	target := b.fn("app", "target", "target", mod, SymbolFunction)
	b.call("app", mod, name("entry"), false)
	b.call("app", entry, name("invoke"), false)
	b.doc.Calls[len(b.doc.Calls)-1].Arguments = []Argument{{Value: name("target")}}
	b.call("app", invoke, name("callback"), false)

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("a uniquely bound synchronous callback must resolve completely, gaps=%v", res.Gaps)
	}
	if !res.Graph.Reaches(target) {
		t.Fatal("target must be reached through invoke -> callback")
	}
}

func TestResolveAmbiguousSynchronousCallbackBindingDefeatsComplete(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	invoke := b.fn("app", "invoke", "invoke", mod, SymbolFunction)
	b.positionalParams(invoke, "callback")
	first := b.fn("app", "first", "first", mod, SymbolFunction)
	b.fn("app", "second", "second", mod, SymbolFunction)
	b.call("app", mod, name("invoke"), false)
	b.doc.Calls[len(b.doc.Calls)-1].Arguments = []Argument{{Value: name("first")}}
	b.call("app", mod, name("invoke"), false)
	b.doc.Calls[len(b.doc.Calls)-1].Arguments = []Argument{{Value: name("second")}}
	b.call("app", invoke, name("callback"), false)

	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("a callback parameter bound to different direct callables must remain incomplete")
	}
	if res.Graph.Reaches(first) {
		t.Fatal("an ambiguously bound callback must not create a first-callback edge")
	}
}

func TestResolveStaticallyUniqueReturnedCallable(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	target := b.fn("app", "target", "target", mod, SymbolFunction)
	factory := b.fn("app", "factory", "factory", mod, SymbolFunction)
	b.doc.Returns = append(b.doc.Returns, Return{ScopeID: factory, Value: name("target"), Pos: Position{File: "app.js", Line: 3}})
	b.call("app", mod, callref("factory"), false)

	res := resolveOrFatal(t, b)
	if !res.Complete {
		t.Fatalf("a factory with one direct callable return must resolve completely, gaps=%v", res.Gaps)
	}
	if !res.Graph.Reaches(target) {
		t.Fatal("target must be reached through factory()()")
	}
}

func TestResolveAliasedReturnedCallableDefeatsComplete(t *testing.T) {
	b := newDoc()
	mod := b.module("app")
	target := b.fn("app", "target", "target", mod, SymbolFunction)
	factory := b.fn("app", "factory", "factory", mod, SymbolFunction)
	b.assign("app", factory, name("alias"), name("target"))
	b.doc.Returns = append(b.doc.Returns, Return{ScopeID: factory, Value: name("alias"), Pos: Position{File: "app.js", Line: 4}})
	b.call("app", mod, callref("factory"), false)

	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("an aliased returned callable must remain incomplete")
	}
	if res.Graph.Reaches(target) {
		t.Fatal("an aliased returned callable must not create a target edge")
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

func TestResolveVirtualDispatchDownwardClosure(t *testing.T) {
	// class Base { run(){ this.step() } step(){} }  class Derived extends Base { step(){} }
	// new Derived().run() must reach Derived.step (the override), not only Base.step.
	b := newDoc()
	mod := b.module("app")
	base := b.class("app", "Base", mod)
	baseRun := b.fn("app", "Base.run", "run", base, SymbolMethod)
	b.fn("app", "Base.step", "step", base, SymbolMethod)
	derived := b.class("app", "Derived", mod, name("Base"))
	derivedStep := b.fn("app", "Derived.step", "step", derived, SymbolMethod)
	b.call("app", baseRun, attr("this", "step"), false)
	b.assign("app", mod, name("d"), callref("Derived"))
	b.call("app", mod, name("Derived"), true)
	b.call("app", mod, attr("d", "run"), false)

	res := resolveOrFatal(t, b)
	if !res.Graph.Reaches(derivedStep) {
		t.Errorf("Derived.step override must be reachable via this.step() downward closure")
	}
}

func TestResolveSuperResolvesToBase(t *testing.T) {
	// class Base { step(){} }  class Derived extends Base { step(){ super.step() } }  new Derived().step()
	// Base.step is reachable ONLY through super and must be reached.
	b := newDoc()
	mod := b.module("app")
	base := b.class("app", "Base", mod)
	baseStep := b.fn("app", "Base.step", "step", base, SymbolMethod)
	derived := b.class("app", "Derived", mod, name("Base"))
	derivedStep := b.fn("app", "Derived.step", "step", derived, SymbolMethod)
	b.call("app", derivedStep, attr("super", "step"), false)
	b.assign("app", mod, name("d"), callref("Derived"))
	b.call("app", mod, name("Derived"), true)
	b.call("app", mod, attr("d", "step"), false)

	res := resolveOrFatal(t, b)
	if !res.Graph.Reaches(baseStep) {
		t.Errorf("Base.step must be reachable via super.step()")
	}
}

func TestResolveMemberCallbackEscapeDefeatsComplete(t *testing.T) {
	// class Svc { run(){ dispatch(this.onEvent) } onEvent(){} }  a first-party method handed to a dispatcher
	// escapes, so a negative is unsafe: the document must be incomplete.
	b := newDoc()
	mod := b.module("app")
	b.fn("app", "dispatch", "dispatch", mod, SymbolFunction)
	svc := b.class("app", "Svc", mod)
	run := b.fn("app", "Svc.run", "run", svc, SymbolMethod)
	b.fn("app", "Svc.onEvent", "onEvent", svc, SymbolMethod)
	b.callSeq++
	b.doc.Calls = append(b.doc.Calls, Call{
		ID: "c1", CallerID: run, Callee: name("dispatch"),
		Arguments: []Argument{{Value: attr("this", "onEvent")}}, Pos: Position{File: "app.js", Line: 3},
	})
	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("a first-party method passed as a callback must force incomplete (member-ref escape)")
	}
}

func TestResolveReturnedFunctionCallDefeatsComplete(t *testing.T) {
	// function vuln(){}  function f(){ return vuln }  f()()  — the outer call invokes f's RETURN value, not
	// f. The resolver must not pin it to f (which would leave vuln unreached with a "complete" proof); it
	// records an unresolved-call gap.
	b := newDoc()
	mod := b.module("app")
	b.fn("app", "vuln", "vuln", mod, SymbolFunction)
	b.fn("app", "f", "f", mod, SymbolFunction)
	// f()() : the outer call's callee is a ReferenceCall over "f".
	b.callSeq++
	b.doc.Calls = append(b.doc.Calls, Call{ID: "c1", CallerID: mod, Callee: callref("f"), Pos: Position{File: "app.js", Line: 3}})
	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("invoking a returned function f()() must force incomplete, not resolve to the factory")
	}
	if res.Graph.Reaches(CanonicalSymbolID("app", "vuln")) {
		t.Error("vuln is not statically reached; it must not be a false-positive edge")
	}
}

func TestResolvePropertyEscapeDefeatsComplete(t *testing.T) {
	// import bus from 'bus'; function vuln(){}; bus.handler = vuln; bus.start(); — vuln is stored on an
	// external object that may invoke it, so a negative is unsafe.
	b := newDoc()
	mod := b.module("app")
	b.fn("app", "vuln", "vuln", mod, SymbolFunction)
	b.imp("app", mod, ImportDefault, "bus", "default", "bus")
	b.assign("app", mod, attr("bus", "handler"), name("vuln"))
	b.call("app", mod, attr("bus", "start"), false)
	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("a first-party function assigned to an external property must force incomplete")
	}
}

func TestResolveUnresolvedFirstPartyImportIsGapNotExternal(t *testing.T) {
	// import {work} from './missing'; work() — a first-party relative import to a module not in the analyzed
	// set is a hole (the file may exist), so it must be an unresolved-call gap, not a silent external leaf.
	b := newDoc()
	mod := b.module("app")
	b.imp("app", mod, ImportNamed, "./missing", "work", "")
	b.call("app", mod, name("work"), false)
	res := resolveOrFatal(t, b)
	if res.Complete {
		t.Fatal("an unresolved first-party relative import must force incomplete, not be treated as external")
	}
}

func TestResolveDirectoryIndexImportResolves(t *testing.T) {
	// import {work} from './helper'; work() where the module is helper/index (Node directory import).
	b := newDoc()
	appMod := b.module("app")
	helperIndex := b.module("helper/index")
	work := b.fn("helper/index", "work", "work", helperIndex, SymbolFunction)
	b.imp("app", appMod, ImportNamed, "./helper", "work", "")
	b.call("app", appMod, name("work"), false)
	res := resolveOrFatal(t, b)
	if !res.Graph.Reaches(work) {
		t.Errorf("./helper must resolve to helper/index via the directory-import fallback")
	}
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
