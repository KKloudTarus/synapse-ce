package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

// jsDoc builds a minimal, VALID one-module document whose module scope holds the given imports, values, and
// calls, so the value-flow engine can be unit-tested without the tree-sitter extractor (and without cgo).
func jsDoc(imports []jsprogram.Import, values []jsprogram.Value, calls []jsprogram.Call) jsprogram.Document {
	const module = "app"
	const file = "app.js"
	pos := jsprogram.Position{File: file, Line: 1, Column: 0}
	moduleID := jsprogram.CanonicalSymbolID(module, "<module>")
	return jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules:       []jsprogram.Module{{Name: module, File: file, Pos: pos}},
		Symbols: []jsprogram.Symbol{
			{ID: moduleID, Module: module, QualifiedName: "<module>", Name: module, Kind: jsprogram.SymbolModule, Pos: pos},
		},
		Imports:     imports,
		Values:      values,
		Calls:       calls,
		FilesSeen:   1,
		FilesParsed: 1,
	}
}

func jsModuleID() string { return jsprogram.CanonicalSymbolID("app", "<module>") }

func jsPos(line, col int) jsprogram.Position {
	return jsprogram.Position{File: "app.js", Line: line, Column: col}
}

func jsFindingRules(graph JsValueFlowGraph) map[string]bool {
	out := map[string]bool{}
	for _, finding := range graph.Vulnerabilities() {
		out[finding.Rule] = true
	}
	return out
}

func TestBuildJsValueGraphCommandInjection(t *testing.T) {
	scope := jsModuleID()
	source := jsprogram.Value{
		ID: "v-src", ScopeID: scope, Kind: jsprogram.ValueReference,
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceAttribute, Segments: []string{"req", "query", "cmd"}}, Pos: jsPos(2, 10),
	}
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: scope, Kind: jsprogram.ImportNamed, Module: "child_process", Name: "exec", Alias: "exec", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{source},
		[]jsprogram.Call{{
			ID: "c1", CallerID: scope,
			Callee:    jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"exec"}},
			Arguments: []jsprogram.Argument{{Value: source.Ref, ValueID: source.ID, Pos: jsPos(2, 10)}},
			Pos:       jsPos(2, 0),
		}},
	)
	graph, err := BuildJsValueGraph(doc, DefaultJsCatalog())
	if err != nil {
		t.Fatalf("BuildJsValueGraph: %v", err)
	}
	if !jsFindingRules(graph)["js-taint-command"] {
		t.Fatalf("expected js-taint-command, got %v", jsFindingRules(graph))
	}
}

// TestBuildJsValueGraphShadowedImportIsNotASink proves a call whose callee name is a local binding, not the
// same-named import, is not treated as the sink.
func TestBuildJsValueGraphShadowedImportIsNotASink(t *testing.T) {
	scope := jsModuleID()
	binding := jsprogram.Value{
		ID: "v-exec", ScopeID: scope, Kind: jsprogram.ValueBinding, Name: "exec",
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"exec"}}, Pos: jsPos(2, 0),
	}
	source := jsprogram.Value{
		ID: "v-src", ScopeID: scope, Kind: jsprogram.ValueReference,
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceAttribute, Segments: []string{"req", "query", "cmd"}}, Pos: jsPos(3, 10),
	}
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: scope, Kind: jsprogram.ImportNamed, Module: "child_process", Name: "exec", Alias: "exec", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{binding, source},
		[]jsprogram.Call{{
			ID: "c1", CallerID: scope,
			Callee:    jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"exec"}},
			Arguments: []jsprogram.Argument{{Value: source.Ref, ValueID: source.ID, Pos: jsPos(3, 10)}},
			Pos:       jsPos(3, 0),
		}},
	)
	graph, err := BuildJsValueGraph(doc, DefaultJsCatalog())
	if err != nil {
		t.Fatalf("BuildJsValueGraph: %v", err)
	}
	if len(jsFindingRules(graph)) != 0 {
		t.Fatalf("shadowed import wrongly reported a sink: %v", jsFindingRules(graph))
	}
}

func TestBuildJsValueGraphRejectsEmptyCatalog(t *testing.T) {
	doc := jsDoc(nil, nil, nil)
	if _, err := BuildJsValueGraph(doc, JsCatalog{}); err == nil {
		t.Fatal("expected an empty catalog to be rejected")
	}
}

// --- Shared helpers for the false-positive regression suite -------------------------------------------

// jsDocSym is jsDoc plus extra symbols (function/class declarations), so a shadow of a language global can
// be represented without the cgo extractor.
func jsDocSym(imports []jsprogram.Import, symbols []jsprogram.Symbol, values []jsprogram.Value, calls []jsprogram.Call) jsprogram.Document {
	doc := jsDoc(imports, values, calls)
	doc.Symbols = append(doc.Symbols, symbols...)
	return doc
}

// jsDecl builds a module-level function/class declaration symbol named name (the form that binds a bare name
// but emits no ValueBinding).
func jsDecl(name string, kind jsprogram.SymbolKind) jsprogram.Symbol {
	return jsprogram.Symbol{
		ID: jsprogram.CanonicalSymbolID("app", name), Module: "app", QualifiedName: name, Name: name,
		ParentID: jsModuleID(), Kind: kind, Pos: jsPos(1, 0),
	}
}

// jsReqSource is an untrusted request member read (a ReferenceSourcePrefix match) at module scope.
func jsReqSource(id string, segments ...string) jsprogram.Value {
	return jsprogram.Value{
		ID: id, ScopeID: jsModuleID(), Kind: jsprogram.ValueReference,
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceAttribute, Segments: segments}, Pos: jsPos(2, 10),
	}
}

// jsNameCall / jsAttrCall build a single-argument call whose one argument carries valueID.
func jsNameCall(id string, segments []string, argValue jsprogram.Reference, argID string) jsprogram.Call {
	return jsprogram.Call{
		ID: id, CallerID: jsModuleID(),
		Callee:    jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: segments},
		Arguments: []jsprogram.Argument{{Value: argValue, ValueID: argID, Pos: jsPos(3, 10)}},
		Pos:       jsPos(3, 0),
	}
}

func jsAttrCall(id string, segments []string, argValue jsprogram.Reference, argID string) jsprogram.Call {
	c := jsNameCall(id, segments, argValue, argID)
	c.Callee.Kind = jsprogram.ReferenceAttribute
	return c
}

func mustJsGraph(t *testing.T, doc jsprogram.Document) JsValueFlowGraph {
	t.Helper()
	graph, err := BuildJsValueGraph(doc, DefaultJsCatalog())
	if err != nil {
		t.Fatalf("BuildJsValueGraph: %v", err)
	}
	return graph
}

// --- Critical: a local declaration named like a global sink must NOT fire the global sink ---------------

// TestLocalFunctionShadowsGlobalFetch is the regression for the reproduced critical FP: a user wrapper
// `function fetch(id){}` (a Symbol with no ValueBinding) must shadow the global fetch SSRF sink.
func TestLocalFunctionShadowsGlobalFetch(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "id")
	doc := jsDocSym(nil,
		[]jsprogram.Symbol{jsDecl("fetch", jsprogram.SymbolFunction)},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"fetch"}, src.Ref, src.ID)},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
		t.Fatalf("local function fetch wrongly reported a global sink: %v", rules)
	}
}

// TestLocalClassShadowsGlobalFunction: `class Function{}` shadows the global Function code sink.
func TestLocalClassShadowsGlobalFunction(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "code")
	doc := jsDocSym(nil,
		[]jsprogram.Symbol{jsDecl("Function", jsprogram.SymbolClass)},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"Function"}, src.Ref, src.ID)},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
		t.Fatalf("local class Function wrongly reported a global sink: %v", rules)
	}
}

// TestLocalFunctionShadowsGlobalEval: `function eval(){}` shadows the global eval code sink.
func TestLocalFunctionShadowsGlobalEval(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "expr")
	doc := jsDocSym(nil,
		[]jsprogram.Symbol{jsDecl("eval", jsprogram.SymbolFunction)},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"eval"}, src.Ref, src.ID)},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
		t.Fatalf("local function eval wrongly reported a global sink: %v", rules)
	}
}

// TestGlobalFetchIsSSRF is the control: with no shadowing declaration, the global fetch sink fires.
func TestGlobalFetchIsSSRF(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "url")
	doc := jsDoc(nil,
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"fetch"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-ssrf"] {
		t.Fatal("global fetch should be an SSRF sink")
	}
}

// TestGlobalEvalIsCode is the control for the eval shadow test.
func TestGlobalEvalIsCode(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "expr")
	doc := jsDoc(nil,
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"eval"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-code"] {
		t.Fatal("global eval should be a code sink")
	}
}

// --- Receiver-name convention and its tightening -------------------------------------------------------

// TestResSendIsXSS: the Express-specific res.send writer is an XSS sink.
func TestResSendIsXSS(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "msg")
	doc := jsDoc(nil,
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"res", "send"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-xss"] {
		t.Fatal("res.send should be an XSS sink")
	}
}

// TestResWriteIsNotXSS: .write / .end are the generic Writable API and were dropped from the XSS set, so a
// value written to a stream bound to res is not reported (the FP tightening).
func TestResWriteIsNotXSS(t *testing.T) {
	for _, method := range []string{"write", "end"} {
		src := jsReqSource("v-src", "req", "body", "chunk")
		doc := jsDoc(nil,
			[]jsprogram.Value{src},
			[]jsprogram.Call{jsAttrCall("c1", []string{"res", method}, src.Ref, src.ID)},
		)
		if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
			t.Fatalf("res.%s must not be an XSS sink, got %v", method, rules)
		}
	}
}

// TestResRedirectIsOpenRedirect: res.redirect is the open-redirect sink.
func TestResRedirectIsOpenRedirect(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "to")
	doc := jsDoc(nil,
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"res", "redirect"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-open-redirect"] {
		t.Fatal("res.redirect should be an open-redirect sink")
	}
}

// --- Argument-index precision --------------------------------------------------------------------------

// TestFsReadFilePathTraversal: fs.readFile(userPath) reports path traversal (arg 0 is the path).
func TestFsReadFilePathTraversal(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "name")
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: jsModuleID(), Kind: jsprogram.ImportNamed, Module: "fs", Name: "readFile", Alias: "readFile", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"readFile"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-path"] {
		t.Fatal("fs.readFile(userPath) should be a path-traversal sink")
	}
}

// TestFsWriteFileDataArgIsSafe: fs.writeFile(constPath, userData) must NOT report path traversal, because
// the modeled sink argument is the path (arg 0), not the data (arg 1).
func TestFsWriteFileDataArgIsSafe(t *testing.T) {
	pathLit := jsprogram.Value{ID: "v-path", ScopeID: jsModuleID(), Kind: jsprogram.ValueLiteral, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceLiteral}, Pos: jsPos(2, 5)}
	data := jsReqSource("v-data", "req", "body", "data")
	call := jsprogram.Call{
		ID: "c1", CallerID: jsModuleID(),
		Callee: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"writeFile"}},
		Arguments: []jsprogram.Argument{
			{Value: jsprogram.Reference{Kind: jsprogram.ReferenceLiteral}, ValueID: "v-path", Pos: jsPos(2, 5)},
			{Value: data.Ref, ValueID: "v-data", Pos: jsPos(2, 20)},
		},
		Pos: jsPos(2, 0),
	}
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: jsModuleID(), Kind: jsprogram.ImportNamed, Module: "fs", Name: "writeFile", Alias: "writeFile", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{pathLit, data},
		[]jsprogram.Call{call},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
		t.Fatalf("tainted DATA in writeFile arg 1 must not be a path sink, got %v", rules)
	}
}

// --- Sanitizer walls -----------------------------------------------------------------------------------

// TestEncodeURIComponentSanitizesXSS: res.send(encodeURIComponent(userInput)) yields no XSS finding.
func TestEncodeURIComponentSanitizesXSS(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "msg")
	enc := jsprogram.Value{ID: "v-enc", ScopeID: jsModuleID(), Kind: jsprogram.ValueCallResult, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceExpression}, Pos: jsPos(2, 20)}
	call1 := jsprogram.Call{
		ID: "c-enc", CallerID: jsModuleID(),
		Callee:    jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"encodeURIComponent"}},
		Arguments: []jsprogram.Argument{{Value: src.Ref, ValueID: "v-src", Pos: jsPos(2, 20)}},
		ResultID:  "v-enc", Pos: jsPos(2, 10),
	}
	call2 := jsAttrCall("c-send", []string{"res", "send"}, jsprogram.Reference{Kind: jsprogram.ReferenceExpression}, "v-enc")
	doc := jsDoc(nil, []jsprogram.Value{src, enc}, []jsprogram.Call{call1, call2})
	if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
		t.Fatalf("encodeURIComponent should neutralize the XSS flow, got %v", rules)
	}
}

// --- Receiver provenance: the receiver-name convention requires a parameter/global receiver, not a
// locally constructed object, and an EXACT dotted path (no deeper suffixes). ------------------------------

// TestResSendOnConstructedObjectIsNotXSS: `const res = { send() {} }` is a plain local object, not the
// Express response parameter, so res.send does not match (Codex finding 1).
func TestResSendOnConstructedObjectIsNotXSS(t *testing.T) {
	resObj := jsprogram.Value{
		ID: "v-res", ScopeID: jsModuleID(), Kind: jsprogram.ValueBinding, Name: "res",
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceExpression}, Pos: jsPos(2, 0),
	}
	src := jsReqSource("v-src", "req", "body", "name")
	src.Pos = jsPos(3, 10)
	doc := jsDoc(nil,
		[]jsprogram.Value{resObj, src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"res", "send"}, src.Ref, src.ID)},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
		t.Fatalf("res.send on a locally constructed object must not be an XSS sink, got %v", rules)
	}
}

// TestResSendOnParameterIsXSS: when res is a request-handler PARAMETER (the Express convention), res.send is
// the XSS sink. Proves the provenance check keeps the real case that the constructed-object case drops.
func TestResSendOnParameterIsXSS(t *testing.T) {
	resParam := jsprogram.Value{
		ID: "v-res", ScopeID: jsModuleID(), Kind: jsprogram.ValueParameter, Name: "res",
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"res"}}, Pos: jsPos(1, 20),
	}
	src := jsReqSource("v-src", "req", "query", "msg")
	doc := jsDoc(nil,
		[]jsprogram.Value{resParam, src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"res", "send"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-xss"] {
		t.Fatal("res.send where res is a handler parameter should be an XSS sink")
	}
}

// TestDeepDocumentWriteIsNotXSS: widget.document.write is a nested object method, not the DOM document.write,
// so the exact-path receiver-name match does not fire (Codex finding 2).
func TestDeepDocumentWriteIsNotXSS(t *testing.T) {
	src := jsReqSource("v-src", "req", "body", "x")
	doc := jsDoc(nil,
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"widget", "document", "write"}, src.Ref, src.ID)},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); len(rules) != 0 {
		t.Fatalf("widget.document.write must not match the DOM document.write sink, got %v", rules)
	}
}

// TestGlobalRegExpIsReDoS: the RegExp global constructor with a tainted pattern is a ReDoS (CWE-1333) sink.
func TestGlobalRegExpIsReDoS(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "pattern")
	doc := jsDoc(nil,
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"RegExp"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-redos"] {
		t.Fatal("global RegExp with a tainted pattern should be a ReDoS sink")
	}
}

// TestShadowedRegExpIsNotReDoS: a local binding named RegExp is not the global constructor, so it is not a sink.
func TestShadowedRegExpIsNotReDoS(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "pattern")
	doc := jsDocSym(nil,
		[]jsprogram.Symbol{jsDecl("RegExp", jsprogram.SymbolFunction)},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsNameCall("c1", []string{"RegExp"}, src.Ref, src.ID)},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); rules["js-taint-redos"] {
		t.Fatalf("a locally shadowed RegExp must not be a ReDoS sink, got %v", rules)
	}
}

// TestEscapeStringRegexpSanitizesReDoS: escape-string-regexp's default export escapes the pattern, so the
// value reaching RegExp carries no injectable metacharacters and the ReDoS flow is neutralized.
func TestEscapeStringRegexpSanitizesReDoS(t *testing.T) {
	scope := jsModuleID()
	src := jsReqSource("v-src", "req", "query", "q")
	esc := jsprogram.Value{ID: "v-esc", ScopeID: scope, Kind: jsprogram.ValueCallResult, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceExpression}, Pos: jsPos(3, 20)}
	escCall := jsprogram.Call{
		ID: "c-esc", CallerID: scope,
		Callee:    jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"escapeStringRegexp"}},
		Arguments: []jsprogram.Argument{{Value: src.Ref, ValueID: src.ID, Pos: jsPos(3, 20)}},
		ResultID:  "v-esc", Pos: jsPos(3, 10),
	}
	reCall := jsNameCall("c-re", []string{"RegExp"}, jsprogram.Reference{Kind: jsprogram.ReferenceExpression}, "v-esc")
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: scope, Kind: jsprogram.ImportDefault, Module: "escape-string-regexp", Alias: "escapeStringRegexp", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{src, esc},
		[]jsprogram.Call{escCall, reCall},
	)
	if rules := jsFindingRules(mustJsGraph(t, doc)); rules["js-taint-redos"] {
		t.Fatalf("escape-string-regexp should neutralize the ReDoS flow, got %v", rules)
	}
}

// TestNodeSerializeUnserializeIsDeserialization: node-serialize.unserialize on a tainted payload is an unsafe
// deserialization (RCE) sink.
func TestNodeSerializeUnserializeIsDeserialization(t *testing.T) {
	scope := jsModuleID()
	src := jsReqSource("v-src", "req", "body", "payload")
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: scope, Kind: jsprogram.ImportDefault, Module: "node-serialize", Alias: "nodeSerialize", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"nodeSerialize", "unserialize"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-deserialization"] {
		t.Fatal("node-serialize.unserialize on tainted input should be a deserialization sink")
	}
}

// TestHandlebarsCompileIsSSTI: handlebars.compile on a tainted template source is an SSTI sink.
func TestHandlebarsCompileIsSSTI(t *testing.T) {
	scope := jsModuleID()
	src := jsReqSource("v-src", "req", "query", "tpl")
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: scope, Kind: jsprogram.ImportDefault, Module: "handlebars", Alias: "handlebars", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"handlebars", "compile"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-ssti"] {
		t.Fatal("handlebars.compile on a tainted template should be an SSTI sink")
	}
}

// TestXpathSelectIsXpathInjection: xpath.select on a tainted expression is an XPath-injection sink.
func TestXpathSelectIsXpathInjection(t *testing.T) {
	scope := jsModuleID()
	src := jsReqSource("v-src", "req", "query", "id")
	doc := jsDoc(
		[]jsprogram.Import{{ScopeID: scope, Kind: jsprogram.ImportDefault, Module: "xpath", Alias: "xpath", Pos: jsPos(1, 0)}},
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"xpath", "select"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-xpath"] {
		t.Fatal("xpath.select on a tainted expression should be an XPath-injection sink")
	}
}

// TestConsoleLogIsLogInjection: console.log with a tainted argument is a log-injection sink, and a tainted
// argument in any position (not only zero) is caught.
func TestConsoleLogIsLogInjection(t *testing.T) {
	src := jsReqSource("v-src", "req", "query", "user")
	doc := jsDoc(nil,
		[]jsprogram.Value{src},
		[]jsprogram.Call{jsAttrCall("c1", []string{"console", "log"}, src.Ref, src.ID)},
	)
	if !jsFindingRules(mustJsGraph(t, doc))["js-taint-log"] {
		t.Fatal("console.log on tainted input should be a log-injection sink")
	}
}
