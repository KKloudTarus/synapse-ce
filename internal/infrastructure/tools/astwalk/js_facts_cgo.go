//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"

	sitter "github.com/smacker/go-tree-sitter"
)

// jsFactBudget is the total-fact budget the extractor stops at. It is a var (not a const) ONLY so a test
// can lower it to exercise the mid-structure budget path; production always uses maxJsFacts.
var jsFactBudget = maxJsFacts

const (
	maxJsFactNodes = 2_000_000
	maxJsFacts     = 4_000_000

	// Per-item bounds mirror the jsprogram domain validator, enforced INSIDE the emitters so a hostile huge
	// expression/arg-list/param-list/destructuring never produces a fact that would fail Validate and reject
	// the whole document. Exceeding a bound records a GapBudget (so Complete() is false) and stops that item.
	maxJsRefSegments = 256
	maxJsParams      = 1_024
	maxJsArgs        = 4_096
	maxJsTargets     = 4_096
	maxJsNameBytes   = 256   // a symbol name longer than this is sanitized (Validate caps at 4096)
	maxJsQualBytes   = 3_000 // a qualified name longer than this collapses to a flat synthetic name
	maxJsSegBytes    = 256   // a reference segment / value name longer than this is sanitized
	maxJsSpecBytes   = 1_024 // an import specifier longer than this is skipped with a gap
)

// JsFactsFor extracts a bounded, versioned JavaScript/TypeScript semantic-facts document without importing
// or executing target code. Parser recovery and unresolved dynamic shapes (eval, dynamic import,
// computed reflection) are explicit coverage gaps. Subscript/member and object/array literals are tracked
// at CONTAINER granularity, never field-sensitively, so a value-flow read is conservative (no false
// negative it could turn into an unsound "not detected").
func JsFactsFor(ctx context.Context, root string) (jsprogram.Document, error) {
	doc := jsprogram.Document{SchemaVersion: jsprogram.SchemaVersion}
	modules := map[string]bool{}
	walkTruncated, err := walkSourceWithIssues(ctx, root, func(rel, lang string, content []byte) {
		grammar, ok := jsGrammarFor(rel, lang)
		if !ok {
			return
		}
		doc.FilesSeen++
		rel = filepath.ToSlash(rel)
		module, ok := jsModuleName(rel)
		if !ok {
			doc.CoverageGaps = append(doc.CoverageGaps, jsprogram.CoverageGap{
				Kind: jsprogram.GapUnresolvedImport, Detail: "invalid_module_path", Pos: jsprogram.Position{File: rel, Line: 1},
			})
			return
		}
		if modules[module] {
			doc.CoverageGaps = append(doc.CoverageGaps, jsprogram.CoverageGap{
				Kind: jsprogram.GapUnresolvedImport, Detail: "ambiguous_module_path", Pos: jsprogram.Position{File: rel, Line: 1},
			})
			return
		}
		modules[module] = true
		rootNode := parseRoot(ctx, grammar, content)
		if rootNode == nil {
			doc.CoverageGaps = append(doc.CoverageGaps, jsprogram.CoverageGap{
				Kind: jsprogram.GapParseRecovery, Detail: "parse_failed", Pos: jsprogram.Position{File: rel, Line: 1},
			})
			return
		}
		doc.FilesParsed++
		modulePos := jsprogram.Position{File: rel, Line: 1}
		moduleID := jsprogram.CanonicalSymbolID(module, "<module>")
		doc.Modules = append(doc.Modules, jsprogram.Module{Name: module, File: rel, Pos: modulePos})
		doc.Symbols = append(doc.Symbols, jsprogram.Symbol{
			ID: moduleID, Module: module, QualifiedName: "<module>", Name: jsModuleLeaf(module), Kind: jsprogram.SymbolModule, Pos: modulePos,
		})
		doc.Entrypoints = append(doc.Entrypoints, jsprogram.EntrypointHint{SymbolID: moduleID, Kind: "module_import", Pos: modulePos})
		extractor := jsFactExtractor{
			doc: &doc, module: module, file: rel, source: content,
			values: map[string]bool{}, flows: map[string]bool{},
		}
		if rootNode.HasError() {
			extractor.gap(jsprogram.GapParseRecovery, moduleID, "parser_recovery", rootNode)
		}
		extractor.walk(rootNode, jsScope{id: moduleID, qualified: "", kind: jsprogram.SymbolModule})
	}, func(issue sourceIssue) {
		// The shared walker only reports issues for python-shaped files; a JS file that is oversized or
		// unreadable is simply not visited. That is a coverage-recall limitation (a missed file), never a
		// soundness one, so it needs no gap here.
	})
	if err != nil {
		return jsprogram.Document{}, err
	}
	if walkTruncated {
		doc.Truncated = true
		doc.CoverageGaps = append(doc.CoverageGaps, jsprogram.CoverageGap{Kind: jsprogram.GapBudget, Detail: "file_budget"})
	}
	doc.SortCanonical()
	if err := doc.Validate(); err != nil {
		return jsprogram.Document{}, fmt.Errorf("validate extracted js facts: %w", err)
	}
	return doc, nil
}

// jsGrammarFor picks the tree-sitter grammar for a JS-family file. It re-derives the language from the
// EXTENSION because enry mislabels a bare `.ts` file (ambiguous with XML/typescript); a non-JS file returns
// ok=false so JsFactsFor skips it.
func jsGrammarFor(rel, lang string) (spec, bool) {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".ts", ".cts", ".mts":
		return specs["TypeScript"], true
	case ".tsx":
		return specs["TSX"], true
	case ".js", ".jsx", ".mjs", ".cjs":
		return specs["JavaScript"], true
	}
	switch lang {
	case "JavaScript":
		return specs["JavaScript"], true
	case "TypeScript":
		return specs["TypeScript"], true
	case "TSX":
		return specs["TSX"], true
	}
	return spec{}, false
}

type jsScope struct {
	id        string
	qualified string
	kind      jsprogram.SymbolKind
}

type jsFactExtractor struct {
	doc        *jsprogram.Document
	module     string
	file       string
	source     []byte
	budgetHit  bool
	values     map[string]bool
	flows      map[string]bool
	symbolQual map[string]bool // qualified names already emitted in this module, to disambiguate duplicates
}

// boundedQualified builds a unique, length-bounded qualified name from a parent scope and a (possibly
// invalid or over-long) declaration name. The name is sanitized to a valid identifier, and a qualified name
// that would exceed the string bound (a pathologically deep nesting) collapses to a flat synthetic name.
// This keeps every symbol fact acceptable to Validate by construction.
func (e *jsFactExtractor) boundedQualified(parentQual, name string, node *sitter.Node) string {
	q := joinJsQualified(parentQual, e.safeName(name, node))
	if len(q) > maxJsQualBytes {
		q = "<fn@" + e.posSuffix(node) + ">"
	}
	return e.uniqueQualified(q, node)
}

// safeName returns a valid JS identifier for a declaration name. A synthetic arrow/anon name ("<fn@..>") is
// returned unchanged; a name that is already a valid, bounded identifier is kept; anything else (an escaped
// identifier, a non-identifier character, an over-long name) is reduced to its valid leading characters, or
// to a deterministic position-based fallback, so the symbol fact is never rejected by Validate.
func (e *jsFactExtractor) safeName(name string, node *sitter.Node) string {
	if strings.HasPrefix(name, "<fn@") {
		return name
	}
	name = jsDecodeIdentEscapes(name) // an escaped declaration name decodes to its plain identifier
	if jsValidSegment(name) && len(name) <= maxJsNameBytes {
		return name
	}
	var b strings.Builder
	for _, r := range name {
		if b.Len() >= 48 {
			break
		}
		first := b.Len() == 0
		if r == '_' || r == '$' || unicode.IsLetter(r) || (!first && unicode.IsDigit(r)) {
			b.WriteRune(r)
		}
	}
	if out := b.String(); jsValidSegment(out) {
		return out
	}
	return "_id" + e.posSuffix(node)
}

// uniqueQualified returns qualified unless it has already been used in this module, in which case it appends
// a position suffix ("Name@line_col") so a duplicate/overloaded declaration keeps a distinct symbol id rather
// than colliding and getting the whole document rejected by Validate. Position is unique per declaration.
func (e *jsFactExtractor) uniqueQualified(qualified string, node *sitter.Node) string {
	if e.symbolQual == nil {
		e.symbolQual = map[string]bool{}
	}
	candidate := qualified
	if e.symbolQual[candidate] {
		candidate = qualified + "@" + e.posSuffix(node)
		for i := 1; e.symbolQual[candidate]; i++ {
			candidate = qualified + "@" + e.posSuffix(node) + strconv.Itoa(i)
		}
	}
	e.symbolQual[candidate] = true
	return candidate
}

func (e *jsFactExtractor) walk(node *sitter.Node, scope jsScope) {
	if node == nil || e.budgetHit {
		return
	}
	e.doc.NodesSeen++
	if e.factsExhausted() {
		return
	}
	switch node.Type() {
	case "function_declaration", "generator_function_declaration":
		e.walkFunction(node, scope, false)
		return
	case "function_expression", "generator_function", "arrow_function":
		e.walkAnonymousFunction(node, scope)
		return
	case "method_definition":
		e.walkMethod(node, scope)
		return
	case "class_declaration", "class":
		e.walkClass(node, scope)
		return
	case "import_statement":
		e.importFacts(node, scope)
		return
	case "export_statement":
		e.exportFacts(node, scope)
		// keep walking children so an `export const x = ...` still yields its assignment/value facts
	case "call_expression":
		e.callFact(node, scope, false)
	case "new_expression":
		e.callFact(node, scope, true)
	case "assignment_expression", "augmented_assignment_expression":
		e.assignmentFact(node, scope)
	case "variable_declarator":
		e.variableDeclaratorFact(node, scope)
	case "return_statement":
		e.returnFact(node, scope)
	case "with_statement":
		e.gap(jsprogram.GapDynamicAttribute, scope.id, "with_statement", node)
	case "subscript_expression":
		// A computed member with a NON-literal key resolves a property we cannot name. The flow is still
		// tracked container-granular (in valueFor/targets), but record the dynamic property so a reader knows
		// the specific field is unresolved. A string/number literal key ("obj['x']", "arr[0]") is effectively
		// static and not gapped, so ordinary indexing does not flood the coverage gaps.
		if idx := node.ChildByFieldName("index"); idx != nil && !jsIsLiteralKeyNode(idx) {
			e.gap(jsprogram.GapDynamicAttribute, scope.id, "computed_member", node)
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		e.walk(node.NamedChild(i), scope)
	}
}

func (e *jsFactExtractor) walkFunction(node *sitter.Node, parent jsScope, _ bool) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		e.walkAnonymousFunction(node, parent)
		return
	}
	name := nameNode.Content(e.source)
	kind := jsprogram.SymbolFunction
	if parent.kind == jsprogram.SymbolClass {
		kind = jsprogram.SymbolMethod
	}
	e.emitCallable(node, parent, name, kind)
}

// walkDecorators walks the @decorator expressions attached to a class or method. A decorator executes in the
// ENCLOSING scope when the declaration is evaluated, so its calls/flows (and any nested dynamic construct
// such as import()) are recorded there rather than silently skipped by the class/method short-circuit in
// walk(). Tree-sitter attaches decorators as named `decorator` children of the class/method node.
func (e *jsFactExtractor) walkDecorators(node *sitter.Node, parent jsScope) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if child := node.NamedChild(i); child != nil && child.Type() == "decorator" {
			e.walk(child, parent)
		}
	}
}

func (e *jsFactExtractor) walkMethod(node *sitter.Node, parent jsScope) {
	nameNode := node.ChildByFieldName("name")
	name := "<fn@" + e.posSuffix(node) + ">"
	kind := jsprogram.SymbolArrow
	if nameNode != nil && (nameNode.Type() == "property_identifier" || nameNode.Type() == "identifier") {
		name = nameNode.Content(e.source)
		kind = jsprogram.SymbolMethod
	}
	e.emitCallable(node, parent, name, kind)
}

// walkAnonymousFunction handles arrow functions and unnamed function expressions: a synthetic name keyed to
// its position, so its parameters (a request handler's req/res) and body are still extracted for value flow.
func (e *jsFactExtractor) walkAnonymousFunction(node *sitter.Node, parent jsScope) {
	name := "<fn@" + e.posSuffix(node) + ">"
	e.emitCallable(node, parent, name, jsprogram.SymbolArrow)
}

func (e *jsFactExtractor) emitCallable(node *sitter.Node, parent jsScope, name string, kind jsprogram.SymbolKind) {
	name = e.safeName(name, node) // sanitize an escaped/over-long identifier so the symbol fact stays valid
	qualified := e.boundedQualified(parent.qualified, name, node)
	id := jsprogram.CanonicalSymbolID(e.module, qualified)
	params := node.ChildByFieldName("parameters")
	if params == nil {
		params = node.ChildByFieldName("parameter") // an arrow with a single un-parenthesized param
	}
	symbol := jsprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id, Kind: kind,
		Pos: e.position(node), Parameters: e.parameters(params, id), Async: jsNodeHasToken(node, "async"),
	}
	e.doc.Symbols = append(e.doc.Symbols, symbol)
	e.entrypointHints(symbol)
	// A COMPUTED member name (`[sink(source())]() {}`) is an expression evaluated in the ENCLOSING scope when
	// the class is defined, so its calls/flows are walked in the parent scope. Without this the walk would
	// short-circuit past it (method_definition returns from walk() before the default child recursion).
	if nameNode := node.ChildByFieldName("name"); nameNode != nil && nameNode.Type() == "computed_property_name" {
		e.walk(nameNode, parent)
	}
	e.walkDecorators(node, parent) // @decorator expressions on a method execute in the enclosing scope
	if params != nil {
		e.walk(params, parent) // default expressions execute in the parent scope
	}
	body := node.ChildByFieldName("body")
	if body != nil {
		e.walk(body, jsScope{id: id, qualified: qualified, kind: kind})
	}
}

func (e *jsFactExtractor) walkClass(node *sitter.Node, parent jsScope) {
	e.walkDecorators(node, parent) // @decorator expressions on a class execute in the enclosing scope
	nameNode := node.ChildByFieldName("name")
	name := "<fn@" + e.posSuffix(node) + ">"
	kind := jsprogram.SymbolArrow // an anonymous class expression still owns a scope
	if nameNode != nil {
		name = nameNode.Content(e.source)
		kind = jsprogram.SymbolClass
	}
	// Only a named class becomes a class symbol; an anonymous class expression is uncommon and treated as a
	// synthetic scope so its methods still bind.
	name = e.safeName(name, node)
	qualified := e.boundedQualified(parent.qualified, name, node)
	id := jsprogram.CanonicalSymbolID(e.module, qualified)
	symbol := jsprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id,
		Kind: firstClassKind(kind), Pos: e.position(node),
	}
	if heritage := jsClassHeritage(node); heritage != nil {
		// Only a plain name/member superclass (`extends Base`, `extends ns.Base`) is a resolvable base. A
		// computed heritage (`extends mixin(source())`) carries calls/flows this walk does not analyze, so it is
		// recorded as a coverage gap rather than silently dropped (its inner flow could be a taint path).
		switch heritage.Type() {
		case "identifier", "member_expression":
			base := e.reference(heritage)
			if base.Kind == jsprogram.ReferenceUnknown {
				e.gap(jsprogram.GapUnresolvedValue, parent.id, "class_base", heritage)
			} else {
				symbol.Bases = append(symbol.Bases, base)
			}
		default:
			e.gap(jsprogram.GapUnresolvedValue, parent.id, "class_heritage", heritage)
		}
	}
	e.doc.Symbols = append(e.doc.Symbols, symbol)
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, jsScope{id: id, qualified: qualified, kind: symbol.Kind})
	}
}

func firstClassKind(kind jsprogram.SymbolKind) jsprogram.SymbolKind {
	if kind == jsprogram.SymbolClass {
		return jsprogram.SymbolClass
	}
	return jsprogram.SymbolArrow
}

// jsClassHeritage returns the superclass expression of `extends X`, or nil. In tree-sitter-javascript the
// class node has a `class_heritage` child whose named child is the superclass expression.
func jsClassHeritage(node *sitter.Node) *sitter.Node {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "class_heritage" && child.NamedChildCount() > 0 {
			return child.NamedChild(0)
		}
	}
	return nil
}

func (e *jsFactExtractor) importFacts(node *sitter.Node, scope jsScope) {
	source := node.ChildByFieldName("source")
	spec, ok := jsStringLiteral(source, e.source)
	if !ok {
		// `import(expr)` dynamic import or a missing source: a dependency could be loaded invisibly.
		e.gap(jsprogram.GapDynamicImport, scope.id, "dynamic_import", node)
		return
	}
	clause := jsImportClause(node)
	if clause == nil {
		// bare `import 'm'` (side-effect import): no binding, still a known dependency, nothing to bind.
		return
	}
	e.bindImportClause(clause, spec, scope, node)
}

func (e *jsFactExtractor) bindImportClause(clause *sitter.Node, spec string, scope jsScope, node *sitter.Node) {
	for i := 0; i < int(clause.NamedChildCount()); i++ {
		child := clause.NamedChild(i)
		switch child.Type() {
		case "identifier": // default import: import d from 'm'
			e.addImport(scope, jsprogram.ImportDefault, spec, "default", child.Content(e.source), node)
		case "namespace_import": // import * as ns from 'm'
			if id := jsFirstIdentifier(child, e.source); id != "" {
				e.addImport(scope, jsprogram.ImportNamespace, spec, "", id, node)
			}
		case "named_imports":
			for j := 0; j < int(child.NamedChildCount()); j++ {
				sp := child.NamedChild(j)
				if sp.Type() != "import_specifier" {
					continue
				}
				name := jsSpecifierName(sp, "name", e.source)
				alias := jsSpecifierName(sp, "alias", e.source)
				if alias == "" {
					alias = name
				}
				if name != "" && alias != "" {
					e.addImport(scope, jsprogram.ImportNamed, spec, name, alias, node)
				}
			}
		}
	}
}

func (e *jsFactExtractor) exportFacts(node *sitter.Node, scope jsScope) {
	// A re-export `export ... from 'm'` republishes a dependency; record it so its specifier is known.
	source := node.ChildByFieldName("source")
	if spec, ok := jsStringLiteral(source, e.source); ok {
		e.addImport(scope, jsprogram.ImportReexport, spec, "", "", node)
	}
}

func (e *jsFactExtractor) addImport(scope jsScope, kind jsprogram.ImportKind, spec, name, alias string, node *sitter.Node) {
	if !jsValidSpecifier(spec) || len(spec) > maxJsSpecBytes {
		// An unresolvable or over-long specifier is skipped WITH a gap rather than emitting an import fact the
		// validator rejects (a truncated specifier would be wrong for package matching, so skip, not truncate).
		e.gap(jsprogram.GapUnresolvedImport, scope.id, "import_specifier", node)
		return
	}
	e.doc.Imports = append(e.doc.Imports, jsprogram.Import{
		// The local binding names go through the bounded segment sanitizer (not jsSafeName, which has no length
		// bound), so an over-long import alias cannot emit an Import fact the validator rejects.
		ScopeID: scope.id, Kind: kind, Module: spec, Name: jsSanitizeSegment(name), Alias: jsSanitizeSegment(alias), Pos: e.position(node),
	})
}

func (e *jsFactExtractor) variableDeclaratorFact(node *sitter.Node, scope jsScope) {
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")
	if nameNode == nil {
		return
	}
	// `const x = require('m')` / `const {a,b} = require('m')`: a synchronous dependency load. A dynamic
	// require(expr) is gapped by callFact when the walk reaches the require call, so here we only bind the
	// static-specifier form and then return (the require binding is an import, not a data assignment).
	if valueNode != nil && jsIsRequireCall(valueNode, e.source) {
		if spec, ok := jsRequireSpecifier(valueNode, e.source); ok {
			e.bindRequire(nameNode, spec, scope, node)
		}
		return
	}
	if valueNode == nil {
		return
	}
	e.recordAssignment(nameNode, valueNode, scope, node)
}

func (e *jsFactExtractor) bindRequire(target *sitter.Node, spec string, scope jsScope, node *sitter.Node) {
	switch target.Type() {
	case "identifier":
		e.addImport(scope, jsprogram.ImportRequire, spec, "", target.Content(e.source), node)
	case "object_pattern":
		for i := 0; i < int(target.NamedChildCount()); i++ {
			if name := jsPatternName(target.NamedChild(i), e.source); name != "" {
				e.addImport(scope, jsprogram.ImportRequire, spec, name, name, node)
			}
		}
	default:
		if id := jsFirstIdentifier(target, e.source); id != "" {
			e.addImport(scope, jsprogram.ImportRequire, spec, "", id, node)
		}
	}
}

func (e *jsFactExtractor) callFact(node *sitter.Node, scope jsScope, isNew bool) {
	calleeNode := node.ChildByFieldName("function")
	if isNew {
		calleeNode = node.ChildByFieldName("constructor")
	}
	callee := e.reference(calleeNode)
	call := jsprogram.Call{
		ID: jsFactID(e.file, node), CallerID: scope.id, Callee: callee, ResultID: e.valueFor(node, scope),
		Pos: e.position(node), Await: node.Parent() != nil && node.Parent().Type() == "await_expression", New: isNew,
	}
	if calleeNode != nil && calleeNode.Type() == "member_expression" {
		call.ReceiverValueID = e.valueFor(calleeNode.ChildByFieldName("object"), scope)
	}
	// A dynamic `import(expr)` parses with an `import`-typed callee node (not an identifier): a dependency
	// loaded invisibly. Record it before the generic unresolved-call gap.
	if calleeNode != nil && calleeNode.Type() == "import" {
		e.gap(jsprogram.GapDynamicImport, scope.id, "dynamic_import", node)
	} else if callee.Kind == jsprogram.ReferenceUnknown {
		e.gap(jsprogram.GapUnresolvedCall, scope.id, "call_target", node)
	}
	joined := strings.Join(callee.Segments, ".")
	last := ""
	if len(callee.Segments) > 0 {
		last = callee.Segments[len(callee.Segments)-1]
	}
	switch {
	// Dynamic code construction/execution, matched on the LAST segment so a receiver-qualified form is caught
	// too (globalThis.eval, window.Function). Function(...) is dynamic with or without `new`. Over-matching a
	// user method that happens to be named eval/Function only marks coverage incomplete (a conservative gap),
	// never a false finding, so it is the safe direction.
	case last == "eval" || last == "Function":
		e.gap(jsprogram.GapDynamicExecution, scope.id, "dynamic_code", node)
	case (last == "call" || last == "apply") && len(callee.Segments) >= 2 &&
		(callee.Segments[len(callee.Segments)-2] == "eval" || callee.Segments[len(callee.Segments)-2] == "Function"):
		// Indirect invocation `eval.call(...)` / `Function.apply(...)`. Deeper indirections (Reflect.apply(eval,
		// ...), window["eval"](...), an aliased const e = eval) are a documented recall limitation, not gapped:
		// they are vanishingly rare and this extractor produces no findings, so a missed gap is at worst a
		// missed downstream finding, never a false positive or a false suppression.
		e.gap(jsprogram.GapDynamicExecution, scope.id, "dynamic_code", node)
	case last == "runInContext" || last == "runInNewContext" || last == "runInThisContext" || last == "compileFunction":
		e.gap(jsprogram.GapDynamicExecution, scope.id, "dynamic_code", node)
	case joined == "import":
		e.gap(jsprogram.GapDynamicImport, scope.id, "dynamic_import", node)
	case joined == "require" && !jsFirstArgIsStringLiteral(node):
		// require(expr) with a non-string-literal argument loads a dependency invisibly, in ANY call
		// position (foo(require(x)), module.exports = require(x), require(x).y). require('literal') is a known
		// dependency and is not gapped.
		e.gap(jsprogram.GapDynamicImport, scope.id, "dynamic_require", node)
	}
	if args := node.ChildByFieldName("arguments"); args != nil {
		for i := 0; i < int(args.NamedChildCount()); i++ {
			if len(call.Arguments) >= maxJsArgs {
				e.gap(jsprogram.GapBudget, scope.id, "argument_budget", node)
				break
			}
			argNode := args.NamedChild(i)
			arg := jsprogram.Argument{}
			valueNode := argNode
			if argNode.Type() == "spread_element" {
				arg.Spread = true
				valueNode = firstNamedChild(argNode)
			}
			arg.Value = e.reference(valueNode)
			arg.ValueID = e.valueFor(valueNode, scope)
			arg.Pos = e.position(valueNode)
			if arg.Value.Kind == jsprogram.ReferenceUnknown && arg.ValueID == "" {
				e.gap(jsprogram.GapUnresolvedValue, scope.id, "call_argument", argNode)
			}
			call.Arguments = append(call.Arguments, arg)
		}
	}
	e.doc.Calls = append(e.doc.Calls, call)
}

func (e *jsFactExtractor) assignmentFact(node *sitter.Node, scope jsScope) {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	e.recordAssignmentNodes(left, right, scope, node, node.Type() == "augmented_assignment_expression")
}

func (e *jsFactExtractor) recordAssignment(left, right *sitter.Node, scope jsScope, node *sitter.Node) {
	e.recordAssignmentNodes(left, right, scope, node, false)
}

func (e *jsFactExtractor) recordAssignmentNodes(left, right *sitter.Node, scope jsScope, node *sitter.Node, augmented bool) {
	if left == nil {
		return
	}
	targets := e.targets(left)
	if len(targets) == 0 {
		return
	}
	if len(targets) > maxJsTargets {
		targets = targets[:maxJsTargets]
		e.gap(jsprogram.GapBudget, scope.id, "target_budget", node)
	}
	value := e.reference(right)
	valueID := e.valueFor(right, scope)
	if value.Kind == jsprogram.ReferenceUnknown && valueID == "" {
		e.gap(jsprogram.GapUnresolvedValue, scope.id, "assignment_value", node)
	}
	targetIDs := e.bindingValues(left, scope)
	if len(targetIDs) > maxJsTargets {
		targetIDs = targetIDs[:maxJsTargets]
		e.gap(jsprogram.GapBudget, scope.id, "target_budget", node)
	}
	for _, targetID := range targetIDs {
		e.addValueFlow(valueID, targetID, jsprogram.FlowAssignment, node)
		if augmented {
			e.addValueFlow(e.valueFor(left, scope), targetID, jsprogram.FlowAssignment, node)
		}
	}
	e.doc.Assignments = append(e.doc.Assignments, jsprogram.Assignment{
		ScopeID: scope.id, Targets: targets, TargetIDs: targetIDs, Value: value, ValueID: valueID, Pos: e.position(node),
	})
}

func (e *jsFactExtractor) returnFact(node *sitter.Node, scope jsScope) {
	value := jsprogram.Reference{Kind: jsprogram.ReferenceLiteral}
	if node.NamedChildCount() > 0 {
		value = e.reference(node.NamedChild(0))
	}
	valueNode := firstNamedChild(node)
	valueID := e.valueFor(valueNode, scope)
	if value.Kind == jsprogram.ReferenceUnknown && valueID == "" {
		e.gap(jsprogram.GapUnresolvedValue, scope.id, "return_value", node)
	}
	slotID := scope.id + "#return"
	if !e.addValue(jsprogram.Value{
		ID: slotID, ScopeID: scope.id, Kind: jsprogram.ValueReturn,
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}, Pos: e.position(node),
	}) {
		slotID = "" // budget: record the return without a dangling slot id
	} else {
		e.addValueFlow(valueID, slotID, jsprogram.FlowReturn, node)
	}
	e.doc.Returns = append(e.doc.Returns, jsprogram.Return{ScopeID: scope.id, Value: value, ValueID: valueID, SlotID: slotID, Pos: e.position(node)})
}

func (e *jsFactExtractor) valueFor(node *sitter.Node, scope jsScope) string {
	if node == nil {
		return ""
	}
	id := jsValueID(e.file, node, "value")
	if e.values[id] {
		return id
	}
	if e.budgetHit {
		return ""
	}
	ref := e.reference(node)
	kind := jsprogram.ValueExpression
	switch {
	case node.Type() == "call_expression" || node.Type() == "new_expression":
		kind = jsprogram.ValueCallResult
	case node.Type() == "identifier" || node.Type() == "member_expression":
		kind = jsprogram.ValueReference
	case ref.Kind == jsprogram.ReferenceLiteral && node.NamedChildCount() == 0:
		kind = jsprogram.ValueLiteral
	default:
		ref = jsprogram.Reference{Kind: jsprogram.ReferenceExpression}
	}
	if !e.addValue(jsprogram.Value{ID: id, ScopeID: scope.id, Kind: kind, Ref: ref, Pos: e.position(node)}) {
		return "" // budget: the slot was not emitted, so no fact may reference this id
	}

	switch node.Type() {
	case "call_expression", "new_expression":
		// Argument-to-result propagation is function-model/interprocedural behavior, not a syntax flow.
		return id
	case "member_expression":
		from := e.valueFor(node.ChildByFieldName("object"), scope)
		e.addValueFlow(from, id, jsprogram.FlowAttribute, node)
		return id
	case "subscript_expression":
		// Container-granular: the value of a[k] flows from the container `a`, never a specific field.
		from := e.valueFor(node.ChildByFieldName("object"), scope)
		e.addValueFlow(from, id, jsprogram.FlowAttribute, node)
		return id
	case "identifier":
		return id
	case "function_declaration", "function_expression", "arrow_function", "generator_function",
		"generator_function_declaration", "method_definition", "class", "class_declaration":
		// A nested function/class introduces its own scope, walked separately; never flow its body into the
		// enclosing expression (that would create a cross-scope value flow).
		return id
	case "await_expression", "parenthesized_expression":
		if inner := firstNamedChild(node); inner != nil {
			e.addValueFlow(e.valueFor(inner, scope), id, jsprogram.FlowExpression, node)
		}
		return id
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		e.addValueFlow(e.valueFor(child, scope), id, jsprogram.FlowExpression, node)
	}
	return id
}

func (e *jsFactExtractor) bindingValues(node *sitter.Node, scope jsScope) []string {
	if node == nil {
		return nil
	}
	switch node.Type() {
	case "subscript_expression", "member_expression":
		// Container-granular write: a[k] = v / a.b = v / this.x = v taints the container `a`/`this`.
		return e.bindingValues(node.ChildByFieldName("object"), scope)
	case "pair_pattern": // { key: target } = v -> the binding is the value node
		return e.bindingValues(node.ChildByFieldName("value"), scope)
	case "assignment_pattern", "object_assignment_pattern": // { a = default } -> the binding is the left
		left := node.ChildByFieldName("left")
		if left == nil {
			return nil
		}
		ids := e.bindingValues(left, scope)
		// The default initializer flows into the bound name, so `const { x = source() } = {}` taints x.
		if right := node.ChildByFieldName("right"); right != nil {
			defID := e.valueFor(right, scope)
			for _, id := range ids {
				e.addValueFlow(defID, id, jsprogram.FlowAssignment, node)
			}
		}
		return ids
	case "rest_pattern": // [ ...rest ] / { ...rest }
		return e.bindingValues(firstNamedChild(node), scope)
	case "array_pattern", "object_pattern", "array", "object":
		var out []string
		for i := 0; i < int(node.NamedChildCount()); i++ {
			out = append(out, e.bindingValues(node.NamedChild(i), scope)...)
		}
		return out
	}
	ref := e.reference(node)
	if ref.Kind == jsprogram.ReferenceName || ref.Kind == jsprogram.ReferenceAttribute {
		id := jsValueID(e.file, node, "binding")
		name := ref.Segments[len(ref.Segments)-1]
		if !e.addValue(jsprogram.Value{ID: id, ScopeID: scope.id, Kind: jsprogram.ValueBinding, Name: name, Ref: ref, Pos: e.position(node)}) {
			return nil // budget: do not return a binding id whose value was not emitted
		}
		return []string{id}
	}
	return nil
}

// addValue appends a value slot and reports whether the slot is now available (either just emitted or
// already present). It returns false when the budget is exhausted so a caller can avoid returning a value
// id that was never emitted (which would leave a dangling reference the validator rejects).
func (e *jsFactExtractor) addValue(value jsprogram.Value) bool {
	if value.ID == "" {
		return false
	}
	if e.values[value.ID] {
		return true
	}
	if e.factsExhausted() {
		return false
	}
	e.values[value.ID] = true
	e.doc.Values = append(e.doc.Values, value)
	return true
}

func (e *jsFactExtractor) addValueFlow(from, to string, kind jsprogram.ValueFlowKind, node *sitter.Node) {
	if from == "" || to == "" || from == to {
		return
	}
	key := from + "\x00" + to + "\x00" + string(kind)
	if e.flows[key] {
		return
	}
	if e.factsExhausted() {
		return
	}
	e.flows[key] = true
	e.doc.Flows = append(e.doc.Flows, jsprogram.ValueFlow{FromID: from, ToID: to, Kind: kind, Pos: e.position(node)})
}

func (e *jsFactExtractor) reference(node *sitter.Node) jsprogram.Reference {
	if node == nil {
		return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}
	}
	switch node.Type() {
	case "identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern", "property_identifier", "this":
		content := jsSanitizeSegment(node.Content(e.source))
		if content == "" {
			return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}
		}
		return jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{content}}
	case "member_expression":
		base := e.reference(node.ChildByFieldName("object"))
		prop := node.ChildByFieldName("property")
		if prop == nil || (base.Kind != jsprogram.ReferenceName && base.Kind != jsprogram.ReferenceAttribute) {
			return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}
		}
		propName := jsSanitizeSegment(prop.Content(e.source))
		if propName == "" {
			return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}
		}
		if len(base.Segments) >= maxJsRefSegments {
			// A pathologically deep member chain would exceed the reference-segment bound; fall back to an
			// opaque reference AND record honest incompleteness rather than emitting a fact the validator
			// rejects (which would drop the whole document) or silently claiming completeness.
			e.gap(jsprogram.GapBudget, "", "reference_depth", nil)
			return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}
		}
		return jsprogram.Reference{Kind: jsprogram.ReferenceAttribute, Segments: append(append([]string{}, base.Segments...), propName)}
	case "call_expression", "new_expression":
		fn := node.ChildByFieldName("function")
		if node.Type() == "new_expression" {
			fn = node.ChildByFieldName("constructor")
		}
		callee := e.reference(fn)
		if callee.Kind == jsprogram.ReferenceUnknown {
			return callee
		}
		callee.Kind = jsprogram.ReferenceCall
		return callee
	case "parenthesized_expression", "await_expression":
		if node.NamedChildCount() == 1 {
			return e.reference(node.NamedChild(0))
		}
	case "string", "template_string", "number", "true", "false", "null", "undefined", "regex", "object", "array":
		return jsprogram.Reference{Kind: jsprogram.ReferenceLiteral}
	}
	return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}
}

func (e *jsFactExtractor) targets(node *sitter.Node) []jsprogram.Reference {
	if node == nil {
		return nil
	}
	switch node.Type() {
	case "subscript_expression", "member_expression":
		return e.targets(node.ChildByFieldName("object"))
	case "pair_pattern":
		return e.targets(node.ChildByFieldName("value"))
	case "assignment_pattern", "object_assignment_pattern":
		if left := node.ChildByFieldName("left"); left != nil {
			return e.targets(left)
		}
		return nil
	case "rest_pattern":
		return e.targets(firstNamedChild(node))
	case "array_pattern", "object_pattern", "array", "object":
		var out []jsprogram.Reference
		for i := 0; i < int(node.NamedChildCount()); i++ {
			out = append(out, e.targets(node.NamedChild(i))...)
		}
		return out
	}
	ref := e.reference(node)
	if ref.Kind == jsprogram.ReferenceName || ref.Kind == jsprogram.ReferenceAttribute {
		return []jsprogram.Reference{ref}
	}
	return nil
}

func (e *jsFactExtractor) parameters(node *sitter.Node, scopeID string) []jsprogram.Parameter {
	if node == nil {
		return nil
	}
	var out []jsprogram.Parameter
	// A single un-parenthesized arrow parameter is an identifier node itself, not a formal_parameters list.
	if node.Type() == "identifier" {
		e.appendParameter(&out, scopeID, node.Content(e.source), jsprogram.ParameterPositional, node)
		return out
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		e.parameterFrom(&out, node.NamedChild(i), scopeID)
	}
	return out
}

func (e *jsFactExtractor) parameterFrom(out *[]jsprogram.Parameter, child *sitter.Node, scopeID string) {
	switch child.Type() {
	case "identifier":
		e.appendParameter(out, scopeID, child.Content(e.source), jsprogram.ParameterPositional, child)
	case "required_parameter", "optional_parameter":
		// TypeScript: unwrap the `pattern` field (an identifier or a binding pattern).
		if pattern := child.ChildByFieldName("pattern"); pattern != nil {
			e.parameterFrom(out, pattern, scopeID)
		}
	case "rest_pattern":
		if id := jsFirstIdentifier(child, e.source); id != "" {
			e.appendParameter(out, scopeID, id, jsprogram.ParameterRest, child)
		}
	case "assignment_pattern":
		if left := child.ChildByFieldName("left"); left != nil {
			e.appendDefaultParams(out, left, scopeID)
		}
	case "object_pattern", "array_pattern":
		e.appendPatternParams(out, child, scopeID)
	}
}

func (e *jsFactExtractor) appendDefaultParams(out *[]jsprogram.Parameter, left *sitter.Node, scopeID string) {
	if left.Type() == "identifier" {
		e.appendParameter(out, scopeID, left.Content(e.source), jsprogram.ParameterDefault, left)
		return
	}
	e.appendPatternParams(out, left, scopeID)
}

func (e *jsFactExtractor) appendPatternParams(out *[]jsprogram.Parameter, pattern *sitter.Node, scopeID string) {
	for i := 0; i < int(pattern.NamedChildCount()); i++ {
		child := pattern.NamedChild(i)
		if name := jsPatternName(child, e.source); name != "" {
			e.appendParameter(out, scopeID, name, jsprogram.ParameterDestructured, child)
			continue
		}
		if child.Type() == "object_pattern" || child.Type() == "array_pattern" {
			e.appendPatternParams(out, child, scopeID)
		}
	}
}

func (e *jsFactExtractor) appendParameter(out *[]jsprogram.Parameter, scopeID, name string, kind jsprogram.ParameterKind, node *sitter.Node) {
	name = jsSanitizeSegment(name) // bounded + valid, so the parameter and its value slot never fail Validate
	if name == "" {
		return
	}
	if len(*out) >= maxJsParams {
		// A nil node gives every overflow parameter the same (zero) position, so gap() dedups them to a
		// single budget gap instead of one per excess parameter (which could itself exceed the fact bound).
		e.gap(jsprogram.GapBudget, scopeID, "parameter_budget", nil)
		return
	}
	valueID := scopeID + "#param:" + strconv.Itoa(len(*out)) + ":" + name
	pos := e.position(node)
	if !e.addValue(jsprogram.Value{
		ID: valueID, ScopeID: scopeID, Kind: jsprogram.ValueParameter, Name: name,
		Ref: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{name}}, Pos: pos,
	}) {
		valueID = "" // budget: keep the parameter's shape but do not reference a value slot that was not emitted
	}
	*out = append(*out, jsprogram.Parameter{Name: name, Kind: kind, ValueID: valueID, Pos: pos})
}

func (e *jsFactExtractor) entrypointHints(symbol jsprogram.Symbol) {
	if symbol.Name == "main" || symbol.Name == "handler" {
		e.doc.Entrypoints = append(e.doc.Entrypoints, jsprogram.EntrypointHint{SymbolID: symbol.ID, Kind: "conventional_handler", Pos: symbol.Pos})
	}
}

func (e *jsFactExtractor) gap(kind jsprogram.GapKind, symbolID, detail string, node *sitter.Node) {
	pos := jsprogram.Position{}
	if node != nil {
		pos = e.position(node)
	}
	for _, existing := range e.doc.CoverageGaps {
		if existing.Kind == kind && existing.SymbolID == symbolID && existing.Detail == detail && existing.Pos == pos {
			return
		}
	}
	if len(e.doc.CoverageGaps) >= jsFactBudget {
		return // the coverage gaps must not themselves exceed the fact bound
	}
	e.doc.CoverageGaps = append(e.doc.CoverageGaps, jsprogram.CoverageGap{Kind: kind, SymbolID: symbolID, Detail: detail, Pos: pos})
}

// factsExhausted reports whether the document has reached its fact budget. On the first time it trips it
// records a single budget gap and marks the document truncated, so every subsequent emitter stops. This is
// the by-construction guard that keeps the document within the bounds Validate enforces, whatever the input.
func (e *jsFactExtractor) factsExhausted() bool {
	if e.budgetHit {
		return true
	}
	if e.doc.NodesSeen > maxJsFactNodes || e.factCount() >= jsFactBudget {
		e.budgetHit = true
		e.doc.Truncated = true
		e.gap(jsprogram.GapBudget, "", "fact_budget", nil)
		return true
	}
	return false
}

func (e *jsFactExtractor) position(node *sitter.Node) jsprogram.Position {
	if node == nil {
		return jsprogram.Position{File: e.file, Line: 1}
	}
	point := node.StartPoint()
	return jsprogram.Position{File: e.file, Line: int(point.Row) + 1, Column: int(point.Column)}
}

func (e *jsFactExtractor) posSuffix(node *sitter.Node) string {
	point := node.StartPoint()
	return strconv.Itoa(int(point.Row)+1) + "_" + strconv.Itoa(int(point.Column))
}

func (e *jsFactExtractor) factCount() int {
	return len(e.doc.Symbols) + len(e.doc.Imports) + len(e.doc.Calls) + len(e.doc.Assignments) + len(e.doc.Returns) +
		len(e.doc.Values) + len(e.doc.Flows) + len(e.doc.CoverageGaps)
}

// --- pure helpers ---

func jsModuleName(rel string) (string, bool) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	ext := strings.ToLower(filepath.Ext(rel))
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	// A ".d" left from a ".d.ts" declaration file is stripped so the module path is clean.
	if ext == ".ts" && strings.HasSuffix(strings.ToLower(rel), ".d") {
		rel = rel[:len(rel)-2]
	}
	parts := strings.Split(rel, "/")
	if len(parts) == 0 {
		return "", false
	}
	for i, part := range parts {
		parts[i] = jsSanitizePathSegment(part)
		if parts[i] == "" {
			return "", false
		}
	}
	return strings.Join(parts, "/"), true
}

// jsSanitizePathSegment keeps only the module-path characters the domain validator accepts, so a directory
// with an unusual character still yields a stable, valid module name.
func jsSanitizePathSegment(part string) string {
	part = strings.TrimSpace(part)
	if part == "" || part == "." || part == ".." {
		return ""
	}
	var b strings.Builder
	for _, r := range part {
		switch {
		case r == '_' || r == '$' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "." || out == ".." {
		return ""
	}
	return out
}

func jsModuleLeaf(module string) string {
	if at := strings.LastIndexByte(module, '/'); at >= 0 {
		return jsSafeLeaf(module[at+1:])
	}
	return jsSafeLeaf(module)
}

// jsSafeLeaf reduces a path leaf to a valid JS identifier for the module symbol's Name (letters/digits/_/$).
func jsSafeLeaf(leaf string) string {
	var b strings.Builder
	for i, r := range leaf {
		switch {
		case r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			b.WriteRune(r)
		case i > 0 && r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "_"
	}
	// ensure the first char is a valid start
	if r := rune(out[0]); !(r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
		return "_" + out
	}
	return out
}

func joinJsQualified(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

func jsFactID(file string, node *sitter.Node) string {
	// Key on BOTH start and end: a chained call `f()()` (or any nested expression) has an outer and inner node
	// that share a start position, so a start-only id would collide and make the two facts duplicate, which
	// Validate rejects (dropping the whole document). Including the end disambiguates them.
	start, end := node.StartPoint(), node.EndPoint()
	return file + ":" + strconv.Itoa(int(start.Row)+1) + ":" + strconv.Itoa(int(start.Column)) + ":" +
		strconv.Itoa(int(end.Row)+1) + ":" + strconv.Itoa(int(end.Column))
}

func jsValueID(file string, node *sitter.Node, role string) string {
	start, end := node.StartPoint(), node.EndPoint()
	return file + ":" + strconv.Itoa(int(start.Row)+1) + ":" + strconv.Itoa(int(start.Column)) + ":" +
		strconv.Itoa(int(end.Row)+1) + ":" + strconv.Itoa(int(end.Column)) + ":" + role
}

func jsNodeHasToken(node *sitter.Node, token string) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == token {
			return true
		}
	}
	return false
}

func jsFirstIdentifier(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	stack := []*sitter.Node{node}
	for len(stack) > 0 {
		current := stack[0]
		stack = stack[1:]
		if current.Type() == "identifier" || current.Type() == "shorthand_property_identifier_pattern" {
			return current.Content(source)
		}
		for i := 0; i < int(current.NamedChildCount()); i++ {
			stack = append(stack, current.NamedChild(i))
		}
	}
	return ""
}

// jsPatternName returns the bound identifier of a destructuring pattern element, or "".
func jsPatternName(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	switch node.Type() {
	case "shorthand_property_identifier_pattern", "identifier":
		return node.Content(source)
	case "pair_pattern":
		if v := node.ChildByFieldName("value"); v != nil {
			return jsPatternName(v, source)
		}
	case "assignment_pattern":
		if left := node.ChildByFieldName("left"); left != nil {
			return jsPatternName(left, source)
		}
	case "rest_pattern":
		return jsFirstIdentifier(node, source)
	}
	return ""
}

func jsStringLiteral(node *sitter.Node, source []byte) (string, bool) {
	if node == nil || node.Type() != "string" {
		return "", false
	}
	// The string's content is between the quote children; use the fragment child if present, else strip.
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if node.NamedChild(i).Type() == "string_fragment" {
			return node.NamedChild(i).Content(source), true
		}
	}
	raw := node.Content(source)
	if len(raw) >= 2 {
		return raw[1 : len(raw)-1], true
	}
	return "", false
}

func jsImportClause(node *sitter.Node) *sitter.Node {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if node.NamedChild(i).Type() == "import_clause" {
			return node.NamedChild(i)
		}
	}
	return nil
}

func jsSpecifierName(sp *sitter.Node, field string, source []byte) string {
	if n := sp.ChildByFieldName(field); n != nil {
		return n.Content(source)
	}
	return ""
}

// jsIsLiteralKeyNode reports whether a computed-member index is a static string/number literal.
func jsIsLiteralKeyNode(node *sitter.Node) bool {
	switch node.Type() {
	case "string", "number":
		return true
	}
	return false
}

// jsFirstArgIsStringLiteral reports whether a call's first argument is a string literal.
func jsFirstArgIsStringLiteral(node *sitter.Node) bool {
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return false
	}
	return args.NamedChild(0).Type() == "string"
}

func jsIsRequireCall(node *sitter.Node, source []byte) bool {
	if node == nil || node.Type() != "call_expression" {
		return false
	}
	fn := node.ChildByFieldName("function")
	return fn != nil && fn.Type() == "identifier" && fn.Content(source) == "require"
}

func jsRequireSpecifier(node *sitter.Node, source []byte) (string, bool) {
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return "", false
	}
	return jsStringLiteral(args.NamedChild(0), source)
}

// jsValidSegment mirrors jsprogram's identifier rule (a JS identifier, '$' allowed) so the extractor only
// emits reference/name segments the domain validator will accept.
func jsValidSegment(value string) bool {
	if value == "" || value == "*" {
		return false
	}
	for i, r := range value {
		if r == '_' || r == '$' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r)) {
			continue
		}
		return false
	}
	return true
}

// jsDecodeIdentEscapes decodes the JS unicode escape forms (\uXXXX and \u{...}) that a source identifier may
// use, so an escaped spelling and its plain spelling map to the SAME identifier. A malformed or non-\u
// backslash is left as-is (the sanitizer then drops the stray character). It scans raw once.
func jsDecodeIdentEscapes(raw string) string {
	if !strings.Contains(raw, `\u`) {
		return raw
	}
	var b strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] == '\\' && i+1 < len(raw) && raw[i+1] == 'u' {
			if i+2 < len(raw) && raw[i+2] == '{' { // \u{ hex... }
				j := i + 3
				for j < len(raw) && raw[j] != '}' {
					j++
				}
				if j < len(raw) && j > i+3 {
					if cp, err := strconv.ParseInt(raw[i+3:j], 16, 32); err == nil && cp >= 0 && cp <= 0x10FFFF {
						b.WriteRune(rune(cp))
						i = j + 1
						continue
					}
				}
			} else if i+6 <= len(raw) { // \uXXXX
				if cp, err := strconv.ParseInt(raw[i+2:i+6], 16, 32); err == nil && cp >= 0 && cp <= 0x10FFFF {
					b.WriteRune(rune(cp))
					i += 6
					continue
				}
			}
		}
		b.WriteByte(raw[i])
		i++
	}
	return b.String()
}

// jsSanitizeSegment is the SINGLE choke point every identifier/property/name passes through before it
// becomes a Reference segment, Value name, or Parameter name. It returns a bounded, valid JS-identifier
// segment (jsprogram.validName-compatible, length <= maxJsSegBytes < maxStringBytes), or "" when no valid
// segment can be produced. It is deterministic: the same raw text always yields the same segment, so an
// escaped or over-long identifier still binds and reads consistently (its write and read connect), never an
// invalid fact that Validate would reject.
func jsSanitizeSegment(raw string) string {
	// Decode JS unicode identifier escapes first, so an escaped spelling (a) and its plain spelling (a)
	// produce the SAME segment and a flow between the two connects instead of being silently lost.
	raw = jsDecodeIdentEscapes(raw)
	if len(raw) <= maxJsSegBytes && jsValidSegment(raw) {
		return raw
	}
	var b strings.Builder
	for _, r := range raw {
		if b.Len() >= maxJsSegBytes-8 {
			break
		}
		first := b.Len() == 0
		if r == '_' || r == '$' || unicode.IsLetter(r) || (!first && unicode.IsDigit(r)) {
			b.WriteRune(r)
		}
	}
	if out := b.String(); out != "" && jsValidSegment(out) {
		return out
	}
	return ""
}

// jsValidSpecifier mirrors jsprogram's module-specifier rule (character set only).
func jsValidSpecifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r == '_' || r == '$' || r == '-' || r == '.' || r == '/' || r == '@' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}
