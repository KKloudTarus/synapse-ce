//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	maxJavaFactNodes = 2_000_000
	maxJavaFacts     = 4_000_000
	// maxJavaExprDepth bounds recursion into a single expression subtree (a deeply nested chain, parenthesis
	// nest, or binary expression in hostile source) so the expression-lowering helpers cannot stack-overflow
	// before the node/fact budget in walk trips. Generous: a real Java expression is far shallower.
	maxJavaExprDepth = 512
)

// JavaFactsFor extracts a bounded, versioned Java semantic-facts document without compiling or executing
// target code. It is the Java twin of JsFactsFor / PythonFactsFor: tree-sitter-java parses each `.java`
// file, an extractor lowers the tree into javaprogram value/flow/call facts, and every document is
// validated at the trust boundary before it is returned. Reflection (Class.forName, Method.invoke,
// dynamic proxies, ScriptEngineManager), parser recovery, unresolved callees, and budget limits are
// recorded as explicit coverage gaps so a downstream negative is never mistaken for proof.
func JavaFactsFor(ctx context.Context, root string) (javaprogram.Document, error) {
	doc := javaprogram.Document{SchemaVersion: javaprogram.SchemaVersion}
	modules := map[string]bool{}
	walkTruncated, err := walkSourceWithIssues(ctx, root, func(rel, lang string, content []byte) {
		if lang != "Java" || !strings.EqualFold(filepath.Ext(rel), ".java") {
			return
		}
		doc.FilesSeen++
		rel = filepath.ToSlash(rel)
		module, ok := javaModuleName(rel)
		if !ok {
			doc.CoverageGaps = append(doc.CoverageGaps, javaprogram.CoverageGap{
				Kind: javaprogram.GapUnresolvedImport, Detail: "invalid_module_path", Pos: javaprogram.Position{File: rel, Line: 1},
			})
			return
		}
		if modules[module] {
			doc.CoverageGaps = append(doc.CoverageGaps, javaprogram.CoverageGap{
				Kind: javaprogram.GapUnresolvedImport, Detail: "ambiguous_module_path", Pos: javaprogram.Position{File: rel, Line: 1},
			})
			return
		}
		modules[module] = true
		rootNode := parseRoot(ctx, specs["Java"], content)
		if rootNode == nil {
			doc.CoverageGaps = append(doc.CoverageGaps, javaprogram.CoverageGap{
				Kind: javaprogram.GapParseRecovery, Detail: "parse_failed", Pos: javaprogram.Position{File: rel, Line: 1},
			})
			return
		}
		doc.FilesParsed++
		modulePos := javaprogram.Position{File: rel, Line: 1}
		moduleID := javaprogram.CanonicalSymbolID(module, "<module>")
		doc.Modules = append(doc.Modules, javaprogram.Module{Name: module, File: rel, Pos: modulePos})
		doc.Symbols = append(doc.Symbols, javaprogram.Symbol{
			ID: moduleID, Module: module, QualifiedName: "<module>", Name: javaModuleLeaf(module), Kind: javaprogram.SymbolModule, Pos: modulePos,
		})
		doc.Entrypoints = append(doc.Entrypoints, javaprogram.EntrypointHint{SymbolID: moduleID, Kind: "module_import", Pos: modulePos})
		extractor := javaFactExtractor{
			doc: &doc, module: module, file: rel, source: content,
			values: map[string]bool{}, flows: map[string]bool{}, gapKeys: map[string]bool{}, symbolQual: map[string]bool{},
		}
		if rootNode.HasError() {
			extractor.gap(javaprogram.GapParseRecovery, moduleID, "parser_recovery", rootNode)
		}
		extractor.walk(rootNode, javaScope{id: moduleID, qualified: "", kind: javaprogram.SymbolModule})
	}, func(sourceIssue) {
		// The shared walker only reports issues for python-shaped files; a Java file that is oversized or
		// unreadable is simply not visited. That is a coverage-recall limitation (a missed file), never a
		// soundness one, so no gap is emitted here.
	})
	if err != nil {
		return javaprogram.Document{}, err
	}
	if walkTruncated {
		doc.Truncated = true
		doc.CoverageGaps = append(doc.CoverageGaps, javaprogram.CoverageGap{Kind: javaprogram.GapBudget, Detail: "file_budget"})
	}
	doc.SortCanonical()
	if err := doc.Validate(); err != nil {
		return javaprogram.Document{}, fmt.Errorf("validate extracted java facts: %w", err)
	}
	return doc, nil
}

type javaScope struct {
	id        string
	qualified string
	kind      javaprogram.SymbolKind
}

type javaFactExtractor struct {
	doc        *javaprogram.Document
	module     string
	file       string
	source     []byte
	budgetHit  bool
	depth      int // current expression-recursion depth, bounded by maxJavaExprDepth
	values     map[string]bool
	flows      map[string]bool
	gapKeys    map[string]bool // coverage-gap dedup keys, so gap() is O(1) not O(existing gaps)
	symbolQual map[string]bool // qualified names already emitted in this module, to disambiguate overloads
}

// enterExpr bounds recursion into an expression subtree of hostile depth. A true return must be paired with
// `defer e.leaveExpr()`; a false return means the guard tripped, so the caller returns its safe fallback and
// the document is marked truncated (the deep subtree is not modeled, honestly reported as incomplete).
func (e *javaFactExtractor) enterExpr() bool {
	if e.depth >= maxJavaExprDepth {
		e.doc.Truncated = true
		return false
	}
	e.depth++
	return true
}

func (e *javaFactExtractor) leaveExpr() { e.depth-- }

func (e *javaFactExtractor) walk(node *sitter.Node, scope javaScope) {
	if node == nil || e.budgetHit {
		return
	}
	e.doc.NodesSeen++
	if e.doc.NodesSeen > maxJavaFactNodes || e.factCount() > maxJavaFacts {
		e.doc.Truncated = true
		e.budgetHit = true
		e.gap(javaprogram.GapBudget, scope.id, "node_or_fact_budget", node)
		return
	}
	switch node.Type() {
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		e.walkType(node, scope)
		return
	case "method_declaration", "constructor_declaration":
		e.walkMethod(node, scope)
		return
	case "lambda_expression":
		e.walkLambda(node, scope)
		return
	case "import_declaration":
		e.importFact(node, scope)
		return
	case "method_invocation":
		e.callFact(node, scope, false)
	case "object_creation_expression":
		e.callFact(node, scope, true)
	case "assignment_expression":
		e.assignmentFact(node, scope)
	case "variable_declarator":
		e.variableDeclaratorFact(node, scope)
	case "return_statement":
		e.returnFact(node, scope)
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		e.walk(node.NamedChild(i), scope)
	}
}

// walkType handles a class / interface / enum / record declaration: it emits the type symbol (with its
// annotations and extends/implements bases) and descends into the type body under the new scope.
func (e *javaFactExtractor) walkType(node *sitter.Node, parent javaScope) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		e.gap(javaprogram.GapUnresolvedValue, parent.id, "type_without_name", node)
		return
	}
	name := e.safeName(nameNode.Content(e.source), node)
	kind := javaprogram.SymbolClass
	if node.Type() == "interface_declaration" {
		kind = javaprogram.SymbolInterface
	}
	qualified := e.uniqueQualified(joinJavaQualified(parent.qualified, name), node)
	id := javaprogram.CanonicalSymbolID(e.module, qualified)
	symbol := javaprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id, Kind: kind,
		Pos: e.position(node), Annotations: e.modifierAnnotations(node), Bases: e.typeBases(node),
	}
	e.doc.Symbols = append(e.doc.Symbols, symbol)
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, javaScope{id: id, qualified: qualified, kind: kind})
	}
}

func (e *javaFactExtractor) walkMethod(node *sitter.Node, parent javaScope) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		e.gap(javaprogram.GapUnresolvedCall, parent.id, "method_without_name", node)
		return
	}
	name := e.safeName(nameNode.Content(e.source), node)
	kind := javaprogram.SymbolMethod
	if node.Type() == "constructor_declaration" {
		kind = javaprogram.SymbolConstructor
	}
	qualified := e.uniqueQualified(joinJavaQualified(parent.qualified, name), node)
	id := javaprogram.CanonicalSymbolID(e.module, qualified)
	symbol := javaprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id, Kind: kind,
		Pos: e.position(node), Parameters: e.parameters(node.ChildByFieldName("parameters"), id), Annotations: e.modifierAnnotations(node),
	}
	e.doc.Symbols = append(e.doc.Symbols, symbol)
	e.entrypointHints(symbol)
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, javaScope{id: id, qualified: qualified, kind: kind})
	}
}

// walkLambda handles a Java lambda: a synthetic name keyed to its position keeps its parameters and body in
// their own scope, so a request value captured or passed into a lambda still yields intra-lambda value flow.
func (e *javaFactExtractor) walkLambda(node *sitter.Node, parent javaScope) {
	pos := e.position(node)
	name := "<fn@" + strconv.Itoa(pos.Line) + "_" + strconv.Itoa(pos.Column) + ">"
	qualified := e.uniqueQualified(joinJavaQualified(parent.qualified, name), node)
	id := javaprogram.CanonicalSymbolID(e.module, qualified)
	e.doc.Symbols = append(e.doc.Symbols, javaprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id,
		Kind: javaprogram.SymbolLambda, Pos: pos, Parameters: e.parameters(node.ChildByFieldName("parameters"), id),
	})
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, javaScope{id: id, qualified: qualified, kind: javaprogram.SymbolLambda})
	}
}

// importFact lowers one import_declaration into a javaprogram.Import. The declaration wraps a
// scoped_identifier (the dotted path), an optional `static` keyword, and an optional trailing `*`
// (on-demand). Module/Name/Kind follow the domain contract so the taint engine can anchor a sink to a
// package without a classpath.
func (e *javaFactExtractor) importFact(node *sitter.Node, scope javaScope) {
	static := false
	onDemand := false
	var pathNode *sitter.Node
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "static":
			static = true
		case "asterisk":
			onDemand = true
		case "scoped_identifier", "identifier":
			pathNode = child
		}
	}
	if pathNode == nil {
		e.gap(javaprogram.GapUnresolvedImport, scope.id, "import_syntax", node)
		return
	}
	segments := e.dottedSegments(pathNode)
	if len(segments) == 0 {
		e.gap(javaprogram.GapUnresolvedImport, scope.id, "import_syntax", node)
		return
	}
	item := javaprogram.Import{ScopeID: scope.id, Pos: e.position(node)}
	switch {
	case onDemand && static:
		item.Kind = javaprogram.ImportStaticOnDemand
		item.Module = strings.Join(segments, ".")
	case onDemand:
		item.Kind = javaprogram.ImportOnDemand
		item.Module = strings.Join(segments, ".")
	case static:
		// import static java.lang.Math.max; -> module java.lang.Math, name max.
		if len(segments) < 2 {
			e.gap(javaprogram.GapUnresolvedImport, scope.id, "import_syntax", node)
			return
		}
		item.Kind = javaprogram.ImportStatic
		item.Module = strings.Join(segments[:len(segments)-1], ".")
		item.Name = segments[len(segments)-1]
	default:
		// import java.sql.Statement; -> module java.sql.Statement, name Statement.
		item.Kind = javaprogram.ImportSingle
		item.Module = strings.Join(segments, ".")
		item.Name = segments[len(segments)-1]
	}
	e.doc.Imports = append(e.doc.Imports, item)
}

func (e *javaFactExtractor) callFact(node *sitter.Node, scope javaScope, isNew bool) {
	callee, resolvable := e.callee(node, isNew)
	call := javaprogram.Call{
		ID: javaFactID(e.file, node), CallerID: scope.id, Callee: callee, ResultID: e.valueFor(node, scope),
		Pos: e.position(node), New: isNew,
	}
	if !isNew {
		if object := node.ChildByFieldName("object"); object != nil {
			call.ReceiverValueID = e.valueFor(object, scope)
		}
	}
	if !resolvable {
		e.gap(javaprogram.GapUnresolvedCall, scope.id, "call_target", node)
	}
	e.reflectionGap(callee, isNew, scope, node)
	if args := node.ChildByFieldName("arguments"); args != nil {
		for i := 0; i < int(args.NamedChildCount()); i++ {
			argNode := args.NamedChild(i)
			arg := javaprogram.Argument{Value: e.reference(argNode), ValueID: e.valueFor(argNode, scope), Pos: e.position(argNode)}
			if arg.Value.Kind == javaprogram.ReferenceUnknown && arg.ValueID == "" {
				e.gap(javaprogram.GapUnresolvedValue, scope.id, "call_argument", argNode)
			}
			call.Arguments = append(call.Arguments, arg)
		}
	}
	e.doc.Calls = append(e.doc.Calls, call)
}

// reflectionGap records a dynamic-execution coverage gap for the reflection / dynamic-proxy / script-engine
// surfaces whose behaviour source-only facts cannot follow, so a downstream negative is not read as proof.
func (e *javaFactExtractor) reflectionGap(callee javaprogram.Reference, isNew bool, scope javaScope, node *sitter.Node) {
	if len(callee.Segments) == 0 {
		return
	}
	last := callee.Segments[len(callee.Segments)-1]
	if isNew {
		if last == "ScriptEngineManager" {
			e.gap(javaprogram.GapDynamicExecution, scope.id, "script_engine", node)
		}
		return
	}
	switch last {
	case "forName", "invoke", "newProxyInstance", "getMethod", "getDeclaredMethod", "loadClass":
		e.gap(javaprogram.GapDynamicExecution, scope.id, "reflection", node)
	}
}

func (e *javaFactExtractor) assignmentFact(node *sitter.Node, scope javaScope) {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	if left == nil || right == nil {
		return
	}
	targets := e.targets(left)
	if len(targets) == 0 {
		return
	}
	value := e.reference(right)
	valueID := e.valueFor(right, scope)
	if value.Kind == javaprogram.ReferenceUnknown && valueID == "" {
		e.gap(javaprogram.GapUnresolvedValue, scope.id, "assignment_value", node)
	}
	targetIDs := e.bindingValues(left, scope)
	for _, targetID := range targetIDs {
		e.addValueFlow(valueID, targetID, javaprogram.FlowAssignment, node)
	}
	e.doc.Assignments = append(e.doc.Assignments, javaprogram.Assignment{
		ScopeID: scope.id, Targets: targets, TargetIDs: targetIDs, Value: value, ValueID: valueID, Pos: e.position(node),
	})
}

func (e *javaFactExtractor) variableDeclaratorFact(node *sitter.Node, scope javaScope) {
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")
	if nameNode == nil || valueNode == nil {
		return
	}
	targets := e.targets(nameNode)
	if len(targets) == 0 {
		return
	}
	value := e.reference(valueNode)
	valueID := e.valueFor(valueNode, scope)
	if value.Kind == javaprogram.ReferenceUnknown && valueID == "" {
		e.gap(javaprogram.GapUnresolvedValue, scope.id, "declarator_value", node)
	}
	targetIDs := e.bindingValues(nameNode, scope)
	for _, targetID := range targetIDs {
		e.addValueFlow(valueID, targetID, javaprogram.FlowAssignment, node)
	}
	e.doc.Assignments = append(e.doc.Assignments, javaprogram.Assignment{
		ScopeID: scope.id, Targets: targets, TargetIDs: targetIDs, Value: value, ValueID: valueID, Pos: e.position(node),
	})
}

func (e *javaFactExtractor) returnFact(node *sitter.Node, scope javaScope) {
	value := javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}
	valueNode := firstNamedChild(node)
	if valueNode != nil {
		value = e.reference(valueNode)
	}
	valueID := e.valueFor(valueNode, scope)
	if value.Kind == javaprogram.ReferenceUnknown && valueID == "" {
		e.gap(javaprogram.GapUnresolvedValue, scope.id, "return_value", node)
	}
	slotID := scope.id + "#return"
	e.addValue(javaprogram.Value{
		ID: slotID, ScopeID: scope.id, Kind: javaprogram.ValueReturn,
		Ref: javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}, Pos: e.position(node),
	})
	e.addValueFlow(valueID, slotID, javaprogram.FlowReturn, node)
	e.doc.Returns = append(e.doc.Returns, javaprogram.Return{ScopeID: scope.id, Value: value, ValueID: valueID, SlotID: slotID, Pos: e.position(node)})
}

// valueFor returns the stable value-slot id for an expression node, creating the slot (and its
// intra-procedural sub-flows) on first sight. Container-granular member access mirrors the JS/Python twins.
func (e *javaFactExtractor) valueFor(node *sitter.Node, scope javaScope) string {
	if node == nil {
		return ""
	}
	if !e.enterExpr() {
		return ""
	}
	defer e.leaveExpr()
	id := javaValueID(e.file, node, "value")
	if e.values[id] {
		return id
	}
	ref := e.reference(node)
	kind := javaprogram.ValueExpression
	switch {
	case node.Type() == "method_invocation" || node.Type() == "object_creation_expression":
		kind = javaprogram.ValueCallResult
	case node.Type() == "identifier" || node.Type() == "field_access" || node.Type() == "scoped_identifier" || node.Type() == "this":
		kind = javaprogram.ValueReference
	case ref.Kind == javaprogram.ReferenceLiteral && node.NamedChildCount() == 0:
		kind = javaprogram.ValueLiteral
	default:
		ref = javaprogram.Reference{Kind: javaprogram.ReferenceExpression}
	}
	e.addValue(javaprogram.Value{ID: id, ScopeID: scope.id, Kind: kind, Ref: ref, Pos: e.position(node)})

	switch node.Type() {
	case "method_invocation", "object_creation_expression":
		// Argument/receiver-to-result propagation is function-model / interprocedural behavior applied by the
		// value-flow engine, not a syntactic flow.
		return id
	case "field_access":
		e.addValueFlow(e.valueFor(node.ChildByFieldName("object"), scope), id, javaprogram.FlowAttribute, node)
		return id
	case "array_access":
		// Container-granular: the value of a[k] flows from the array container `a`, never a specific index.
		e.addValueFlow(e.valueFor(node.ChildByFieldName("array"), scope), id, javaprogram.FlowAttribute, node)
		return id
	case "identifier", "scoped_identifier", "this":
		return id
	case "lambda_expression", "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		// A nested callable/type owns its own scope, walked separately; never flow its body into the enclosing
		// expression (that would create a cross-scope value flow the validator rejects).
		return id
	case "parenthesized_expression":
		if inner := firstNamedChild(node); inner != nil {
			e.addValueFlow(e.valueFor(inner, scope), id, javaprogram.FlowExpression, node)
		}
		return id
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		e.addValueFlow(e.valueFor(node.NamedChild(i), scope), id, javaprogram.FlowExpression, node)
	}
	return id
}

func (e *javaFactExtractor) bindingValues(node *sitter.Node, scope javaScope) []string {
	if node == nil {
		return nil
	}
	if !e.enterExpr() {
		return nil
	}
	defer e.leaveExpr()
	switch node.Type() {
	case "field_access":
		// Container-granular write: this.x = v / a.b = v taints the container `this`/`a`.
		return e.bindingValues(node.ChildByFieldName("object"), scope)
	case "array_access":
		return e.bindingValues(node.ChildByFieldName("array"), scope)
	}
	ref := e.reference(node)
	if ref.Kind == javaprogram.ReferenceName || ref.Kind == javaprogram.ReferenceAttribute {
		id := javaValueID(e.file, node, "binding")
		name := ref.Segments[len(ref.Segments)-1]
		e.addValue(javaprogram.Value{ID: id, ScopeID: scope.id, Kind: javaprogram.ValueBinding, Name: name, Ref: ref, Pos: e.position(node)})
		return []string{id}
	}
	return nil
}

func (e *javaFactExtractor) targets(node *sitter.Node) []javaprogram.Reference {
	if node == nil {
		return nil
	}
	if !e.enterExpr() {
		return nil
	}
	defer e.leaveExpr()
	switch node.Type() {
	case "field_access":
		return e.targets(node.ChildByFieldName("object"))
	case "array_access":
		return e.targets(node.ChildByFieldName("array"))
	}
	ref := e.reference(node)
	if ref.Kind == javaprogram.ReferenceName || ref.Kind == javaprogram.ReferenceAttribute {
		return []javaprogram.Reference{ref}
	}
	return nil
}

func (e *javaFactExtractor) addValue(value javaprogram.Value) {
	if value.ID == "" || e.values[value.ID] {
		return
	}
	e.values[value.ID] = true
	e.doc.Values = append(e.doc.Values, value)
}

func (e *javaFactExtractor) addValueFlow(from, to string, kind javaprogram.ValueFlowKind, node *sitter.Node) {
	if from == "" || to == "" || from == to {
		return
	}
	key := from + "\x00" + to + "\x00" + string(kind)
	if e.flows[key] {
		return
	}
	e.flows[key] = true
	e.doc.Flows = append(e.doc.Flows, javaprogram.ValueFlow{FromID: from, ToID: to, Kind: kind, Pos: e.position(node)})
}

// callee builds the callee reference for a method_invocation or object_creation_expression per the taint
// engine's encoding contract. It returns (reference, resolvable): resolvable is false when the callee is a
// shape the facts cannot name (a call on an array element or a parenthesized expression), for which the
// caller records a GapUnresolvedCall.
func (e *javaFactExtractor) callee(node *sitter.Node, isNew bool) (javaprogram.Reference, bool) {
	if isNew {
		segments := e.typeSegments(node.ChildByFieldName("type"))
		if len(segments) == 0 {
			return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}, false
		}
		kind := javaprogram.ReferenceAttribute
		if len(segments) == 1 {
			kind = javaprogram.ReferenceName
		}
		return javaprogram.Reference{Kind: kind, Segments: segments}, true
	}
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}, false
	}
	name := nameNode.Content(e.source)
	if !javaValidSegment(name) {
		return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}, false
	}
	object := node.ChildByFieldName("object")
	if object == nil {
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{name}}, true
	}
	recv, ok := e.receiverPath(object)
	if !ok {
		return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}, false
	}
	return javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: append(recv, name)}, true
}

// receiverPath returns the dotted segment path of a method-call receiver, extending through nested member
// accesses and call chains (Runtime.getRuntime() -> ["Runtime","getRuntime"]) so the taint engine's
// method-name floor can match a chain like Runtime.getRuntime().exec. A receiver that is not a nameable
// dotted path (an array element, a parenthesized/cast expression) returns ok=false.
func (e *javaFactExtractor) receiverPath(node *sitter.Node) ([]string, bool) {
	if node == nil {
		return nil, false
	}
	if !e.enterExpr() {
		return nil, false
	}
	defer e.leaveExpr()
	switch node.Type() {
	case "identifier", "type_identifier":
		content := node.Content(e.source)
		if !javaValidSegment(content) {
			return nil, false
		}
		return []string{content}, true
	case "this":
		return []string{"this"}, true
	case "super":
		return []string{"super"}, true
	case "scoped_identifier":
		segments := e.dottedSegments(node)
		if len(segments) == 0 {
			return nil, false
		}
		return segments, true
	case "field_access":
		base, ok := e.receiverPath(node.ChildByFieldName("object"))
		if !ok {
			return nil, false
		}
		field := node.ChildByFieldName("field")
		if field == nil || !javaValidSegment(field.Content(e.source)) {
			return nil, false
		}
		return append(base, field.Content(e.source)), true
	case "method_invocation":
		name := node.ChildByFieldName("name")
		if name == nil || !javaValidSegment(name.Content(e.source)) {
			return nil, false
		}
		object := node.ChildByFieldName("object")
		if object == nil {
			return []string{name.Content(e.source)}, true
		}
		base, ok := e.receiverPath(object)
		if !ok {
			return nil, false
		}
		return append(base, name.Content(e.source)), true
	}
	return nil, false
}

// reference summarizes an expression as a bounded shape. Source text is never retained.
func (e *javaFactExtractor) reference(node *sitter.Node) javaprogram.Reference {
	if node == nil {
		return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
	}
	if !e.enterExpr() {
		return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
	}
	defer e.leaveExpr()
	switch node.Type() {
	case "identifier", "type_identifier":
		content := node.Content(e.source)
		if !javaValidSegment(content) {
			return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
		}
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{content}}
	case "this":
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"this"}}
	case "super":
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{"super"}}
	case "scoped_identifier":
		segments := e.dottedSegments(node)
		if len(segments) == 0 {
			return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
		}
		if len(segments) == 1 {
			return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: segments}
		}
		return javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: segments}
	case "field_access":
		base := e.reference(node.ChildByFieldName("object"))
		field := node.ChildByFieldName("field")
		if field == nil || (base.Kind != javaprogram.ReferenceName && base.Kind != javaprogram.ReferenceAttribute) {
			return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
		}
		content := field.Content(e.source)
		if !javaValidSegment(content) {
			return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
		}
		return javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: append(append([]string{}, base.Segments...), content)}
	case "method_invocation":
		callee, ok := e.callee(node, false)
		if !ok || callee.Kind == javaprogram.ReferenceUnknown {
			return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
		}
		callee.Kind = javaprogram.ReferenceCall
		return callee
	case "object_creation_expression":
		callee, ok := e.callee(node, true)
		if !ok || callee.Kind == javaprogram.ReferenceUnknown {
			return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
		}
		callee.Kind = javaprogram.ReferenceCall
		return callee
	case "parenthesized_expression":
		if inner := firstNamedChild(node); inner != nil {
			return e.reference(inner)
		}
	case "string_literal", "character_literal", "decimal_integer_literal", "hex_integer_literal",
		"octal_integer_literal", "binary_integer_literal", "decimal_floating_point_literal",
		"hex_floating_point_literal", "true", "false", "null_literal", "class_literal":
		return javaprogram.Reference{Kind: javaprogram.ReferenceLiteral}
	}
	return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
}

// parameters lowers a formal_parameters node into declaration-ordered parameters. Each parameter carries a
// ValueParameter slot and its Java annotations (so an annotated web-input parameter can be a source), and a
// spread_parameter (String... args) is tagged ParameterVararg.
func (e *javaFactExtractor) parameters(node *sitter.Node, scopeID string) []javaprogram.Parameter {
	if node == nil {
		return nil
	}
	var out []javaprogram.Parameter
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		kind := javaprogram.ParameterPositional
		switch child.Type() {
		case "formal_parameter":
		case "spread_parameter":
			kind = javaprogram.ParameterVararg
		default:
			continue // receiver_parameter and any non-parameter node carry no bindable name
		}
		nameNode := child.ChildByFieldName("name")
		if nameNode == nil {
			continue
		}
		name := e.safeName(nameNode.Content(e.source), child)
		valueID := scopeID + "#param:" + strconv.Itoa(len(out)) + ":" + name
		pos := e.position(child)
		e.addValue(javaprogram.Value{
			ID: valueID, ScopeID: scopeID, Kind: javaprogram.ValueParameter, Name: name,
			Ref: javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: []string{name}}, Pos: pos,
		})
		out = append(out, javaprogram.Parameter{Name: name, Kind: kind, ValueID: valueID, Annotations: e.parameterAnnotations(child), Pos: pos})
	}
	return out
}

// parameterAnnotations returns the annotation references on a formal/spread parameter. Annotations live in
// the parameter's `modifiers` child.
func (e *javaFactExtractor) parameterAnnotations(node *sitter.Node) []javaprogram.Reference {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if child := node.NamedChild(i); child.Type() == "modifiers" {
			return e.annotationsIn(child)
		}
	}
	return nil
}

// modifierAnnotations returns the annotation references declared on a type/method via its `modifiers` child
// (@RestController, @RequestMapping, ...).
func (e *javaFactExtractor) modifierAnnotations(node *sitter.Node) []javaprogram.Reference {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if child := node.NamedChild(i); child.Type() == "modifiers" {
			return e.annotationsIn(child)
		}
	}
	return nil
}

func (e *javaFactExtractor) annotationsIn(modifiers *sitter.Node) []javaprogram.Reference {
	var out []javaprogram.Reference
	for i := 0; i < int(modifiers.NamedChildCount()); i++ {
		child := modifiers.NamedChild(i)
		if child.Type() != "annotation" && child.Type() != "marker_annotation" {
			continue
		}
		nameNode := child.ChildByFieldName("name")
		if nameNode == nil {
			continue
		}
		segments := e.dottedSegments(nameNode)
		if len(segments) == 0 {
			continue
		}
		kind := javaprogram.ReferenceAttribute
		if len(segments) == 1 {
			kind = javaprogram.ReferenceName
		}
		out = append(out, javaprogram.Reference{Kind: kind, Segments: segments})
	}
	return out
}

// typeBases returns the extends superclass and implements interfaces of a type declaration as references.
func (e *javaFactExtractor) typeBases(node *sitter.Node) []javaprogram.Reference {
	var out []javaprogram.Reference
	if superclass := node.ChildByFieldName("superclass"); superclass != nil {
		for i := 0; i < int(superclass.NamedChildCount()); i++ {
			if ref := e.baseReference(superclass.NamedChild(i)); ref.Kind != javaprogram.ReferenceUnknown {
				out = append(out, ref)
			}
		}
	}
	if interfaces := node.ChildByFieldName("interfaces"); interfaces != nil {
		list := interfaces
		for i := 0; i < int(interfaces.NamedChildCount()); i++ {
			if interfaces.NamedChild(i).Type() == "type_list" {
				list = interfaces.NamedChild(i)
				break
			}
		}
		for i := 0; i < int(list.NamedChildCount()); i++ {
			if ref := e.baseReference(list.NamedChild(i)); ref.Kind != javaprogram.ReferenceUnknown {
				out = append(out, ref)
			}
		}
	}
	return out
}

func (e *javaFactExtractor) baseReference(node *sitter.Node) javaprogram.Reference {
	segments := e.typeSegments(node)
	if len(segments) == 0 {
		return javaprogram.Reference{Kind: javaprogram.ReferenceUnknown}
	}
	if len(segments) == 1 {
		return javaprogram.Reference{Kind: javaprogram.ReferenceName, Segments: segments}
	}
	return javaprogram.Reference{Kind: javaprogram.ReferenceAttribute, Segments: segments}
}

// typeSegments extracts the dotted name of a type node (type_identifier, scoped_type_identifier, or a
// generic_type's raw type), skipping type arguments and array dimensions. Each segment is validated.
func (e *javaFactExtractor) typeSegments(node *sitter.Node) []string {
	if node == nil {
		return nil
	}
	if !e.enterExpr() {
		return nil
	}
	defer e.leaveExpr()
	switch node.Type() {
	case "type_identifier", "identifier":
		content := node.Content(e.source)
		if !javaValidSegment(content) {
			return nil
		}
		return []string{content}
	case "scoped_type_identifier", "scoped_identifier":
		var out []string
		for i := 0; i < int(node.NamedChildCount()); i++ {
			seg := e.typeSegments(node.NamedChild(i))
			if seg == nil {
				return nil
			}
			out = append(out, seg...)
		}
		return out
	case "generic_type", "annotated_type", "array_type":
		if inner := firstNamedChild(node); inner != nil {
			return e.typeSegments(inner)
		}
	}
	return nil
}

// dottedSegments returns the identifier chain of a scoped_identifier / identifier used in imports and
// annotation names. Each segment is validated.
func (e *javaFactExtractor) dottedSegments(node *sitter.Node) []string {
	if node == nil {
		return nil
	}
	if !e.enterExpr() {
		return nil
	}
	defer e.leaveExpr()
	switch node.Type() {
	case "identifier", "type_identifier":
		content := node.Content(e.source)
		if !javaValidSegment(content) {
			return nil
		}
		return []string{content}
	case "scoped_identifier", "scoped_type_identifier":
		var out []string
		for i := 0; i < int(node.NamedChildCount()); i++ {
			seg := e.dottedSegments(node.NamedChild(i))
			if seg == nil {
				return nil
			}
			out = append(out, seg...)
		}
		return out
	}
	return nil
}

func (e *javaFactExtractor) entrypointHints(symbol javaprogram.Symbol) {
	if symbol.Kind == javaprogram.SymbolMethod && symbol.Name == "main" {
		e.doc.Entrypoints = append(e.doc.Entrypoints, javaprogram.EntrypointHint{SymbolID: symbol.ID, Kind: "conventional_main", Pos: symbol.Pos})
	}
	for _, annotation := range symbol.Annotations {
		if len(annotation.Segments) == 0 {
			continue
		}
		switch annotation.Segments[len(annotation.Segments)-1] {
		case "RequestMapping", "GetMapping", "PostMapping", "PutMapping", "PatchMapping", "DeleteMapping":
			e.doc.Entrypoints = append(e.doc.Entrypoints, javaprogram.EntrypointHint{SymbolID: symbol.ID, Kind: "framework_route", Pos: symbol.Pos})
		}
	}
}

func (e *javaFactExtractor) gap(kind javaprogram.GapKind, symbolID, detail string, node *sitter.Node) {
	pos := javaprogram.Position{}
	if node != nil {
		pos = e.position(node)
	}
	key := string(kind) + "\x00" + symbolID + "\x00" + detail + "\x00" + pos.File + "\x00" + strconv.Itoa(pos.Line) + "\x00" + strconv.Itoa(pos.Column)
	if e.gapKeys[key] {
		return
	}
	e.gapKeys[key] = true
	e.doc.CoverageGaps = append(e.doc.CoverageGaps, javaprogram.CoverageGap{Kind: kind, SymbolID: symbolID, Detail: detail, Pos: pos})
}

func (e *javaFactExtractor) position(node *sitter.Node) javaprogram.Position {
	if node == nil {
		return javaprogram.Position{File: e.file, Line: 1}
	}
	point := node.StartPoint()
	return javaprogram.Position{File: e.file, Line: int(point.Row) + 1, Column: int(point.Column)}
}

func (e *javaFactExtractor) factCount() int {
	return len(e.doc.Symbols) + len(e.doc.Imports) + len(e.doc.Calls) + len(e.doc.Assignments) + len(e.doc.Returns) +
		len(e.doc.Values) + len(e.doc.Flows) + len(e.doc.CoverageGaps)
}

// safeName sanitizes a declaration name to a valid Java identifier so a symbol/parameter fact is never
// rejected by the domain validator. A valid, bounded identifier is kept; anything else is reduced to its
// valid leading characters, or a position-based fallback.
func (e *javaFactExtractor) safeName(name string, node *sitter.Node) string {
	if javaValidSegment(name) && len(name) <= 256 {
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
	if out := b.String(); javaValidSegment(out) {
		return out
	}
	return "_id" + e.posSuffix(node)
}

// uniqueQualified keeps a qualified name unique within the module: a colliding (overloaded) declaration is
// suffixed with a position ("Name@line_col"), a form the domain qualified-name validator accepts, so it
// keeps a distinct symbol id instead of the whole document being rejected as a duplicate.
func (e *javaFactExtractor) uniqueQualified(qualified string, node *sitter.Node) string {
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

func (e *javaFactExtractor) posSuffix(node *sitter.Node) string {
	if node == nil {
		return "0_0"
	}
	point := node.StartPoint()
	return strconv.Itoa(int(point.Row)+1) + "_" + strconv.Itoa(int(point.Column))
}

// --- pure helpers ---

func joinJavaQualified(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

func javaFactID(file string, node *sitter.Node) string {
	start, end := node.StartPoint(), node.EndPoint()
	return file + ":" + strconv.Itoa(int(start.Row)+1) + ":" + strconv.Itoa(int(start.Column)) + ":" +
		strconv.Itoa(int(end.Row)+1) + ":" + strconv.Itoa(int(end.Column))
}

func javaValueID(file string, node *sitter.Node, role string) string {
	start, end := node.StartPoint(), node.EndPoint()
	return file + ":" + strconv.Itoa(int(start.Row)+1) + ":" + strconv.Itoa(int(start.Column)) + ":" +
		strconv.Itoa(int(end.Row)+1) + ":" + strconv.Itoa(int(end.Column)) + ":" + role
}

// javaModuleName derives a module path from a source path: the path without its .java extension, each
// segment sanitized to the character set the domain module-path validator accepts.
func javaModuleName(rel string) (string, bool) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if !strings.EqualFold(filepath.Ext(rel), ".java") {
		return "", false
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, "/")
	if len(parts) == 0 {
		return "", false
	}
	for i, part := range parts {
		parts[i] = javaSanitizePathSegment(part)
		if parts[i] == "" {
			return "", false
		}
	}
	return strings.Join(parts, "/"), true
}

func javaSanitizePathSegment(part string) string {
	part = strings.TrimSpace(part)
	if part == "" || part == "." || part == ".." {
		return ""
	}
	var b strings.Builder
	for _, r := range part {
		switch {
		case r == '_' || r == '$' || r == '-' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r):
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

func javaModuleLeaf(module string) string {
	leaf := module
	if at := strings.LastIndexByte(module, '/'); at >= 0 {
		leaf = module[at+1:]
	}
	var b strings.Builder
	for i, r := range leaf {
		switch {
		case r == '_' || r == '$' || unicode.IsLetter(r):
			b.WriteRune(r)
		case i > 0 && unicode.IsDigit(r):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "_"
	}
	if r := rune(out[0]); !(r == '_' || r == '$' || unicode.IsLetter(r)) {
		return "_" + out
	}
	return out
}

// javaValidSegment mirrors javaprogram.validName: a Java identifier where '_' and '$' are legal, and '*' is
// rejected. Only segments this accepts are emitted, so the domain validator never rejects the document.
func javaValidSegment(value string) bool {
	if value == "" || value == "*" || len(value) > 4096 {
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
