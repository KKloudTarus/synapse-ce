//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	maxPythonFactNodes = 2_000_000
	maxPythonFacts     = 4_000_000
)

// PythonFactsFor extracts a bounded, versioned Python semantic-facts document without importing or
// executing target code. Parser recovery and unresolved dynamic shapes are explicit coverage gaps.
func PythonFactsFor(ctx context.Context, root string) (pythonprogram.Document, error) {
	doc := pythonprogram.Document{SchemaVersion: pythonprogram.SchemaVersion}
	modules := map[string]bool{}
	notebookGaps := map[string]bool{}
	walkTruncated, err := walkSourceWithIssues(ctx, root, func(rel, lang string, content []byte) {
		if lang != "Python" {
			return
		}
		doc.FilesSeen++
		rel = filepath.ToSlash(rel)
		if strings.Contains(strings.ToLower(rel), ".ipynb#cell-") {
			base := rel
			if at := strings.Index(strings.ToLower(base), ".ipynb#cell-"); at >= 0 {
				base = base[:at+len(".ipynb")]
			}
			if !notebookGaps[base] {
				notebookGaps[base] = true
				doc.CoverageGaps = append(doc.CoverageGaps, pythonprogram.CoverageGap{
					Kind: pythonprogram.GapUnsupportedNotebook, Detail: "notebook_cells", Pos: pythonprogram.Position{File: base, Line: 1},
				})
			}
			return
		}
		module, ok := pythonModuleName(rel)
		if !ok {
			doc.CoverageGaps = append(doc.CoverageGaps, pythonprogram.CoverageGap{
				Kind: pythonprogram.GapUnresolvedImport, Detail: "invalid_module_path", Pos: pythonprogram.Position{File: rel, Line: 1},
			})
			return
		}
		if modules[module] {
			doc.CoverageGaps = append(doc.CoverageGaps, pythonprogram.CoverageGap{
				Kind: pythonprogram.GapUnresolvedImport, Detail: "ambiguous_module_path", Pos: pythonprogram.Position{File: rel, Line: 1},
			})
			return
		}
		modules[module] = true
		rootNode := parseRoot(ctx, specs["Python"], content)
		if rootNode == nil {
			doc.CoverageGaps = append(doc.CoverageGaps, pythonprogram.CoverageGap{
				Kind: pythonprogram.GapParseRecovery, Detail: "parse_failed", Pos: pythonprogram.Position{File: rel, Line: 1},
			})
			return
		}
		doc.FilesParsed++
		modulePos := pythonprogram.Position{File: rel, Line: 1}
		moduleID := pythonSymbolID(module, "<module>")
		doc.Modules = append(doc.Modules, pythonprogram.Module{Name: module, File: rel, Pos: modulePos})
		doc.Symbols = append(doc.Symbols, pythonprogram.Symbol{
			ID: moduleID, Module: module, QualifiedName: "<module>", Name: pythonModuleLeaf(module), Kind: pythonprogram.SymbolModule, Pos: modulePos,
		})
		doc.Entrypoints = append(doc.Entrypoints, pythonprogram.EntrypointHint{SymbolID: moduleID, Kind: "module_import", Pos: modulePos})
		extractor := pythonFactExtractor{
			doc: &doc, module: module, file: rel, source: content,
			values: map[string]bool{}, flows: map[string]bool{},
		}
		if rootNode.HasError() {
			extractor.gap(pythonprogram.GapParseRecovery, moduleID, "parser_recovery", rootNode)
		}
		extractor.walk(rootNode, pythonScope{id: moduleID, qualified: "", kind: pythonprogram.SymbolModule})
	}, func(issue sourceIssue) {
		doc.FilesSeen++
		kind := pythonprogram.GapUnreadable
		if issue.Reason == sourceIssueOversized {
			kind = pythonprogram.GapBudget
		}
		if issue.Reason == sourceIssueMalformedNotebook {
			kind = pythonprogram.GapUnsupportedNotebook
		}
		doc.CoverageGaps = append(doc.CoverageGaps, pythonprogram.CoverageGap{
			Kind: kind, Detail: string(issue.Reason), Pos: pythonprogram.Position{File: filepath.ToSlash(issue.Rel), Line: 1},
		})
	})
	if err != nil {
		return pythonprogram.Document{}, err
	}
	if walkTruncated {
		doc.Truncated = true
		doc.CoverageGaps = append(doc.CoverageGaps, pythonprogram.CoverageGap{Kind: pythonprogram.GapBudget, Detail: "file_budget"})
	}
	doc.SortCanonical()
	if err := doc.Validate(); err != nil {
		return pythonprogram.Document{}, fmt.Errorf("validate extracted python facts: %w", err)
	}
	return doc, nil
}

type pythonScope struct {
	id        string
	qualified string
	kind      pythonprogram.SymbolKind
}

type pythonFactExtractor struct {
	doc       *pythonprogram.Document
	module    string
	file      string
	source    []byte
	budgetHit bool
	values    map[string]bool
	flows     map[string]bool
}

func (e *pythonFactExtractor) walk(node *sitter.Node, scope pythonScope) {
	if node == nil || e.budgetHit {
		return
	}
	e.doc.NodesSeen++
	if e.doc.NodesSeen > maxPythonFactNodes || e.factCount() > maxPythonFacts {
		e.doc.Truncated = true
		e.budgetHit = true
		e.gap(pythonprogram.GapBudget, scope.id, "node_or_fact_budget", node)
		return
	}
	switch node.Type() {
	case "decorated_definition":
		e.walkDecorated(node, scope)
		return
	case "function_definition":
		e.walkFunction(node, scope, nil)
		return
	case "class_definition":
		e.walkClass(node, scope, nil)
		return
	case "lambda":
		e.walkLambda(node, scope)
		return
	case "import_statement", "import_from_statement":
		e.importFacts(node, scope)
		return
	case "call":
		e.callFact(node, scope)
	case "assignment", "annotated_assignment", "augmented_assignment", "named_expression":
		e.assignmentFact(node, scope)
	case "for_statement", "for_in_clause":
		e.bindingFact(node, scope, "left", "right")
	case "with_item":
		e.bindingFact(node, scope, "alias", "value")
	case "return_statement":
		e.returnFact(node, scope)
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		e.walk(node.NamedChild(i), scope)
	}
}

func (e *pythonFactExtractor) walkDecorated(node *sitter.Node, scope pythonScope) {
	var decorators []pythonprogram.Reference
	var definition *sitter.Node
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "decorator" {
			if child.NamedChildCount() > 0 {
				ref := e.reference(child.NamedChild(0))
				if ref.Kind == pythonprogram.ReferenceUnknown {
					e.gap(pythonprogram.GapUnsupportedDecorator, scope.id, "decorator_shape", child)
				} else {
					decorators = append(decorators, ref)
				}
			}
			e.walk(child, scope) // decorator calls execute in the owning scope
			continue
		}
		if child.Type() == "function_definition" || child.Type() == "class_definition" {
			definition = child
		}
	}
	if definition == nil {
		e.gap(pythonprogram.GapUnsupportedDecorator, scope.id, "missing_definition", node)
		return
	}
	if definition.Type() == "function_definition" {
		e.walkFunction(definition, scope, decorators)
	} else {
		e.walkClass(definition, scope, decorators)
	}
}

func (e *pythonFactExtractor) walkFunction(node *sitter.Node, parent pythonScope, decorators []pythonprogram.Reference) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		e.gap(pythonprogram.GapUnresolvedCall, parent.id, "function_without_name", node)
		return
	}
	name := nameNode.Content(e.source)
	qualified := joinPythonQualified(parent.qualified, name)
	id := pythonSymbolID(e.module, qualified)
	kind := pythonprogram.SymbolFunction
	if parent.kind == pythonprogram.SymbolClass {
		kind = pythonprogram.SymbolMethod
	}
	symbol := pythonprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id, Kind: kind,
		Pos: e.position(node), Parameters: e.parameters(node.ChildByFieldName("parameters"), id), Decorators: filterKnownReferences(decorators), Async: pythonNodeHasToken(node, "async"),
	}
	e.doc.Symbols = append(e.doc.Symbols, symbol)
	e.entrypointHints(symbol)
	if params := node.ChildByFieldName("parameters"); params != nil {
		e.walk(params, parent) // default expressions execute in the parent scope
	}
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, pythonScope{id: id, qualified: qualified, kind: kind})
	}
}

func (e *pythonFactExtractor) walkClass(node *sitter.Node, parent pythonScope, decorators []pythonprogram.Reference) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		e.gap(pythonprogram.GapUnresolvedCall, parent.id, "class_without_name", node)
		return
	}
	name := nameNode.Content(e.source)
	qualified := joinPythonQualified(parent.qualified, name)
	id := pythonSymbolID(e.module, qualified)
	symbol := pythonprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id,
		Kind: pythonprogram.SymbolClass, Pos: e.position(node), Decorators: filterKnownReferences(decorators),
	}
	if supers := node.ChildByFieldName("superclasses"); supers != nil {
		for i := 0; i < int(supers.NamedChildCount()); i++ {
			base := e.reference(supers.NamedChild(i))
			if base.Kind == pythonprogram.ReferenceUnknown {
				e.gap(pythonprogram.GapUnresolvedValue, parent.id, "class_base", supers.NamedChild(i))
				continue
			}
			symbol.Bases = append(symbol.Bases, base)
		}
	}
	e.doc.Symbols = append(e.doc.Symbols, symbol)
	if supers := node.ChildByFieldName("superclasses"); supers != nil {
		e.walk(supers, parent)
	}
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, pythonScope{id: id, qualified: qualified, kind: pythonprogram.SymbolClass})
	}
}

func (e *pythonFactExtractor) walkLambda(node *sitter.Node, parent pythonScope) {
	pos := e.position(node)
	name := "<lambda@" + strconv.Itoa(pos.Line) + "_" + strconv.Itoa(pos.Column) + ">"
	qualified := joinPythonQualified(parent.qualified, name)
	id := pythonSymbolID(e.module, qualified)
	e.doc.Symbols = append(e.doc.Symbols, pythonprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id,
		Kind: pythonprogram.SymbolLambda, Pos: pos, Parameters: e.parameters(node.ChildByFieldName("parameters"), id),
	})
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, pythonScope{id: id, qualified: qualified, kind: pythonprogram.SymbolLambda})
	}
}

func (e *pythonFactExtractor) importFacts(node *sitter.Node, scope pythonScope) {
	items, ok := parsePythonImport(node.Content(e.source), scope.id, e.position(node))
	if !ok || len(items) == 0 {
		e.gap(pythonprogram.GapUnresolvedImport, scope.id, "import_syntax", node)
		return
	}
	for _, item := range items {
		e.doc.Imports = append(e.doc.Imports, item)
		if item.Wildcard {
			e.gap(pythonprogram.GapWildcardImport, scope.id, "wildcard", node)
		}
	}
}

func (e *pythonFactExtractor) callFact(node *sitter.Node, scope pythonScope) {
	calleeNode := node.ChildByFieldName("function")
	callee := e.reference(calleeNode)
	call := pythonprogram.Call{
		ID: pythonFactID(e.file, node), CallerID: scope.id, Callee: callee, ResultID: e.valueFor(node, scope),
		Pos: e.position(node), Await: node.Parent() != nil && node.Parent().Type() == "await",
	}
	if calleeNode != nil && calleeNode.Type() == "attribute" {
		call.ReceiverValueID = e.valueFor(calleeNode.ChildByFieldName("object"), scope)
	}
	if callee.Kind == pythonprogram.ReferenceUnknown {
		e.gap(pythonprogram.GapUnresolvedCall, scope.id, "call_target", node)
	}
	joined := strings.Join(callee.Segments, ".")
	switch joined {
	case "__import__", "importlib.import_module":
		e.gap(pythonprogram.GapDynamicImport, scope.id, "dynamic_loader", node)
	case "eval", "exec", "compile":
		e.gap(pythonprogram.GapDynamicExecution, scope.id, "dynamic_code", node)
	case "getattr", "setattr", "delattr", "globals", "locals":
		e.gap(pythonprogram.GapDynamicAttribute, scope.id, "dynamic_attribute", node)
	}
	if args := node.ChildByFieldName("arguments"); args != nil {
		for i := 0; i < int(args.NamedChildCount()); i++ {
			argNode := args.NamedChild(i)
			arg := pythonprogram.Argument{}
			valueNode := argNode
			switch argNode.Type() {
			case "keyword_argument":
				if name := argNode.ChildByFieldName("name"); name != nil {
					arg.Keyword = name.Content(e.source)
				}
				valueNode = argNode.ChildByFieldName("value")
			case "list_splat":
				arg.Star = true
				valueNode = firstNamedChild(argNode)
			case "dictionary_splat":
				arg.Keyword = "**"
				valueNode = firstNamedChild(argNode)
			}
			arg.Value = e.reference(valueNode)
			arg.ValueID = e.valueFor(valueNode, scope)
			arg.Pos = e.position(valueNode)
			if arg.Value.Kind == pythonprogram.ReferenceUnknown && arg.ValueID == "" {
				e.gap(pythonprogram.GapUnresolvedValue, scope.id, "call_argument", argNode)
			}
			call.Arguments = append(call.Arguments, arg)
		}
	}
	e.doc.Calls = append(e.doc.Calls, call)
}

func (e *pythonFactExtractor) assignmentFact(node *sitter.Node, scope pythonScope) {
	left := node.ChildByFieldName("left")
	if left == nil {
		left = node.ChildByFieldName("name")
	}
	right := node.ChildByFieldName("right")
	if right == nil {
		right = node.ChildByFieldName("value")
	}
	targets := e.targets(left)
	if len(targets) == 0 {
		return
	}
	value := e.reference(right)
	valueID := e.valueFor(right, scope)
	if value.Kind == pythonprogram.ReferenceUnknown && valueID == "" {
		e.gap(pythonprogram.GapUnresolvedValue, scope.id, "assignment_value", node)
	}
	targetIDs := e.bindingValues(left, scope)
	for _, targetID := range targetIDs {
		e.addValueFlow(valueID, targetID, pythonprogram.FlowAssignment, node)
		if node.Type() == "augmented_assignment" {
			e.addValueFlow(e.valueFor(left, scope), targetID, pythonprogram.FlowAssignment, node)
		}
	}
	e.doc.Assignments = append(e.doc.Assignments, pythonprogram.Assignment{
		ScopeID: scope.id, Targets: targets, TargetIDs: targetIDs, Value: value, ValueID: valueID, Pos: e.position(node),
	})
}

func (e *pythonFactExtractor) bindingFact(node *sitter.Node, scope pythonScope, leftField, rightField string) {
	left := node.ChildByFieldName(leftField)
	right := node.ChildByFieldName(rightField)
	targets := e.targets(left)
	if len(targets) == 0 || right == nil {
		return
	}
	value := e.reference(right)
	valueID := e.valueFor(right, scope)
	if value.Kind == pythonprogram.ReferenceUnknown && valueID == "" {
		e.gap(pythonprogram.GapUnresolvedValue, scope.id, "binding_value", node)
	}
	targetIDs := e.bindingValues(left, scope)
	for _, targetID := range targetIDs {
		e.addValueFlow(valueID, targetID, pythonprogram.FlowAssignment, node)
	}
	e.doc.Assignments = append(e.doc.Assignments, pythonprogram.Assignment{
		ScopeID: scope.id, Targets: targets, TargetIDs: targetIDs, Value: value, ValueID: valueID, Pos: e.position(node),
	})
}

func (e *pythonFactExtractor) returnFact(node *sitter.Node, scope pythonScope) {
	value := pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}
	if node.NamedChildCount() > 0 {
		value = e.reference(node.NamedChild(0))
	}
	valueNode := firstNamedChild(node)
	valueID := e.valueFor(valueNode, scope)
	if value.Kind == pythonprogram.ReferenceUnknown && valueID == "" {
		e.gap(pythonprogram.GapUnresolvedValue, scope.id, "return_value", node)
	}
	slotID := scope.id + "#return"
	e.addValue(pythonprogram.Value{
		ID: slotID, ScopeID: scope.id, Kind: pythonprogram.ValueReturn,
		Ref: pythonprogram.Reference{Kind: pythonprogram.ReferenceUnknown}, Pos: e.position(node),
	})
	e.addValueFlow(valueID, slotID, pythonprogram.FlowReturn, node)
	e.doc.Returns = append(e.doc.Returns, pythonprogram.Return{ScopeID: scope.id, Value: value, ValueID: valueID, SlotID: slotID, Pos: e.position(node)})
}

func (e *pythonFactExtractor) valueFor(node *sitter.Node, scope pythonScope) string {
	if node == nil {
		return ""
	}
	id := pythonValueID(e.file, node, "value")
	if e.values[id] {
		return id
	}
	ref := e.reference(node)
	kind := pythonprogram.ValueExpression
	switch {
	case node.Type() == "call":
		kind = pythonprogram.ValueCallResult
	case node.Type() == "identifier" || node.Type() == "attribute":
		kind = pythonprogram.ValueReference
	case ref.Kind == pythonprogram.ReferenceLiteral && node.NamedChildCount() == 0:
		kind = pythonprogram.ValueLiteral
	default:
		ref = pythonprogram.Reference{Kind: pythonprogram.ReferenceExpression}
	}
	e.addValue(pythonprogram.Value{ID: id, ScopeID: scope.id, Kind: kind, Ref: ref, Pos: e.position(node)})

	switch node.Type() {
	case "call":
		// Argument-to-result propagation is function-model/interprocedural behavior, not a syntax flow.
		return id
	case "attribute":
		from := e.valueFor(node.ChildByFieldName("object"), scope)
		e.addValueFlow(from, id, pythonprogram.FlowAttribute, node)
		return id
	case "identifier":
		return id
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		e.addValueFlow(e.valueFor(child, scope), id, pythonprogram.FlowExpression, node)
	}
	return id
}

func (e *pythonFactExtractor) bindingValues(node *sitter.Node, scope pythonScope) []string {
	if node == nil {
		return nil
	}
	if node.Type() == "subscript" {
		return e.bindingValues(node.ChildByFieldName("value"), scope)
	}
	ref := e.reference(node)
	if ref.Kind == pythonprogram.ReferenceName || ref.Kind == pythonprogram.ReferenceAttribute {
		id := pythonValueID(e.file, node, "binding")
		name := ref.Segments[len(ref.Segments)-1]
		e.addValue(pythonprogram.Value{ID: id, ScopeID: scope.id, Kind: pythonprogram.ValueBinding, Name: name, Ref: ref, Pos: e.position(node)})
		return []string{id}
	}
	var out []string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		out = append(out, e.bindingValues(node.NamedChild(i), scope)...)
	}
	return out
}

func (e *pythonFactExtractor) addValue(value pythonprogram.Value) {
	if value.ID == "" || e.values[value.ID] {
		return
	}
	e.values[value.ID] = true
	e.doc.Values = append(e.doc.Values, value)
}

func (e *pythonFactExtractor) addValueFlow(from, to string, kind pythonprogram.ValueFlowKind, node *sitter.Node) {
	if from == "" || to == "" || from == to {
		return
	}
	key := from + "\x00" + to + "\x00" + string(kind)
	if e.flows[key] {
		return
	}
	e.flows[key] = true
	e.doc.Flows = append(e.doc.Flows, pythonprogram.ValueFlow{FromID: from, ToID: to, Kind: kind, Pos: e.position(node)})
}

func (e *pythonFactExtractor) reference(node *sitter.Node) pythonprogram.Reference {
	if node == nil {
		return pythonprogram.Reference{Kind: pythonprogram.ReferenceUnknown}
	}
	switch node.Type() {
	case "identifier":
		return pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{node.Content(e.source)}}
	case "attribute":
		base := e.reference(node.ChildByFieldName("object"))
		attr := node.ChildByFieldName("attribute")
		if attr == nil || (base.Kind != pythonprogram.ReferenceName && base.Kind != pythonprogram.ReferenceAttribute) {
			return pythonprogram.Reference{Kind: pythonprogram.ReferenceUnknown}
		}
		return pythonprogram.Reference{Kind: pythonprogram.ReferenceAttribute, Segments: append(append([]string{}, base.Segments...), attr.Content(e.source))}
	case "call":
		callee := e.reference(node.ChildByFieldName("function"))
		if callee.Kind == pythonprogram.ReferenceUnknown {
			return callee
		}
		callee.Kind = pythonprogram.ReferenceCall
		return callee
	case "parenthesized_expression", "await", "expression_list":
		if node.NamedChildCount() == 1 {
			return e.reference(node.NamedChild(0))
		}
	case "string", "concatenated_string", "integer", "float", "true", "false", "none", "list", "set", "dictionary", "tuple":
		return pythonprogram.Reference{Kind: pythonprogram.ReferenceLiteral}
	}
	return pythonprogram.Reference{Kind: pythonprogram.ReferenceUnknown}
}

func (e *pythonFactExtractor) targets(node *sitter.Node) []pythonprogram.Reference {
	if node == nil {
		return nil
	}
	if node.Type() == "subscript" {
		// Track writes at container granularity. Python permits arbitrary key/index expressions, so
		// field-sensitive identity is not reliable; conservatively tainting the container avoids
		// dropping flows from d[key] = value to later reads from d[other_key].
		return e.targets(node.ChildByFieldName("value"))
	}
	ref := e.reference(node)
	if ref.Kind == pythonprogram.ReferenceName || ref.Kind == pythonprogram.ReferenceAttribute {
		return []pythonprogram.Reference{ref}
	}
	if node.Type() != "pattern_list" && node.Type() != "tuple" && node.Type() != "list" && node.Type() != "list_pattern" && node.Type() != "tuple_pattern" {
		return nil
	}
	var out []pythonprogram.Reference
	for i := 0; i < int(node.NamedChildCount()); i++ {
		out = append(out, e.targets(node.NamedChild(i))...)
	}
	return out
}

func (e *pythonFactExtractor) parameters(node *sitter.Node, scopeID string) []pythonprogram.Parameter {
	if node == nil {
		return nil
	}
	var out []pythonprogram.Parameter
	keywordOnly := false
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		kind := pythonprogram.ParameterPositional
		switch child.Type() {
		case "list_splat", "list_splat_pattern":
			kind, keywordOnly = pythonprogram.ParameterVarArgs, true
		case "dictionary_splat", "dictionary_splat_pattern":
			kind = pythonprogram.ParameterKwArgs
		case "keyword_separator":
			keywordOnly = true
			continue
		default:
			if keywordOnly {
				kind = pythonprogram.ParameterKeywordOnly
			}
		}
		name := pythonParameterName(child, e.source)
		if name == "" {
			continue
		}
		valueID := scopeID + "#param:" + strconv.Itoa(len(out)) + ":" + name
		pos := e.position(child)
		e.addValue(pythonprogram.Value{
			ID: valueID, ScopeID: scopeID, Kind: pythonprogram.ValueParameter, Name: name,
			Ref: pythonprogram.Reference{Kind: pythonprogram.ReferenceName, Segments: []string{name}}, Pos: pos,
		})
		out = append(out, pythonprogram.Parameter{Name: name, Kind: kind, ValueID: valueID, Pos: pos})
	}
	return out
}

func (e *pythonFactExtractor) entrypointHints(symbol pythonprogram.Symbol) {
	if symbol.Name == "main" {
		e.doc.Entrypoints = append(e.doc.Entrypoints, pythonprogram.EntrypointHint{SymbolID: symbol.ID, Kind: "conventional_main", Pos: symbol.Pos})
	}
	for _, decorator := range symbol.Decorators {
		if len(decorator.Segments) == 0 {
			continue
		}
		last := decorator.Segments[len(decorator.Segments)-1]
		switch last {
		case "route", "get", "post", "put", "patch", "delete", "options", "head", "websocket", "api_view", "action", "command":
			e.doc.Entrypoints = append(e.doc.Entrypoints, pythonprogram.EntrypointHint{SymbolID: symbol.ID, Kind: "framework_route", Pos: symbol.Pos})
		}
	}
}

func (e *pythonFactExtractor) gap(kind pythonprogram.GapKind, symbolID, detail string, node *sitter.Node) {
	pos := pythonprogram.Position{}
	if node != nil {
		pos = e.position(node)
	}
	for _, existing := range e.doc.CoverageGaps {
		if existing.Kind == kind && existing.SymbolID == symbolID && existing.Detail == detail && existing.Pos == pos {
			return
		}
	}
	e.doc.CoverageGaps = append(e.doc.CoverageGaps, pythonprogram.CoverageGap{Kind: kind, SymbolID: symbolID, Detail: detail, Pos: pos})
}

func (e *pythonFactExtractor) position(node *sitter.Node) pythonprogram.Position {
	if node == nil {
		return pythonprogram.Position{File: e.file, Line: 1}
	}
	point := node.StartPoint()
	return pythonprogram.Position{File: e.file, Line: int(point.Row) + 1, Column: int(point.Column)}
}

func (e *pythonFactExtractor) factCount() int {
	return len(e.doc.Symbols) + len(e.doc.Imports) + len(e.doc.Calls) + len(e.doc.Assignments) + len(e.doc.Returns) +
		len(e.doc.Values) + len(e.doc.Flows) + len(e.doc.CoverageGaps)
}

func pythonModuleName(rel string) (string, bool) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if !strings.HasSuffix(strings.ToLower(rel), ".py") {
		return "", false
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, "/")
	if len(parts) > 1 && parts[len(parts)-1] == "__init__" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return "", false
	}
	for _, part := range parts {
		if !pythonIdentifier(part) {
			return "", false
		}
	}
	return strings.Join(parts, "."), true
}

func pythonIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if r == '_' || unicode.IsLetter(r) || i > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

func pythonModuleLeaf(module string) string {
	if at := strings.LastIndexByte(module, '.'); at >= 0 {
		return module[at+1:]
	}
	return module
}

func pythonSymbolID(module, qualified string) string { return "python:" + module + ":" + qualified }

func joinPythonQualified(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

func pythonFactID(file string, node *sitter.Node) string {
	point := node.StartPoint()
	return file + ":" + strconv.Itoa(int(point.Row)+1) + ":" + strconv.Itoa(int(point.Column))
}

func pythonValueID(file string, node *sitter.Node, role string) string {
	start, end := node.StartPoint(), node.EndPoint()
	return file + ":" + strconv.Itoa(int(start.Row)+1) + ":" + strconv.Itoa(int(start.Column)) + ":" +
		strconv.Itoa(int(end.Row)+1) + ":" + strconv.Itoa(int(end.Column)) + ":" + role
}

func firstNamedChild(node *sitter.Node) *sitter.Node {
	if node == nil || node.NamedChildCount() == 0 {
		return nil
	}
	return node.NamedChild(0)
}

func filterKnownReferences(refs []pythonprogram.Reference) []pythonprogram.Reference {
	out := refs[:0]
	for _, ref := range refs {
		if ref.Kind != pythonprogram.ReferenceUnknown {
			out = append(out, ref)
		}
	}
	return out
}

func pythonNodeHasToken(node *sitter.Node, token string) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == token {
			return true
		}
	}
	return false
}

func pythonParameterName(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	if node.Type() == "identifier" {
		return node.Content(source)
	}
	if name := node.ChildByFieldName("name"); name != nil && name.Type() == "identifier" {
		return name.Content(source)
	}
	stack := []*sitter.Node{node}
	for len(stack) > 0 {
		current := stack[0]
		stack = stack[1:]
		if current.Type() == "identifier" {
			return current.Content(source)
		}
		for i := 0; i < int(current.NamedChildCount()); i++ {
			stack = append(stack, current.NamedChild(i))
		}
	}
	return ""
}

func parsePythonImport(source, scopeID string, pos pythonprogram.Position) ([]pythonprogram.Import, bool) {
	source = stripPythonImportComments(source)
	source = strings.Join(strings.Fields(source), " ")
	if strings.HasPrefix(source, "import ") {
		var out []pythonprogram.Import
		for _, raw := range splitPythonComma(strings.TrimSpace(strings.TrimPrefix(source, "import "))) {
			name, alias := splitPythonAlias(raw)
			if !pythonDottedName(name) || alias != "" && !pythonIdentifier(alias) {
				return nil, false
			}
			out = append(out, pythonprogram.Import{ScopeID: scopeID, Module: name, Alias: alias, Pos: pos})
		}
		return out, len(out) > 0
	}
	if !strings.HasPrefix(source, "from ") {
		return nil, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(source, "from "))
	marker := strings.Index(rest, " import ")
	if marker < 0 {
		return nil, false
	}
	from, names := strings.TrimSpace(rest[:marker]), strings.TrimSpace(rest[marker+len(" import "):])
	level := 0
	for level < len(from) && from[level] == '.' {
		level++
	}
	module := strings.TrimSpace(from[level:])
	if module != "" && !pythonDottedName(module) {
		return nil, false
	}
	names = strings.TrimSpace(strings.Trim(names, "()"))
	var out []pythonprogram.Import
	for _, raw := range splitPythonComma(names) {
		name, alias := splitPythonAlias(raw)
		wildcard := name == "*"
		if !wildcard && !pythonIdentifier(name) || alias != "" && !pythonIdentifier(alias) {
			return nil, false
		}
		out = append(out, pythonprogram.Import{ScopeID: scopeID, Module: module, Name: name, Alias: alias, Level: level, Wildcard: wildcard, Pos: pos})
	}
	return out, len(out) > 0
}

func stripPythonImportComments(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		if at := strings.IndexByte(line, '#'); at >= 0 {
			line = line[:at]
		}
		lines[i] = strings.TrimSuffix(strings.TrimSpace(line), "\\")
	}
	return strings.Join(lines, " ")
}

func splitPythonComma(value string) []string {
	value = strings.TrimSpace(strings.Trim(value, "()"))
	parts := strings.Split(value, ",")
	out := parts[:0]
	for _, part := range parts {
		if part = strings.TrimSpace(strings.Trim(part, "()")); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitPythonAlias(value string) (name, alias string) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 3 && fields[1] == "as" {
		return fields[0], fields[2]
	}
	if len(fields) == 1 {
		return fields[0], ""
	}
	return "", ""
}

func pythonDottedName(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if !pythonIdentifier(part) {
			return false
		}
	}
	return true
}
