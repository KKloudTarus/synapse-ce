//go:build cgo

// Package astwalk (cgo build): tree-sitter grammars parse each supported language to count functions and
// compute per-function complexity. Grammars are MIT-licensed C, compiled into this binary only; the server
// and CLI never import this package, they exec the synapse-ast sidecar. Adding a language is one `specs`
// entry. Complexity definitions (deterministic, no LLM):
//
//   - Cyclomatic (McCabe): 1 + one per decision point (if/elif, each loop, each switch case, catch,
//     ternary) + one per boolean operator (&& || / and or). Exact.
//   - Cognitive: starts at 0; each control structure (if, loop, switch, catch, ternary) adds 1 + the
//     current nesting depth and deepens nesting for its body; each else/elif adds 1 (no depth surcharge)
//     and deepens nesting; each boolean operator adds 1. Documented deviations from the published
//     definition: boolean operators are counted per-operator (not per like-operator sequence), Java
//     `else if` is not folded (its nested if is counted), and a nested function is a separate record
//     rather than adding nesting to its parent. Refinements are incremental.
package astwalk

import (
	"context"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
)

func set(types ...string) map[string]bool {
	m := make(map[string]bool, len(types))
	for _, t := range types {
		m[t] = true
	}
	return m
}

// spec is a language's tree-sitter grammar plus the node-type classification the metrics need.
type spec struct {
	lang         *sitter.Language
	funcType     map[string]bool // function/method nodes (a metrics record + a nesting boundary)
	cycDecision  map[string]bool // nodes each adding 1 to cyclomatic
	cogIncrement map[string]bool // control structures adding 1+nesting to cognitive and deepening nesting
	cogElse      map[string]bool // else/elif nodes adding 1 (no surcharge) and deepening nesting
	// boolOpNode/boolOpToken detect a logical-operator node: either the node type itself (Python
	// boolean_operator) or a binary node (JS/Java binary_expression) carrying a && / || child token.
	boolOpNode  map[string]bool
	boolOpBinry map[string]bool
}

var boolTokens = set("&&", "||")

var specs = map[string]spec{
	"Python": {
		lang:         python.GetLanguage(),
		funcType:     set("function_definition"),
		cycDecision:  set("if_statement", "elif_clause", "for_statement", "while_statement", "except_clause", "conditional_expression", "case_clause"),
		cogIncrement: set("if_statement", "for_statement", "while_statement", "except_clause", "conditional_expression", "case_clause"),
		cogElse:      set("elif_clause", "else_clause"),
		boolOpNode:   set("boolean_operator"),
	},
	"JavaScript": {
		lang:         javascript.GetLanguage(),
		funcType:     set("function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "generator_function"),
		cycDecision:  set("if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement", "switch_case", "catch_clause", "ternary_expression"),
		cogIncrement: set("if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement", "switch_statement", "catch_clause", "ternary_expression"),
		cogElse:      set("else_clause"),
		boolOpBinry:  set("binary_expression"),
	},
	"Java": {
		lang:         java.GetLanguage(),
		funcType:     set("method_declaration", "constructor_declaration"),
		cycDecision:  set("if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_label", "catch_clause", "ternary_expression"),
		cogIncrement: set("if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_expression", "catch_clause", "ternary_expression"),
		cogElse:      set(), // Java `else` is a token inside if_statement, not a node; else-if is a nested if (documented)
		boolOpBinry:  set("binary_expression"),
	},
}

// FunctionsFor parses every supported-language file under root and returns accurate per-language function
// counts.
func FunctionsFor(ctx context.Context, root string) (Result, error) {
	res := Result{Functions: map[string]int{}}
	truncated, err := walkSource(ctx, root, func(_ /*rel*/, lang string, content []byte) {
		sp, ok := specs[lang]
		if !ok {
			return
		}
		root := parseRoot(ctx, sp, content)
		if root == nil {
			return
		}
		res.Functions[lang] += countType(root, sp.funcType)
	})
	if err != nil {
		return Result{}, err
	}
	res.Truncated = truncated
	return res, nil
}

// MetricsFor parses every supported-language file under root and returns one record per function with its
// cyclomatic and cognitive complexity.
func MetricsFor(ctx context.Context, root string) (Metrics, error) {
	var m Metrics
	m.Functions = []FunctionMetric{}
	truncated, err := walkSource(ctx, root, func(rel, lang string, content []byte) {
		sp, ok := specs[lang]
		if !ok {
			return
		}
		root := parseRoot(ctx, sp, content)
		if root == nil {
			return
		}
		for _, fn := range collectFunctions(root, sp) {
			cyc, cog := complexity(fn, sp)
			m.Functions = append(m.Functions, FunctionMetric{
				File:       rel,
				Line:       int(fn.StartPoint().Row) + 1,
				Name:       functionName(fn, content),
				Language:   lang,
				Cyclomatic: cyc,
				Cognitive:  cog,
			})
		}
	})
	if err != nil {
		return Metrics{}, err
	}
	m.Truncated = truncated
	return m, nil
}

func parseRoot(ctx context.Context, sp spec, content []byte) *sitter.Node {
	p := sitter.NewParser()
	p.SetLanguage(sp.lang)
	tree, err := p.ParseCtx(ctx, nil, content)
	if err != nil || tree == nil {
		return nil
	}
	return tree.RootNode()
}

// countType counts descendants (inclusive) whose type is in want (iterative DFS, hostile-tree safe).
func countType(root *sitter.Node, want map[string]bool) int {
	n := 0
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if want[node.Type()] {
			n++
		}
		for i := 0; i < int(node.ChildCount()); i++ {
			stack = append(stack, node.Child(i))
		}
	}
	return n
}

// collectFunctions returns every function node under root (iterative DFS).
func collectFunctions(root *sitter.Node, sp spec) []*sitter.Node {
	var out []*sitter.Node
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if sp.funcType[node.Type()] {
			out = append(out, node)
		}
		for i := 0; i < int(node.ChildCount()); i++ {
			stack = append(stack, node.Child(i))
		}
	}
	return out
}

// functionName returns the function's declared name from src, or "<anonymous>" (arrow/expression functions).
func functionName(fn *sitter.Node, src []byte) string {
	if name := fn.ChildByFieldName("name"); name != nil {
		return name.Content(src)
	}
	return "<anonymous>"
}

// isBoolOp reports whether n is a logical-operator node for the spec (Python boolean_operator, or a JS/Java
// binary node with a && / || operator token child).
func isBoolOp(n *sitter.Node, sp spec) bool {
	if sp.boolOpNode[n.Type()] {
		return true
	}
	if sp.boolOpBinry[n.Type()] {
		for i := 0; i < int(n.ChildCount()); i++ {
			if boolTokens[n.Child(i).Type()] {
				return true
			}
		}
	}
	return false
}

// complexity computes (cyclomatic, cognitive) for one function node over its own body, not descending into
// nested functions (which are separate records). See the package doc for the exact rules. Iterative
// (explicit stack of (node, nestingDepth)) so a pathologically deep expression tree in untrusted source
// cannot overflow the goroutine stack — matching countType/collectFunctions.
func complexity(fn *sitter.Node, sp spec) (cyc, cog int) {
	cyc = 1
	type frame struct {
		n     *sitter.Node
		depth int
	}
	var stack []frame
	push := func(n *sitter.Node, depth int) {
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, frame{n.Child(i), depth})
		}
	}
	push(fn, 0) // start with the function's children at nesting depth 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		c, ct := f.n, f.n.Type()
		if sp.funcType[ct] {
			continue // nested function: its own record, and a nesting boundary — do not descend
		}
		if isBoolOp(c, sp) {
			cyc++
			cog++
			push(c, f.depth)
			continue
		}
		if sp.cycDecision[ct] {
			cyc++
		}
		switch {
		case sp.cogIncrement[ct]:
			cog += 1 + f.depth
			push(c, f.depth+1)
		case sp.cogElse[ct]:
			cog++
			push(c, f.depth+1)
		default:
			push(c, f.depth)
		}
	}
	return cyc, cog
}
