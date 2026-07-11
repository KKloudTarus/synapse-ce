//go:build cgo

// Package astwalk (cgo build): tree-sitter grammars parse each supported language and count function-like
// declarations. Grammars are MIT-licensed C, compiled into this binary only; the server and CLI never
// import this package, they exec the synapse-ast sidecar. Adding a language is one entry in `grammars`.
package astwalk

import (
	"context"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
)

// grammar pairs a tree-sitter language with the set of AST node types that denote a function/method for
// that language (a set, so multiple forms — declaration, method, arrow, constructor — all count).
type grammar struct {
	lang     *sitter.Language
	funcType map[string]bool
}

func set(types ...string) map[string]bool {
	m := make(map[string]bool, len(types))
	for _, t := range types {
		m[t] = true
	}
	return m
}

// grammars maps a go-enry language name to its tree-sitter grammar. Initial set for Phase 0 slice 2;
// TypeScript/Kotlin/Go/Ruby/C#/etc. are one line each and land incrementally.
var grammars = map[string]grammar{
	"Python": {python.GetLanguage(), set("function_definition")},
	// Note: `function` alone is the *keyword* node nested inside function_declaration/expression, so it
	// must NOT be in this set (it would double-count). Match the declaration/expression/arrow/method nodes.
	"JavaScript": {javascript.GetLanguage(), set("function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "generator_function")},
	"Java":       {java.GetLanguage(), set("method_declaration", "constructor_declaration")},
}

// FunctionsFor parses every supported-language file under root and returns accurate per-language function
// counts.
func FunctionsFor(ctx context.Context, root string) (Result, error) {
	return walk(ctx, root, func(lang string, content []byte) (int, bool) {
		g, ok := grammars[lang]
		if !ok {
			return 0, false
		}
		p := sitter.NewParser()
		p.SetLanguage(g.lang)
		tree, err := p.ParseCtx(ctx, nil, content)
		if err != nil || tree == nil {
			return 0, false // unparseable file contributes nothing rather than a wrong count
		}
		defer tree.Close()
		return countNodes(tree.RootNode(), g.funcType), true
	})
}

// countNodes returns the number of descendants (inclusive) whose type is in want. Iterative DFS to avoid
// deep recursion on a hostile tree.
func countNodes(root *sitter.Node, want map[string]bool) int {
	if root == nil {
		return 0
	}
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
