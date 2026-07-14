//go:build cgo

package astwalk

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// javaRule is the metadata for one Java AST quality rule (short key -> finding fields).
var javaRules = map[string]pythonRule{
	"empty-method":    {"quality", "java-ast-empty-method", "", "low", "Empty method body", "A non-abstract method with an empty body does nothing; add an implementation, or document why it is intentionally empty."},
	"missing-default": {"reliability", "java-ast-missing-switch-default", "CWE-478", "medium", "switch without a default", "A switch with no default branch silently ignores unhandled values; add a default (even if it throws)."},
	"nested-try":      {"quality", "java-ast-nested-try", "", "low", "Nested try statement", "A try nested directly inside another try is hard to follow; extract the inner block into a method."},
	"empty-if-block":  {"reliability", "java-ast-empty-if-block", "", "low", "Empty if block", "An if with an empty body has no effect and usually signals unfinished or dead code."},
	"collapsible-if":  {"quality", "java-ast-collapsible-if", "", "low", "Collapsible if statement", "An if whose only statement is another if (with no else) can be merged with && for clarity."},
}

func javaFinding(key string, n *sitter.Node, rel string) QualityFinding {
	r := javaRules[key]
	return QualityFinding{Kind: r.kind, Rule: r.id, CWE: r.cwe, Severity: r.severity, Title: r.title, Description: r.description, File: rel, Line: int(n.StartPoint().Row) + 1}
}

// javaFindings walks a tree-sitter Java tree and reports structural quality issues that a line-level
// regex cannot express (empty bodies, missing switch default, nested/collapsible control flow).
func javaFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	var out []QualityFinding
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.Type() {
		case "method_declaration":
			if body := n.ChildByFieldName("body"); body != nil && body.Type() == "block" && body.NamedChildCount() == 0 {
				out = append(out, javaFinding("empty-method", n, rel))
			}
		case "switch_expression", "switch_statement":
			if !javaSwitchHasDefault(n, src) {
				out = append(out, javaFinding("missing-default", n, rel))
			}
		case "try_statement":
			if javaHasNestedTry(n) {
				out = append(out, javaFinding("nested-try", n, rel))
			}
		case "if_statement":
			cons := n.ChildByFieldName("consequence")
			if cons != nil && cons.Type() == "block" && cons.NamedChildCount() == 0 {
				out = append(out, javaFinding("empty-if-block", n, rel))
			}
			if n.ChildByFieldName("alternative") == nil && javaCollapsibleIf(cons) {
				out = append(out, javaFinding("collapsible-if", n, rel))
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	return dedupeQuality(out)
}

// javaSwitchHasDefault reports whether a switch node contains a default label.
func javaSwitchHasDefault(n *sitter.Node, src []byte) bool {
	stack := []*sitter.Node{n}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		t := c.Type()
		if t == "switch_label" || t == "switch_rule" {
			if strings.HasPrefix(strings.TrimSpace(c.Content(src)), "default") {
				return true
			}
		}
		for i := 0; i < int(c.ChildCount()); i++ {
			stack = append(stack, c.Child(i))
		}
	}
	return false
}

// javaHasNestedTry reports whether a try node contains another try_statement in its subtree.
func javaHasNestedTry(n *sitter.Node) bool {
	var walk func(c *sitter.Node) bool
	walk = func(c *sitter.Node) bool {
		for i := 0; i < int(c.ChildCount()); i++ {
			ch := c.Child(i)
			if ch.Type() == "try_statement" {
				return true
			}
			if walk(ch) {
				return true
			}
		}
		return false
	}
	return walk(n)
}

// javaCollapsibleIf reports whether a then-block's single statement is an if with no else.
func javaCollapsibleIf(block *sitter.Node) bool {
	if block == nil || block.Type() != "block" || block.NamedChildCount() != 1 {
		return false
	}
	inner := block.NamedChild(0)
	return inner != nil && inner.Type() == "if_statement" && inner.ChildByFieldName("alternative") == nil
}
