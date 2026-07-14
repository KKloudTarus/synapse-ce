//go:build cgo

package astwalk

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// javaRule is the metadata for one Java AST quality rule (short key -> finding fields).
var javaRules = map[string]pythonRule{
	"empty-method":       {"quality", "java-ast-empty-method", "", "low", "Empty method body", "A non-abstract method with an empty body does nothing; add an implementation, or document why it is intentionally empty."},
	"missing-default":    {"reliability", "java-ast-missing-switch-default", "CWE-478", "medium", "switch without a default", "A switch with no default branch silently ignores unhandled values; add a default (even if it throws)."},
	"nested-try":         {"quality", "java-ast-nested-try", "", "low", "Nested try statement", "A try nested directly inside another try is hard to follow; extract the inner block into a method."},
	"empty-if-block":     {"reliability", "java-ast-empty-if-block", "", "low", "Empty if block", "An if with an empty body has no effect and usually signals unfinished or dead code."},
	"collapsible-if":     {"quality", "java-ast-collapsible-if", "", "low", "Collapsible if statement", "An if whose only statement is another if (with no else) can be merged with && for clarity."},
	"empty-loop":         {"reliability", "java-ast-empty-loop-body", "", "medium", "Empty loop body", "A loop with an empty body spins doing nothing useful; add the body or remove the loop."},
	"too-many-params":    {"quality", "java-ast-too-many-params", "", "low", "Method has too many parameters", "A long parameter list is hard to call correctly; group related parameters into an object."},
	"empty-else":         {"reliability", "java-ast-empty-else", "", "low", "Empty else block", "An empty else block is dead code; remove it."},
	"constant-if":        {"reliability", "java-ast-constant-condition", "", "medium", "Constant if condition", "An if with a literal true/false condition has a dead branch and is usually leftover debugging."},
	"nested-ternary":     {"quality", "java-ast-nested-ternary", "", "low", "Nested ternary expression", "A ternary inside another ternary is hard to read; use if/else or extract a method."},
	"long-method":        {"quality", "java-ast-long-method", "", "low", "Overly long method", "A method with a very large number of statements is hard to understand and test; split it into smaller methods."},
	"identical-branches": {"reliability", "java-ast-identical-branches", "", "medium", "if and else branches are identical", "The then and else blocks have the same code, so the condition has no effect; one branch is redundant or wrong."},
	"if-return-bool":     {"quality", "java-ast-if-return-boolean", "", "low", "if returning boolean literals", "if (c) return true; else return false; is just `return c;`."},
	"large-class":        {"quality", "java-ast-large-class", "", "low", "Class has too many methods", "A class with a very large number of methods likely has too many responsibilities; consider splitting it."},
	"many-returns":       {"quality", "java-ast-too-many-returns", "", "low", "Method has too many return statements", "A method with many return points is hard to follow; simplify the control flow."},
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
			if p := n.ChildByFieldName("parameters"); p != nil && javaParamCount(p) > 7 {
				out = append(out, javaFinding("too-many-params", n, rel))
			}
			if body := n.ChildByFieldName("body"); body != nil && body.Type() == "block" && int(body.NamedChildCount()) > 50 {
				out = append(out, javaFinding("long-method", n, rel))
			}
			if body := n.ChildByFieldName("body"); countReturnsBounded(body, map[string]bool{"method_declaration": true, "lambda_expression": true, "class_declaration": true}) > 6 {
				out = append(out, javaFinding("many-returns", n, rel))
			}
		case "ternary_expression":
			if javaHasDescendantType(n, "ternary_expression") {
				out = append(out, javaFinding("nested-ternary", n, rel))
			}
		case "for_statement", "while_statement", "do_statement", "enhanced_for_statement":
			if body := n.ChildByFieldName("body"); body != nil && body.Type() == "block" && body.NamedChildCount() == 0 {
				out = append(out, javaFinding("empty-loop", n, rel))
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
			if alt := n.ChildByFieldName("alternative"); alt != nil && alt.Type() == "block" && alt.NamedChildCount() == 0 {
				out = append(out, javaFinding("empty-else", n, rel))
			}
			if cond := n.ChildByFieldName("condition"); cond != nil {
				ct := strings.TrimSpace(cond.Content(src))
				if ct == "(true)" || ct == "(false)" {
					out = append(out, javaFinding("constant-if", n, rel))
				}
			}
			if alt := n.ChildByFieldName("alternative"); alt != nil && alt.Type() == "block" && cons != nil && cons.Type() == "block" {
				if strings.TrimSpace(cons.Content(src)) == strings.TrimSpace(alt.Content(src)) {
					out = append(out, javaFinding("identical-branches", n, rel))
				}
				cv, av := javaBlockSoleReturnBool(cons, src), javaBlockSoleReturnBool(alt, src)
				if cv != "" && av != "" && cv != av {
					out = append(out, javaFinding("if-return-bool", n, rel))
				}
			}
		case "class_declaration":
			if body := n.ChildByFieldName("body"); body != nil {
				methods := 0
				for i := 0; i < int(body.NamedChildCount()); i++ {
					if body.NamedChild(i).Type() == "method_declaration" {
						methods++
					}
				}
				if methods > 20 {
					out = append(out, javaFinding("large-class", n, rel))
				}
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

// javaBlockSoleReturnBool returns "true"/"false" if the block's only statement returns that literal.
func javaBlockSoleReturnBool(b *sitter.Node, src []byte) string {
	if b == nil || b.Type() != "block" || b.NamedChildCount() != 1 {
		return ""
	}
	st := b.NamedChild(0)
	if st.Type() != "return_statement" || st.NamedChildCount() != 1 {
		return ""
	}
	v := strings.TrimSpace(st.NamedChild(0).Content(src))
	if v == "true" || v == "false" {
		return v
	}
	return ""
}

// javaHasDescendantType reports whether n has a descendant (excluding itself) of the given type.
func javaHasDescendantType(n *sitter.Node, typ string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		ch := n.Child(i)
		if ch.Type() == typ || javaHasDescendantType(ch, typ) {
			return true
		}
	}
	return false
}

// javaParamCount counts declared parameters in a formal_parameters node.
func javaParamCount(params *sitter.Node) int {
	cnt := 0
	for i := 0; i < int(params.NamedChildCount()); i++ {
		switch params.NamedChild(i).Type() {
		case "formal_parameter", "spread_parameter", "receiver_parameter":
			cnt++
		}
	}
	return cnt
}

// javaCollapsibleIf reports whether a then-block's single statement is an if with no else.
func javaCollapsibleIf(block *sitter.Node) bool {
	if block == nil || block.Type() != "block" || block.NamedChildCount() != 1 {
		return false
	}
	inner := block.NamedChild(0)
	return inner != nil && inner.Type() == "if_statement" && inner.ChildByFieldName("alternative") == nil
}
