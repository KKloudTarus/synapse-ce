//go:build cgo

package astwalk

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// jsRules is the metadata for the JavaScript AST quality rules (short key -> finding fields).
var jsRules = map[string]pythonRule{
	"empty-function":     {"quality", "js-ast-empty-function", "", "low", "Empty function body", "A named function with an empty body does nothing; implement it or document why it is intentionally empty."},
	"missing-default":    {"reliability", "js-ast-missing-switch-default", "CWE-478", "medium", "switch without a default", "A switch with no default branch silently ignores unhandled values; add a default case."},
	"too-many-params":    {"quality", "js-ast-too-many-params", "", "low", "Function has too many parameters", "A long parameter list is hard to call correctly; pass an options object instead."},
	"long-function":      {"quality", "js-ast-long-function", "", "low", "Overly long function", "A function with a very large number of statements is hard to understand and test; split it up."},
	"large-class":        {"quality", "js-ast-large-class", "", "low", "Class has too many methods", "A class with a very large number of methods likely has too many responsibilities; consider splitting it."},
	"identical-branches": {"reliability", "js-ast-identical-branches", "", "medium", "if and else branches are identical", "The then and else blocks are the same, so the condition has no effect; one branch is redundant or wrong."},
	"return-in-finally":  {"reliability", "js-ast-return-in-finally", "", "medium", "return inside finally", "A return in finally overrides any value returned or exception thrown in the try/catch, silently discarding it."},
}

func jsFinding(key string, n *sitter.Node, rel string) QualityFinding {
	r := jsRules[key]
	return QualityFinding{Kind: r.kind, Rule: r.id, CWE: r.cwe, Severity: r.severity, Title: r.title, Description: r.description, File: rel, Line: int(n.StartPoint().Row) + 1}
}

// jsFindings walks a tree-sitter JavaScript tree for structural quality issues (empty bodies, missing
// switch default, oversized functions/classes) that a line regex cannot express.
func jsFindings(root *sitter.Node, src []byte, rel string) []QualityFinding {
	var out []QualityFinding
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.Type() {
		case "function_declaration", "method_definition", "generator_function_declaration", "function_expression":
			if body := n.ChildByFieldName("body"); body != nil && body.Type() == "statement_block" {
				if body.NamedChildCount() == 0 {
					out = append(out, jsFinding("empty-function", n, rel))
				}
				if int(body.NamedChildCount()) > 50 {
					out = append(out, jsFinding("long-function", n, rel))
				}
			}
			if p := n.ChildByFieldName("parameters"); p != nil && int(p.NamedChildCount()) > 7 {
				out = append(out, jsFinding("too-many-params", n, rel))
			}
		case "switch_statement":
			if body := n.ChildByFieldName("body"); body != nil && !jsSwitchHasDefault(body) {
				out = append(out, jsFinding("missing-default", n, rel))
			}
		case "class_declaration", "class":
			if body := n.ChildByFieldName("body"); body != nil {
				methods := 0
				for i := 0; i < int(body.NamedChildCount()); i++ {
					if body.NamedChild(i).Type() == "method_definition" {
						methods++
					}
				}
				if methods > 20 {
					out = append(out, jsFinding("large-class", n, rel))
				}
			}
		case "if_statement":
			cons := n.ChildByFieldName("consequence")
			alt := n.ChildByFieldName("alternative")
			if alt != nil && alt.Type() == "else_clause" && alt.NamedChildCount() > 0 {
				alt = alt.NamedChild(int(alt.NamedChildCount()) - 1) // unwrap else_clause to its body
			}
			if cons != nil && alt != nil && cons.Type() == "statement_block" && alt.Type() == "statement_block" &&
				strings.TrimSpace(cons.Content(src)) == strings.TrimSpace(alt.Content(src)) {
				out = append(out, jsFinding("identical-branches", n, rel))
			}
		case "finally_clause":
			if jsHasDescendantType(n, "return_statement") {
				out = append(out, jsFinding("return-in-finally", n, rel))
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	return dedupeQuality(out)
}

// jsHasDescendantType reports whether n has a descendant of the given type (used for finally-return).
func jsHasDescendantType(n *sitter.Node, typ string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		ch := n.Child(i)
		if ch.Type() == typ || jsHasDescendantType(ch, typ) {
			return true
		}
	}
	return false
}

// jsSwitchHasDefault reports whether a switch_body contains a default case.
func jsSwitchHasDefault(body *sitter.Node) bool {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		if body.NamedChild(i).Type() == "switch_default" {
			return true
		}
	}
	return false
}
