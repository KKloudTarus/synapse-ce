//go:build cgo

package astwalk

import sitter "github.com/smacker/go-tree-sitter"

const maxCsharpFindingsPerFile = 40

// csharpRules is the metadata for the C# AST-only rules. Pattern-detectable C# rules live in the
// generated SAST language pack, and complexity is owned by the metrics path (cyclomatic
// quality-high-complexity), so this analyzer carries only the structural rules with no other
// producer: a regex cannot tell an empty catch from a commented one, or a switch's default section
// from the word "default" elsewhere.
var csharpRules = map[string]pythonRule{
	"empty-catch":     {"reliability", "csharp-ast-empty-catch", "CWE-390", "medium", "Empty catch block", "An empty catch block silently discards a failure. Handle the expected exception or preserve diagnostic context."},
	"missing-default": {"reliability", "csharp-ast-missing-switch-default", "CWE-478", "medium", "switch without a default", "A switch with no default section silently ignores unhandled values; add a default (even one that throws)."},
}

func csharpFinding(key string, n *sitter.Node, rel string) QualityFinding {
	r := csharpRules[key]
	return QualityFinding{Kind: r.kind, Rule: r.id, CWE: r.cwe, Severity: r.severity, Title: r.title, Description: r.description, File: rel, Line: int(n.StartPoint().Row) + 1}
}

// csharpFindings emits the C# AST rules: empty catch blocks and switch statements without a default
// section. It never suppresses; each finding is propose-only. (Complexity is reported by the metrics
// path as the cyclomatic quality-high-complexity finding, so it is not repeated here.)
func csharpFindings(root *sitter.Node, _ []byte, rel string) []QualityFinding {
	if root == nil {
		return nil
	}
	var out []QualityFinding
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.Type() {
		case "catch_clause":
			if body := astChildByType(n, "block"); body != nil && astBlockEmpty(body) {
				out = append(out, csharpFinding("empty-catch", n, rel))
			}
		case "switch_statement":
			if body := astChildByType(n, "switch_body"); body != nil && !csharpSwitchHasDefault(body) {
				out = append(out, csharpFinding("missing-default", n, rel))
			}
		}
		if len(out) >= maxCsharpFindingsPerFile {
			break
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
	return dedupeQuality(out)
}

// csharpSwitchHasDefault reports whether a switch_body has a section that matches every remaining
// value, so the switch is not silently ignoring unhandled input.
func csharpSwitchHasDefault(body *sitter.Node) bool {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		sec := body.NamedChild(i)
		if sec.Type() == "switch_section" && csharpSectionIsExhaustive(sec) {
			return true
		}
	}
	return false
}

// csharpSectionIsExhaustive reports whether a switch_section matches every remaining value: a
// literal `default` label, a bare discard (`case _:`), or an unguarded `case var x:` (a var pattern
// matches all values). A `when` guard makes the section conditional, so it is NOT exhaustive.
func csharpSectionIsExhaustive(sec *sitter.Node) bool {
	var hasDefault, catchAll, hasWhen bool
	for i := 0; i < int(sec.ChildCount()); i++ {
		switch c := sec.Child(i); c.Type() {
		case "default":
			hasDefault = true
		case "discard":
			catchAll = true
		case "when_clause":
			hasWhen = true
		case "declaration_pattern":
			// `var x` (implicit_type) matches every value; a typed pattern (`int i`) does not.
			if csharpHasChildType(c, "implicit_type") {
				catchAll = true
			}
		}
	}
	if hasDefault {
		return true
	}
	return catchAll && !hasWhen
}

// csharpHasChildType reports whether n has a direct named child of the given type.
func csharpHasChildType(n *sitter.Node, t string) bool {
	return astChildByType(n, t) != nil
}
