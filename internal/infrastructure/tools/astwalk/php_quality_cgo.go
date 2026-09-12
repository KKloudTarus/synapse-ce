//go:build cgo

package astwalk

import sitter "github.com/smacker/go-tree-sitter"

const maxPhpFindingsPerFile = 40

// phpRules is the metadata for the PHP AST-only rules. Pattern-detectable PHP rules live in the
// generated SAST language pack (the `php:` key prefix); cognitive complexity is already owned by the
// metrics path (`php:cognitive-complexity`), so this analyzer carries only the structural rules that
// have no other producer.
var phpRules = map[string]pythonRule{
	"empty-catch":     {"reliability", "php-ast-empty-catch", "CWE-390", "medium", "Empty catch block", "An empty catch block silently discards a failure. Handle the expected exception or preserve diagnostic context."},
	"missing-default": {"reliability", "php-ast-missing-switch-default", "CWE-478", "medium", "switch without a default", "A switch with no default case silently ignores unhandled values; add a default (even one that throws)."},
}

func phpFinding(key string, n *sitter.Node, rel string) QualityFinding {
	r := phpRules[key]
	return QualityFinding{Kind: r.kind, Rule: r.id, CWE: r.cwe, Severity: r.severity, Title: r.title, Description: r.description, File: rel, Line: int(n.StartPoint().Row) + 1}
}

// phpFindings emits the PHP AST rules: empty catch blocks and switch statements without a default
// case. It never suppresses; each finding is propose-only. (Cognitive complexity is reported by the
// metrics path as php:cognitive-complexity, so it is intentionally not repeated here.)
func phpFindings(root *sitter.Node, _ []byte, rel string) []QualityFinding {
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
			if body := astChildByType(n, "compound_statement"); body != nil && astBlockEmpty(body) {
				out = append(out, phpFinding("empty-catch", n, rel))
			}
		case "switch_statement":
			if body := astChildByType(n, "switch_block"); body != nil && !phpSwitchHasDefault(body) {
				out = append(out, phpFinding("missing-default", n, rel))
			}
		}
		if len(out) >= maxPhpFindingsPerFile {
			break
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
	return dedupeQuality(out)
}

// phpSwitchHasDefault reports whether a switch_block contains a default_statement.
func phpSwitchHasDefault(body *sitter.Node) bool {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		if body.NamedChild(i).Type() == "default_statement" {
			return true
		}
	}
	return false
}
