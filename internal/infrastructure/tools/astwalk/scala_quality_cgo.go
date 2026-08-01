//go:build cgo

package astwalk

import sitter "github.com/smacker/go-tree-sitter"

const (
	scalaCognitiveComplexityThreshold = 15
	maxScalaCognitiveFindingsPerFile  = 20
)

// scalaFindings emits the Scala AST-only rules. Pattern-detectable Scala rules live in the
// generated SAST language pack; cognitive complexity stays here because approximating nested
// control flow with line regular expressions would be noisy and structurally incorrect.
func scalaFindings(root *sitter.Node, rel string) []QualityFinding {
	sp, ok := specs["Scala"]
	if !ok || root == nil {
		return nil
	}

	out := make([]QualityFinding, 0)
	for _, fn := range collectFunctions(root, sp) {
		_, cognitive := complexity(fn, sp)
		if cognitive <= scalaCognitiveComplexityThreshold {
			continue
		}
		out = append(out, QualityFinding{
			Kind:        "quality",
			Rule:        "scala:cognitive-complexity",
			Severity:    "medium",
			Title:       "Function has high cognitive complexity",
			Description: "The function's nesting-aware cognitive complexity exceeds 15. Reduce nested control flow or extract smaller functions.",
			File:        rel,
			Line:        int(fn.StartPoint().Row) + 1,
		})
		if len(out) >= maxScalaCognitiveFindingsPerFile {
			break
		}
	}
	return out
}
