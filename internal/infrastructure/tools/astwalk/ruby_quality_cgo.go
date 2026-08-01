//go:build cgo

package astwalk

import sitter "github.com/smacker/go-tree-sitter"

const (
	rubyCognitiveComplexityThreshold = 15
	maxRubyCognitiveFindingsPerFile  = 20
)

// rubyFindings emits Ruby's AST-only rules. Pattern-detectable Ruby and Rails
// rules live in the generated SAST language pack; cognitive complexity stays
// here because nested control flow cannot be measured correctly with line regexes.
func rubyFindings(root *sitter.Node, rel string) []QualityFinding {
	sp, ok := specs["Ruby"]
	if !ok || root == nil {
		return nil
	}

	out := make([]QualityFinding, 0)
	for _, fn := range collectFunctions(root, sp) {
		_, cognitive := complexity(fn, sp)
		if cognitive <= rubyCognitiveComplexityThreshold {
			continue
		}
		out = append(out, QualityFinding{
			Kind:        "quality",
			Rule:        "rb:cognitive-complexity",
			Severity:    "medium",
			Title:       "Method has high cognitive complexity",
			Description: "The method's nesting-aware cognitive complexity exceeds 15. Reduce nested control flow or extract smaller methods.",
			File:        rel,
			Line:        int(fn.StartPoint().Row) + 1,
		})
		if len(out) >= maxRubyCognitiveFindingsPerFile {
			break
		}
	}
	return out
}
