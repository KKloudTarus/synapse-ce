//go:build cgo

package astwalk

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	rubyCognitiveComplexityThreshold = 15
	maxRubyCognitiveFindingsPerFile  = 20
	maxRubyDuplicateWhenPerFile      = 50
	rubyWalkCancelCheckInterval      = 4096
)

// rubyFindings emits Ruby's AST-only rules. Pattern-detectable Ruby and Rails
// rules live in the generated SAST language pack; cognitive complexity and
// duplicate case/when conditions stay here because they need the parse tree.
func rubyFindings(ctx context.Context, root *sitter.Node, src []byte, rel string) []QualityFinding {
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
	out = append(out, rubyDuplicateWhenFindings(ctx, root, src, rel)...)
	return out
}

// rubyDuplicateWhenFindings flags a case/when branch whose condition repeats an earlier when in the same
// case expression: the later branch is dead code (Ruby evaluates when clauses top to bottom and takes the
// first match), which is almost always a copy-paste bug. It compares the whitespace-normalized source of
// each when pattern; `when 2, 3` contributes both `2` and `3`, so a later `when 3` is caught. Each case
// keeps its own seen-set, so a repeated literal across unrelated case expressions is not conflated.
//
// It walks the whole parse tree, so it checks ctx cancellation every rubyWalkCancelCheckInterval nodes: the
// sidecar parses untrusted source, and a multi-megabyte single-case file is otherwise several seconds of
// uninterruptible cgo work.
func rubyDuplicateWhenFindings(ctx context.Context, root *sitter.Node, src []byte, rel string) []QualityFinding {
	var out []QualityFinding
	visited := 0
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited++; visited%rubyWalkCancelCheckInterval == 0 && ctx.Err() != nil {
			return out
		}
		if n.Type() == "case" {
			seen := map[string]bool{}
			for i := 0; i < int(n.NamedChildCount()); i++ {
				w := n.NamedChild(i)
				if w.Type() != "when" {
					continue
				}
				flagged := false
				for j := 0; j < int(w.NamedChildCount()); j++ {
					p := w.NamedChild(j)
					if p.Type() != "pattern" {
						continue
					}
					key := strings.Join(strings.Fields(p.Content(src)), " ")
					if key == "" {
						continue
					}
					if seen[key] && !flagged {
						out = append(out, QualityFinding{
							Kind:        "reliability",
							Rule:        "rb:duplicate-when-condition",
							Severity:    "medium",
							Title:       "Duplicate when condition",
							Description: "This when condition repeats an earlier branch in the same case; because Ruby takes the first matching when, the later branch is dead code. Remove or correct the duplicate.",
							File:        rel,
							Line:        int(w.StartPoint().Row) + 1,
						})
						flagged = true
					}
					seen[key] = true
				}
				if len(out) >= maxRubyDuplicateWhenPerFile {
					return out
				}
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			stack = append(stack, n.NamedChild(i))
		}
	}
	return out
}
