//go:build cgo

// Package astwalk (cgo build): the deeper-bug-detection pass. Unlike the line-pattern rules, these checks
// use the tree-sitter AST and intra-block statement order, so they catch defects a regex cannot:
//   - reliability-unreachable-code: a statement following an unconditional terminator (return/throw/
//     raise/break/continue) in the same block can never execute.
//   - reliability-constant-condition: an `if` whose condition is a boolean literal is always taken or
//     never taken (a logic bug or leftover debug flag). Loops are excluded on purpose (see bugSpecs).
//
// Deterministic (no LLM); emitted as ungated Kind=reliability findings, like the pattern rules.
package astwalk

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

type bugSpec struct {
	blocks      map[string]bool // statement-block node types (children are statements)
	terminators map[string]bool // nodes that unconditionally end control flow
	condHolders map[string]bool // nodes carrying a "condition" field to constant-check
}

// condHolders is if_statement ONLY on purpose: `while (true)` / `do {} while (true)` are the idiomatic
// infinite loop, so flagging a constant loop condition would be a false positive. A constant `if`
// condition, by contrast, is a real logic bug or a leftover debug flag.
var bugSpecs = map[string]bugSpec{
	"Python": {
		blocks:      set("block"),
		terminators: set("return_statement", "raise_statement", "break_statement", "continue_statement"),
		condHolders: set("if_statement"),
	},
	"JavaScript": {
		blocks:      set("statement_block"),
		terminators: set("return_statement", "throw_statement", "break_statement", "continue_statement"),
		condHolders: set("if_statement"),
	},
	"Java": {
		blocks:      set("block"),
		terminators: set("return_statement", "throw_statement", "break_statement", "continue_statement"),
		condHolders: set("if_statement"),
	},
}

var boolLiterals = set("true", "false", "True", "False")

// BugsFor parses every supported-language file under root and returns the deterministic reliability bugs.
func BugsFor(ctx context.Context, root string) (Bugs, error) {
	var out Bugs
	out.Bugs = []Bug{}
	truncated, err := walkSource(ctx, root, func(rel, lang string, content []byte) {
		sp, ok := bugSpecs[lang]
		if !ok {
			return
		}
		root := parseRoot(ctx, sp2spec(lang), content)
		if root == nil {
			return
		}
		out.Bugs = append(out.Bugs, detectBugs(root, content, sp, rel)...)
	})
	if err != nil {
		return Bugs{}, err
	}
	out.Truncated = truncated
	return out, nil
}

// sp2spec returns the parse spec (grammar) for a language so BugsFor can parse; the metric `spec` already
// holds the *sitter.Language, reused here.
func sp2spec(lang string) spec { return specs[lang] }

// detectBugs walks the tree (iterative DFS) applying the block-level and condition-level checks.
func detectBugs(root *sitter.Node, content []byte, sp bugSpec, rel string) []Bug {
	var bugs []Bug
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		t := n.Type()
		if sp.blocks[t] {
			if b, ok := unreachable(n, sp, rel); ok {
				bugs = append(bugs, b)
			}
		}
		if sp.condHolders[t] {
			if b, ok := constantCondition(n, content, rel); ok {
				bugs = append(bugs, b)
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	return bugs
}

// notDeadAfterTerminator are named block children that, appearing after a terminator, are NOT genuinely
// unreachable: comments; a hoisted JS function declaration (still defined and callable); and an empty
// statement (a bare ";").
var notDeadAfterTerminator = set("comment", "function_declaration", "empty_statement")

// unreachable flags the first genuinely-dead statement that follows an unconditional terminator in a block.
func unreachable(block *sitter.Node, sp bugSpec, rel string) (Bug, bool) {
	terminated := false
	for i := 0; i < int(block.NamedChildCount()); i++ {
		c := block.NamedChild(i)
		if notDeadAfterTerminator[c.Type()] {
			continue
		}
		if terminated {
			return Bug{
				File:    rel,
				Line:    int(c.StartPoint().Row) + 1,
				Rule:    "reliability-unreachable-code",
				Message: "statement is unreachable: it follows an unconditional return/throw/break/continue in the same block",
			}, true
		}
		if sp.terminators[c.Type()] {
			terminated = true
		}
	}
	return Bug{}, false
}

// constantCondition flags an `if` whose condition is a boolean literal (loops are excluded by bugSpecs).
func constantCondition(node *sitter.Node, content []byte, rel string) (Bug, bool) {
	cond := node.ChildByFieldName("condition")
	if cond == nil {
		return Bug{}, false
	}
	txt := strings.TrimSpace(strings.Trim(strings.TrimSpace(cond.Content(content)), "()"))
	if !boolLiterals[txt] {
		return Bug{}, false
	}
	return Bug{
		File:    rel,
		Line:    int(node.StartPoint().Row) + 1,
		Rule:    "reliability-constant-condition",
		Message: "condition is the constant " + txt + ", so the branch is always (or never) taken",
	}, true
}
