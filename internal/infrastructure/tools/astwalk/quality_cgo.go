//go:build cgo

package astwalk

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// QualityFor parses supported files and returns the precision-biased seed quality rules. It deliberately does
// not attempt alias, import-resolution, or interprocedural analysis.
func QualityFor(ctx context.Context, root string) (Quality, error) {
	out := Quality{Findings: []QualityFinding{}}
	swiftPerRule := map[string]int{}
	swiftTruncated := false
	swiftParserTruncated := false
	type notebookChunk struct {
		location string
		content  []byte
		start    int
		end      int
	}
	notebooks := map[string][]notebookChunk{}
	truncated, err := walkSource(ctx, root, func(rel, lang string, content []byte) {
		if lang != "Python" && lang != "Java" && lang != "JavaScript" && lang != "Kotlin" && lang != "Scala" && lang != "Ruby" && lang != "CSS" && lang != "HTML" && lang != "Swift" && lang != "Rust" && lang != "C" && lang != "C++" {
			return
		}
		if lang == "Python" {
			lowerRel := strings.ToLower(rel)
			if marker := strings.LastIndex(lowerRel, ".ipynb#cell-"); marker >= 0 {
				base := rel[:marker+len(".ipynb")]
				notebooks[base] = append(notebooks[base], notebookChunk{location: rel, content: content})
				return // Python cells are parsed together below to preserve notebook state.
			}
		}
		tree := parseRoot(ctx, specs[lang], content)
		if tree == nil {
			return
		}
		switch lang {
		case "Python":
			out.Findings = append(out.Findings, pythonFindings(tree, content, rel)...)
		case "Java":
			out.Findings = append(out.Findings, javaFindings(tree, content, rel)...)
		case "JavaScript":
			out.Findings = append(out.Findings, jsFindings(tree, content, rel)...)
		case "Kotlin":
			out.Findings = append(out.Findings, kotlinFindings(tree, content, rel)...)
		case "Scala":
			out.Findings = append(out.Findings, scalaFindings(tree, rel)...)
		case "Ruby":
			out.Findings = append(out.Findings, rubyFindings(tree, rel)...)
		case "CSS":
			out.Findings = append(out.Findings, cssFindings(tree, content, rel)...)
		case "HTML":
			ext := strings.ToLower(filepath.Ext(rel))
			if ext == ".xhtml" || ext == ".xml" || ext == ".jsx" || ext == ".tsx" || ext == ".vue" || ext == ".svelte" {
				return
			}
			out.Findings = append(out.Findings, htmlFindings(tree, content, rel)...)
		case "Swift":
			if tree.HasError() {
				swiftParserTruncated = true
			}
			remaining := maxSwiftTotal - swiftFindingCount(out.Findings)
			if remaining <= 0 {
				swiftTruncated = true
				return
			}
			findings, fileTruncated := swiftFindingsLimitWithCounts(tree, content, rel, remaining, swiftPerRule)
			out.Findings = append(out.Findings, findings...)
			swiftTruncated = swiftTruncated || fileTruncated
		case "Rust":
			out.Findings = append(out.Findings, rustFindings(tree, content, rel)...)
		case "C":
			out.Findings = append(out.Findings, cFindings(tree, content, rel)...)
		case "C++":
			out.Findings = append(out.Findings, cppFindings(tree, content, rel)...)
		}
	})
	if err != nil {
		return Quality{}, err
	}
	truncated = truncated || swiftTruncated || swiftParserTruncated
	for base, chunks := range notebooks {
		var source strings.Builder
		line := 1
		for i := range chunks {
			chunks[i].start = line
			source.Write(chunks[i].content)
			line += strings.Count(string(chunks[i].content), "\n") + 1
			chunks[i].end = line - 1
			source.WriteByte('\n')
		}
		content := []byte(source.String())
		tree := parseRoot(ctx, specs["Python"], content)
		if tree == nil {
			continue
		}
		for _, finding := range pythonFindings(tree, content, base) {
			for _, chunk := range chunks {
				if finding.Line >= chunk.start && finding.Line <= chunk.end {
					finding.File = chunk.location
					finding.Line -= chunk.start - 1
					break
				}
			}
			out.Findings = append(out.Findings, finding)
		}
	}
	out.Truncated = truncated
	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return out, nil
}

// countReturnsBounded counts return_statement nodes under body without descending into nested scopes
// (functions/lambdas/classes) named in stop. Shared by the Python/Java/JS quality walkers.
func countReturnsBounded(body *sitter.Node, stop map[string]bool) int {
	if body == nil {
		return 0
	}
	cnt := 0
	stack := []*sitter.Node{body}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c.Type() == "return_statement" {
			cnt++
		}
		if c != body && stop[c.Type()] {
			continue
		}
		for i := 0; i < int(c.ChildCount()); i++ {
			stack = append(stack, c.Child(i))
		}
	}
	return cnt
}
