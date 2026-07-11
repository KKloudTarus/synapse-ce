package measure

import "sort"

// CodeRange is a line span within a file (both 1-based, inclusive).
type CodeRange struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// DuplicationBlock is one duplicated token run, present at two or more places (Occurrences). Tokens is the
// length of the duplicated run in tokens.
type DuplicationBlock struct {
	Tokens      int         `json:"tokens"`
	Occurrences []CodeRange `json:"occurrences"`
}

// DuplicationReport aggregates copy-paste detection over a source tree, mirroring the standard metrics:
// duplicated blocks, duplicated lines, files touched, and duplicated-lines density. Truncated is true when
// the walk hit its file cap (a signalled undercount).
type DuplicationReport struct {
	Blocks          []DuplicationBlock `json:"blocks"`
	DuplicatedLines int                `json:"duplicated_lines"`
	TotalLines      int                `json:"total_lines"` // code lines considered (non-blank, non-comment)
	Files           int                `json:"files"`       // distinct files containing a duplication
	Truncated       bool               `json:"truncated,omitempty"`
}

// Density is the duplicated-lines density as a percentage of total code lines (0 when there are none).
func (r DuplicationReport) Density() float64 {
	if r.TotalLines == 0 {
		return 0
	}
	return 100 * float64(r.DuplicatedLines) / float64(r.TotalLines)
}

// TopBlocks returns up to n duplication blocks, largest (most tokens) first, deterministic on ties.
func (r DuplicationReport) TopBlocks(n int) []DuplicationBlock {
	sorted := make([]DuplicationBlock, len(r.Blocks))
	copy(sorted, r.Blocks)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Tokens != sorted[j].Tokens {
			return sorted[i].Tokens > sorted[j].Tokens
		}
		if len(sorted[i].Occurrences) == 0 || len(sorted[j].Occurrences) == 0 {
			return len(sorted[i].Occurrences) > len(sorted[j].Occurrences)
		}
		a, b := sorted[i].Occurrences[0], sorted[j].Occurrences[0]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.StartLine < b.StartLine
	})
	if n >= 0 && n < len(sorted) {
		sorted = sorted[:n]
	}
	return sorted
}
