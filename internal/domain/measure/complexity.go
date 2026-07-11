package measure

import "sort"

// FunctionComplexity is one function's location + size/complexity measures. Line is 1-based; File is
// relative to the scanned root. Cyclomatic is McCabe's measure; Cognitive is the nesting-aware
// readability measure. Both are deterministic (no LLM).
type FunctionComplexity struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Name       string `json:"name"`
	Language   string `json:"language"`
	Cyclomatic int    `json:"cyclomatic"`
	Cognitive  int    `json:"cognitive"`
}

// ComplexityReport is the per-function complexity over a source tree. Truncated is true when the walk hit
// its file cap, so the report is a known undercount rather than a silent one.
type ComplexityReport struct {
	Functions []FunctionComplexity `json:"functions"`
	Truncated bool                 `json:"truncated,omitempty"`
}

// MaxCyclomatic returns the highest cyclomatic complexity across all functions (0 when there are none).
func (r ComplexityReport) MaxCyclomatic() int {
	max := 0
	for _, f := range r.Functions {
		if f.Cyclomatic > max {
			max = f.Cyclomatic
		}
	}
	return max
}

// OverCyclomatic returns the functions whose cyclomatic complexity is strictly greater than threshold,
// sorted most-complex first (ties broken by file then line for determinism).
func (r ComplexityReport) OverCyclomatic(threshold int) []FunctionComplexity {
	var over []FunctionComplexity
	for _, f := range r.Functions {
		if f.Cyclomatic > threshold {
			over = append(over, f)
		}
	}
	sortByComplexity(over)
	return over
}

// TopByCyclomatic returns up to n functions with the highest cyclomatic complexity, most-complex first.
func (r ComplexityReport) TopByCyclomatic(n int) []FunctionComplexity {
	sorted := make([]FunctionComplexity, len(r.Functions))
	copy(sorted, r.Functions)
	sortByComplexity(sorted)
	if n >= 0 && n < len(sorted) {
		sorted = sorted[:n]
	}
	return sorted
}

func sortByComplexity(fs []FunctionComplexity) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Cyclomatic != fs[j].Cyclomatic {
			return fs[i].Cyclomatic > fs[j].Cyclomatic
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}
