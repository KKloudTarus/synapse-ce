package measure

import "math"

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

// ComplexityFileCoverage records parse status and coverage for a source file.
type ComplexityFileCoverage struct {
	File       string `json:"file"`
	Language   string `json:"language"`
	Supported  bool   `json:"supported"`
	Parsed     bool   `json:"parsed"`
	ParseError bool   `json:"parse_error,omitempty"`
}

// ComplexityReport is the per-function complexity over a source tree. Truncated is true when the walk hit
// its file cap, so the report is a known undercount rather than a silent one.
type ComplexityReport struct {
	Functions []FunctionComplexity     `json:"functions"`
	Files     []ComplexityFileCoverage `json:"files,omitempty"`
	Truncated bool                     `json:"truncated,omitempty"`
}

// FileCyclomatic returns the sum of cyclomatic complexities for functions in file and whether the file was
// successfully measured. If the report lacks per-file coverage evidence (legacy report), or the file was
// unsupported or failed to parse, it returns (0, false).
func (r ComplexityReport) FileCyclomatic(file string) (int, bool) {
	if len(r.Files) == 0 {
		return 0, false
	}
	var cov *ComplexityFileCoverage
	for i := range r.Files {
		if r.Files[i].File == file {
			cov = &r.Files[i]
			break
		}
	}
	if cov == nil || !cov.Supported || !cov.Parsed || cov.ParseError {
		return 0, false
	}
	sum := 0
	for _, f := range r.Functions {
		if f.File == file {
			if f.Cyclomatic < 0 || sum > math.MaxInt32-f.Cyclomatic {
				return 0, false
			}
			sum += f.Cyclomatic
		}
	}
	return sum, true
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

// OverCognitive returns functions whose cognitive complexity is strictly greater than threshold, sorted
// most-cognitively-complex first with stable file and line tiebreakers.
func (r ComplexityReport) OverCognitive(threshold int) []FunctionComplexity {
	var over []FunctionComplexity
	for _, f := range r.Functions {
		if f.Cognitive > threshold {
			over = append(over, f)
		}
	}
	sort.Slice(over, func(i, j int) bool {
		if over[i].Cognitive != over[j].Cognitive {
			return over[i].Cognitive > over[j].Cognitive
		}
		if over[i].File != over[j].File {
			return over[i].File < over[j].File
		}
		return over[i].Line < over[j].Line
	})
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
