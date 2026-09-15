package measure

import (
	"fmt"
	"math"
	"sort"
)

const ComplexitySchemaVersion = 1

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
	Version   int                      `json:"version,omitempty"`
	Functions []FunctionComplexity     `json:"functions"`
	Files     []ComplexityFileCoverage `json:"files,omitempty"`
	Truncated bool                     `json:"truncated,omitempty"`
}

// ComplexityFileMetrics is the bounded per-file index used by snapshot builders and trend
// comparisons. A missing or invalid coverage record never becomes a zero metric.
type ComplexityFileMetrics struct {
	Cyclomatic int
	Cognitive  int
	Available  bool
	Reason     string
}

// ComplexityIndex returns one aggregate record per covered file in O(files + functions). Reports
// without the per-file coverage introduced by ComplexitySchemaVersion are legacy evidence and return
// an empty index; callers can preserve the old counters while marking their availability explicitly.
func (r ComplexityReport) ComplexityIndex() (map[string]ComplexityFileMetrics, error) {
	index := make(map[string]ComplexityFileMetrics, len(r.Files))
	if len(r.Files) == 0 {
		return index, nil
	}
	for _, coverage := range r.Files {
		path, err := CanonicalPath(coverage.File)
		if err != nil || path == "" || path != coverage.File {
			return nil, fmt.Errorf("complexity coverage path %q is not canonical", coverage.File)
		}
		if _, exists := index[path]; exists {
			return nil, fmt.Errorf("duplicate complexity coverage path %q", path)
		}
		entry := ComplexityFileMetrics{Available: coverage.Supported && coverage.Parsed && !coverage.ParseError}
		if !coverage.Supported {
			entry.Reason = "unsupported_language"
		} else if coverage.ParseError || !coverage.Parsed {
			entry.Reason = "parse_error"
		}
		index[path] = entry
	}
	for _, function := range r.Functions {
		path, err := CanonicalPath(function.File)
		if err != nil || path == "" || path != function.File {
			return nil, fmt.Errorf("complexity function path %q is not canonical", function.File)
		}
		entry, exists := index[path]
		if !exists {
			// A function outside the inventory/coverage set cannot make an unproven file measured.
			continue
		}
		if function.Cyclomatic < 0 || function.Cognitive < 0 {
			return nil, fmt.Errorf("negative complexity metric for %q", path)
		}
		if !entry.Available {
			continue
		}
		if entry.Cyclomatic > math.MaxInt32-function.Cyclomatic || entry.Cognitive > math.MaxInt32-function.Cognitive {
			return nil, fmt.Errorf("complexity metric overflow for %q", path)
		}
		entry.Cyclomatic += function.Cyclomatic
		entry.Cognitive += function.Cognitive
		index[path] = entry
	}
	return index, nil
}

// ComplexityCoverageSummary records how much of a node's source scope has usable complexity evidence.
type ComplexityCoverageSummary struct {
	Version       int          `json:"version,omitempty"`
	EligibleFiles int          `json:"eligible_files"`
	MeasuredFiles int          `json:"measured_files"`
	Availability  Availability `json:"availability"`
	Reason        string       `json:"reason,omitempty"`
}

// FileCyclomatic returns the sum of cyclomatic complexities for functions in file and whether the file was
// successfully measured. If the report lacks per-file coverage evidence (legacy report), or the file was
// unsupported or failed to parse, it returns (0, false).
func (r ComplexityReport) FileCyclomatic(file string) (int, bool) {
	index, err := r.ComplexityIndex()
	if err != nil {
		return 0, false
	}
	entry, ok := index[file]
	if !ok || !entry.Available {
		return 0, false
	}
	return entry.Cyclomatic, true
}

// FileCognitive mirrors FileCyclomatic for the nesting-aware complexity metric.
func (r ComplexityReport) FileCognitive(file string) (int, bool) {
	index, err := r.ComplexityIndex()
	if err != nil {
		return 0, false
	}
	entry, ok := index[file]
	if !ok || !entry.Available {
		return 0, false
	}
	return entry.Cognitive, true
}

// ValidateComplexityEvidence checks the bounded wire model before it is persisted.
func (r ComplexityReport) ValidateComplexityEvidence() error {
	if r.Version != 0 && r.Version != ComplexitySchemaVersion {
		return fmt.Errorf("unsupported complexity schema version %d", r.Version)
	}
	_, err := r.ComplexityIndex()
	return err
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
