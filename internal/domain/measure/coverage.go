package measure

import "sort"

// FileCoverage is one file's line-coverage summary (executable lines only).
type FileCoverage struct {
	File         string `json:"file"`
	CoveredLines int    `json:"covered_lines"`
	TotalLines   int    `json:"total_lines"`
}

// Percent is the file's line-coverage percentage (100 when it has no measurable lines).
func (f FileCoverage) Percent() float64 {
	if f.TotalLines == 0 {
		return 100
	}
	return 100 * float64(f.CoveredLines) / float64(f.TotalLines)
}

// LineCoverage is immutable executable-line state. A missing line is unknown,
// never inferred as uncovered.
type LineCoverage map[string]map[int]bool

// CoverageReport is the whole-tree line coverage parsed from a report file (lcov / cobertura / jacoco).
type CoverageReport struct {
	Files        []FileCoverage `json:"files"`
	CoveredLines int            `json:"covered_lines"`
	TotalLines   int            `json:"total_lines"`
	Lines        LineCoverage   `json:"lines,omitempty"`
}

// CloneLines keeps analysis snapshots independent from parser/request maps.
func CloneLines(in LineCoverage) LineCoverage {
	if len(in) == 0 {
		return nil
	}
	out := make(LineCoverage, len(in))
	for path, lines := range in {
		copyLines := make(map[int]bool, len(lines))
		for line, covered := range lines {
			copyLines[line] = covered
		}
		out[path] = copyLines
	}
	return out
}

// NormalizeLines removes invalid and non-snapshot paths without creating false
// uncovered state. allowed must contain canonical project-relative file paths.
func (r *CoverageReport) NormalizeLines(allowed map[string]struct{}) {
	if r == nil {
		return
	}
	out := make(LineCoverage)
	for path, lines := range r.Lines {
		if _, ok := allowed[path]; !ok {
			continue
		}
		for line, covered := range lines {
			if line < 1 {
				continue
			}
			if out[path] == nil {
				out[path] = map[int]bool{}
			}
			out[path][line] = covered
		}
	}
	r.Lines = out
}

// Percent is the overall line-coverage percentage (0 when nothing is measurable).
func (r CoverageReport) Percent() float64 {
	if r.TotalLines == 0 {
		return 0
	}
	return 100 * float64(r.CoveredLines) / float64(r.TotalLines)
}

// NewCoverageReport builds a sorted, aggregated report from per-file (line -> covered) data. It is the
// single place the covered/total counts are derived, so the summary and the raw line map never drift.
func NewCoverageReport(byFile map[string]map[int]bool) CoverageReport {
	var rep CoverageReport
	for file, lines := range byFile {
		fc := FileCoverage{File: file}
		for _, covered := range lines {
			fc.TotalLines++
			if covered {
				fc.CoveredLines++
			}
		}
		rep.Files = append(rep.Files, fc)
		rep.TotalLines += fc.TotalLines
		rep.CoveredLines += fc.CoveredLines
	}
	sort.Slice(rep.Files, func(i, j int) bool { return rep.Files[i].File < rep.Files[j].File })
	return rep
}

// LeastCovered returns up to n files with the lowest coverage (and at least one measurable line), worst
// first, for a "focus here" display.
func (r CoverageReport) LeastCovered(n int) []FileCoverage {
	withLines := make([]FileCoverage, 0, len(r.Files))
	for _, f := range r.Files {
		if f.TotalLines > 0 {
			withLines = append(withLines, f)
		}
	}
	sort.SliceStable(withLines, func(i, j int) bool {
		if withLines[i].Percent() != withLines[j].Percent() {
			return withLines[i].Percent() < withLines[j].Percent()
		}
		return withLines[i].File < withLines[j].File
	})
	if n >= 0 && n < len(withLines) {
		withLines = withLines[:n]
	}
	return withLines
}
