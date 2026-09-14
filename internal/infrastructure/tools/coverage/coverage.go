// Package coverage parses a test-coverage report (lcov, Cobertura XML, or JaCoCo XML) into per-file,
// per-line coverage. The format is auto-detected from the content. Read-only, size-bounded; returns the
// aggregated measure.CoverageReport plus the raw line map so a caller can compute new-code coverage
// (changed lines that are covered).
package coverage

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

const maxReportBytes = 256 << 20 // coverage reports can be large; cap defensively

// LineCoverage maps a file path to (line number -> covered). A line present here is an executable line;
// absent lines are not counted.
type LineCoverage map[string]map[int]bool

// Options tunes parsing for formats whose file paths are not repo-relative on their own.
type Options struct {
	// GoModulePath is the `module` directive of the scanned tree. A Go -coverprofile names files by
	// import path (module/pkg/file.go); with the module path known, that prefix is stripped so the
	// result keys on repo-relative paths like every other format. Empty leaves Go paths untouched.
	GoModulePath string
}

// Parse reads a coverage report file, auto-detects its format, and returns the aggregated report plus the
// per-line map.
func Parse(path string) (measure.CoverageReport, LineCoverage, error) {
	return ParseWithOptions(path, Options{})
}

// ParseWithOptions is Parse with format options.
func ParseWithOptions(path string, opts Options) (measure.CoverageReport, LineCoverage, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return measure.CoverageReport{}, nil, fmt.Errorf("stat coverage report: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxReportBytes {
		return measure.CoverageReport{}, nil, fmt.Errorf("%s is not a regular coverage file within %d bytes", path, maxReportBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-provided report path, regular + size-capped above
	if err != nil {
		return measure.CoverageReport{}, nil, fmt.Errorf("read coverage report: %w", err)
	}
	return ParseBytesWithOptions(data, opts)
}

// ParseBytes parses coverage data whose format is auto-detected: XML with a <coverage> root is Cobertura,
// XML with a <report> root is JaCoCo, a `mode:` header is a Go -coverprofile, otherwise the data is
// treated as lcov.
func ParseBytes(data []byte) (measure.CoverageReport, LineCoverage, error) {
	return ParseBytesWithOptions(data, Options{})
}

// ParseBytesWithOptions is ParseBytes with format options.
func ParseBytesWithOptions(data []byte, opts Options) (measure.CoverageReport, LineCoverage, error) {
	trimmed := bytes.TrimSpace(data)
	var (
		lc  LineCoverage
		err error
	)
	switch {
	case bytes.HasPrefix(trimmed, []byte("<")) && bytes.Contains(peek(trimmed), []byte("<report")):
		lc, err = parseJaCoCo(data)
	case bytes.HasPrefix(trimmed, []byte("<")) && bytes.Contains(peek(trimmed), []byte("<coverage")):
		lc, err = parseCobertura(data)
	case bytes.HasPrefix(trimmed, []byte(goCoverModePrefix)):
		lc, err = parseGoCoverProfile(data, opts.GoModulePath)
	default:
		lc, err = parseLCOV(data)
	}
	if err != nil {
		return measure.CoverageReport{}, nil, err
	}
	report := measure.NewCoverageReport(lc)
	report.Lines = measure.CloneLines(measure.LineCoverage(lc))
	return report, lc, nil
}

// peek returns the first chunk of the data (to sniff the root element past an <?xml?>/doctype prolog).
func peek(b []byte) []byte {
	if len(b) > 4096 {
		return b[:4096]
	}
	return b
}

func mark(lc LineCoverage, file string, line int, covered bool) {
	if file == "" || line < 1 {
		return
	}
	m := lc[file]
	if m == nil {
		m = map[int]bool{}
		lc[file] = m
	}
	// A line covered by any record stays covered (union across duplicate entries / merged reports).
	if covered {
		m[line] = true
	} else if _, ok := m[line]; !ok {
		m[line] = false
	}
}

// goCoverModePrefix opens every Go -coverprofile: "mode: set", "mode: count" or "mode: atomic".
const goCoverModePrefix = "mode: "

// maxGoCoverBlockLines bounds how many lines one coverprofile block may span, and maxGoCoverLines how
// many a whole profile may expand to. A block is a basic block of one function; a span in the hundreds
// of thousands of lines is not a real block, it is a line asking the parser to size a loop by a number
// the file chose. The report is operator-supplied on the CLI and uploaded on the server, so both are
// refused rather than honoured.
const (
	maxGoCoverBlockLines = 1 << 16
	maxGoCoverLines      = 1 << 22
)

// parseGoCoverProfile parses the profile `go test -coverprofile` writes. After the mode header, each line
// is one block: `file:startLine.startCol,endLine.endCol numStmts count`, where file is an import path.
// Every line the block spans is marked covered when count > 0; a line spanned by several blocks is
// covered if any of them is, which mark already provides (the union rule the merged-report path relies
// on). Column offsets are not needed for line coverage and are validated only for shape.
//
// Unlike the lcov parser, which skips a line it cannot read, this one fails on it. An lcov file is often
// hand-assembled from several tools and a stray line is noise; a coverprofile is written by one tool in
// one pass, so a line that does not parse means the file is not what it claims to be, and reporting
// coverage from the lines that did parse would present a partial profile as a whole one.
func parseGoCoverProfile(data []byte, modulePath string) (LineCoverage, error) {
	lc := LineCoverage{}
	expanded := 0
	prefix := ""
	if modulePath = strings.TrimSpace(modulePath); modulePath != "" {
		prefix = strings.TrimSuffix(modulePath, "/") + "/"
	}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if i == 0 {
			mode := strings.TrimSpace(strings.TrimPrefix(line, goCoverModePrefix))
			if mode != "set" && mode != "count" && mode != "atomic" {
				return nil, fmt.Errorf("go coverprofile: unknown mode %q (want set, count or atomic)", mode)
			}
			continue
		}
		// file:startLine.startCol,endLine.endCol numStmts count — split from the right so a file path
		// containing ':' (a Windows drive, say) still parses.
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("go coverprofile line %d: want 3 fields, got %d", i+1, len(fields))
		}
		colon := strings.LastIndexByte(fields[0], ':')
		if colon <= 0 {
			return nil, fmt.Errorf("go coverprofile line %d: missing file:position", i+1)
		}
		file, span := fields[0][:colon], fields[0][colon+1:]
		start, end, err := goCoverSpan(span)
		if err != nil {
			return nil, fmt.Errorf("go coverprofile line %d: %w", i+1, err)
		}
		if stmts, err := strconv.Atoi(fields[1]); err != nil || stmts < 0 {
			return nil, fmt.Errorf("go coverprofile line %d: statement count %q is not a non-negative number", i+1, fields[1])
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil || count < 0 {
			return nil, fmt.Errorf("go coverprofile line %d: hit count %q is not a non-negative number", i+1, fields[2])
		}
		if prefix != "" {
			file = strings.TrimPrefix(file, prefix)
		}
		// goCoverSpan guarantees 1 <= start <= end, so the arithmetic cannot overflow.
		blockLines := end - start + 1
		if blockLines > maxGoCoverBlockLines {
			return nil, fmt.Errorf("go coverprofile line %d: block spans %d lines, more than the %d one block may", i+1, blockLines, maxGoCoverBlockLines)
		}
		if expanded += blockLines; expanded > maxGoCoverLines {
			return nil, fmt.Errorf("go coverprofile: profile expands to more than %d lines", maxGoCoverLines)
		}
		// Stop on end before incrementing: `ln <= end` never terminates when end is the maximum int.
		for ln := start; ; ln++ {
			mark(lc, file, ln, count > 0)
			if ln == end {
				break
			}
		}
	}
	return lc, nil
}

// goCoverSpan reads `startLine.startCol,endLine.endCol` and returns the line range.
func goCoverSpan(span string) (start, end int, err error) {
	from, to, ok := strings.Cut(span, ",")
	if !ok {
		return 0, 0, fmt.Errorf("span %q is not start,end", span)
	}
	parse := func(pos string) (int, error) {
		lineStr, colStr, ok := strings.Cut(pos, ".")
		if !ok {
			return 0, fmt.Errorf("position %q is not line.col", pos)
		}
		ln, err1 := strconv.Atoi(lineStr)
		_, err2 := strconv.Atoi(colStr)
		if err1 != nil || err2 != nil || ln < 1 {
			return 0, fmt.Errorf("position %q is not line.col", pos)
		}
		return ln, nil
	}
	if start, err = parse(from); err != nil {
		return 0, 0, err
	}
	if end, err = parse(to); err != nil {
		return 0, 0, err
	}
	if end < start {
		return 0, 0, fmt.Errorf("span %q ends before it starts", span)
	}
	return start, end, nil
}

// parseLCOV parses an lcov .info file: SF:<file> sets the current file, DA:<line>,<hits> records a line.
func parseLCOV(data []byte) (LineCoverage, error) {
	lc := LineCoverage{}
	file := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "SF:"):
			file = strings.TrimSpace(line[3:])
		case strings.HasPrefix(line, "DA:"):
			rest := line[3:]
			comma := strings.IndexByte(rest, ',')
			if comma < 0 {
				continue
			}
			ln, err1 := strconv.Atoi(strings.TrimSpace(rest[:comma]))
			hits, err2 := strconv.Atoi(strings.TrimSpace(strings.SplitN(rest[comma+1:], ",", 2)[0]))
			if err1 != nil || err2 != nil {
				continue
			}
			mark(lc, file, ln, hits > 0)
		case line == "end_of_record":
			file = ""
		}
	}
	return lc, nil
}

// Cobertura XML subset.
type cobertura struct {
	Packages struct {
		Package []struct {
			Classes struct {
				Class []struct {
					Filename string `xml:"filename,attr"`
					Lines    struct {
						Line []struct {
							Number int `xml:"number,attr"`
							Hits   int `xml:"hits,attr"`
						} `xml:"line"`
					} `xml:"lines"`
				} `xml:"class"`
			} `xml:"classes"`
		} `xml:"package"`
	} `xml:"packages"`
}

func parseCobertura(data []byte) (LineCoverage, error) {
	var cov cobertura
	if err := xml.Unmarshal(data, &cov); err != nil {
		return nil, fmt.Errorf("parse cobertura: %w", err)
	}
	lc := LineCoverage{}
	for _, p := range cov.Packages.Package {
		for _, c := range p.Classes.Class {
			for _, l := range c.Lines.Line {
				mark(lc, c.Filename, l.Number, l.Hits > 0)
			}
		}
	}
	return lc, nil
}

// JaCoCo XML subset. A line is covered when it has covered instructions (ci > 0); ci==0 && mi==0 is a
// non-executable line and is skipped.
type jacoco struct {
	Package []struct {
		Name       string `xml:"name,attr"`
		Sourcefile []struct {
			Name string `xml:"name,attr"`
			Line []struct {
				Nr int `xml:"nr,attr"`
				Mi int `xml:"mi,attr"`
				Ci int `xml:"ci,attr"`
			} `xml:"line"`
		} `xml:"sourcefile"`
	} `xml:"package"`
}

func parseJaCoCo(data []byte) (LineCoverage, error) {
	var rep jacoco
	if err := xml.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse jacoco: %w", err)
	}
	lc := LineCoverage{}
	for _, p := range rep.Package {
		for _, sf := range p.Sourcefile {
			file := sf.Name
			if p.Name != "" {
				file = p.Name + "/" + sf.Name
			}
			for _, l := range sf.Line {
				if l.Ci == 0 && l.Mi == 0 {
					continue // non-executable line
				}
				mark(lc, file, l.Nr, l.Ci > 0)
			}
		}
	}
	return lc, nil
}

// NewCodePercent returns the line-coverage percentage over only the changed lines (file -> set), i.e.
// coverage on new code. changed[file][line] must be true for a changed line. ok=false when no changed
// line is measurable (so a caller can skip the metric rather than report a misleading 0 or 100).
func (lc LineCoverage) NewCodePercent(changed map[string]map[int]bool) (pct float64, ok bool) {
	total, covered := 0, 0
	for file, lines := range lc {
		ch := changed[file]
		if ch == nil {
			continue
		}
		for ln, cov := range lines {
			if !ch[ln] {
				continue
			}
			total++
			if cov {
				covered++
			}
		}
	}
	if total == 0 {
		return 0, false
	}
	return 100 * float64(covered) / float64(total), true
}
