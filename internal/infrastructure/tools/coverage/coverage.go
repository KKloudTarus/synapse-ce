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

// Parse reads a coverage report file, auto-detects its format, and returns the aggregated report plus the
// per-line map.
func Parse(path string) (measure.CoverageReport, LineCoverage, error) {
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
	return ParseBytes(data)
}

// ParseBytes parses coverage data whose format is auto-detected: XML with a <coverage> root is Cobertura,
// XML with a <report> root is JaCoCo, otherwise the data is treated as lcov.
func ParseBytes(data []byte) (measure.CoverageReport, LineCoverage, error) {
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
	default:
		lc, err = parseLCOV(data)
	}
	if err != nil {
		return measure.CoverageReport{}, nil, err
	}
	return measure.NewCoverageReport(lc), lc, nil
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
