package coverage

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 0.05 }

func TestParseLCOV(t *testing.T) {
	data := "TN:\nSF:src/a.go\nDA:1,1\nDA:2,0\nDA:3,5\nend_of_record\n"
	rep, lc, err := ParseBytes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalLines != 3 || rep.CoveredLines != 2 {
		t.Errorf("lcov totals: got %d/%d, want 2/3", rep.CoveredLines, rep.TotalLines)
	}
	if !approx(rep.Percent(), 66.67) {
		t.Errorf("percent = %.2f, want ~66.67", rep.Percent())
	}
	if !lc["src/a.go"][1] || lc["src/a.go"][2] || !lc["src/a.go"][3] {
		t.Errorf("lcov line map wrong: %+v", lc["src/a.go"])
	}
}

func TestParseCobertura(t *testing.T) {
	data := `<?xml version="1.0"?>
<coverage><packages><package><classes>
<class filename="src/b.py"><lines>
<line number="1" hits="1"/><line number="2" hits="0"/>
</lines></class></classes></package></packages></coverage>`
	rep, _, err := ParseBytes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalLines != 2 || rep.CoveredLines != 1 {
		t.Errorf("cobertura totals: got %d/%d, want 1/2", rep.CoveredLines, rep.TotalLines)
	}
}

func TestParseJaCoCo(t *testing.T) {
	data := `<?xml version="1.0"?>
<report><package name="com/x"><sourcefile name="C.java">
<line nr="5" mi="0" ci="4"/><line nr="6" mi="2" ci="0"/><line nr="7" mi="0" ci="0"/>
</sourcefile></package></report>`
	rep, lc, err := ParseBytes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalLines != 2 || rep.CoveredLines != 1 { // line 7 (mi=0,ci=0) is non-executable, skipped
		t.Errorf("jacoco totals: got %d/%d, want 1/2", rep.CoveredLines, rep.TotalLines)
	}
	if !lc["com/x/C.java"][5] || lc["com/x/C.java"][6] {
		t.Errorf("jacoco line map wrong: %+v", lc["com/x/C.java"])
	}
	if _, ok := lc["com/x/C.java"][7]; ok {
		t.Errorf("non-executable line 7 must not be recorded")
	}
}

func TestNewCodePercent(t *testing.T) {
	_, lc, err := ParseBytes([]byte("SF:src/a.go\nDA:1,1\nDA:2,0\nDA:3,5\nend_of_record\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Changed lines 2 (uncovered) + 3 (covered) => 1/2 = 50%. Line 1 is unchanged, excluded.
	pct, ok := lc.NewCodePercent(map[string]map[int]bool{"src/a.go": {2: true, 3: true}})
	if !ok || !approx(pct, 50) {
		t.Errorf("new-code coverage = %.1f ok=%v, want 50", pct, ok)
	}
	// No changed line is measurable => ok=false.
	if _, ok := lc.NewCodePercent(map[string]map[int]bool{"other.go": {9: true}}); ok {
		t.Errorf("unmeasurable changed set must yield ok=false")
	}
}

func TestLeastCovered(t *testing.T) {
	rep, _, _ := ParseBytes([]byte("SF:hi.go\nDA:1,1\nDA:2,1\nend_of_record\nSF:lo.go\nDA:1,0\nDA:2,0\nend_of_record\n"))
	lc := rep.LeastCovered(1)
	if len(lc) != 1 || lc[0].File != "lo.go" {
		t.Errorf("least-covered should be lo.go, got %+v", lc)
	}
}

// A profile as `go test -coverprofile` writes it: import-path file names, one block per line, blocks
// that span several lines, and two blocks on one line (the `if` and its `else` body).
const goProfile = `mode: set
github.com/acme/app/internal/x/y.go:10.2,12.16 2 1
github.com/acme/app/internal/x/y.go:12.16,14.3 1 0
github.com/acme/app/internal/x/y.go:20.1,20.40 1 1
github.com/acme/app/cmd/main.go:5.13,7.2 1 1
`

func TestParseGoCoverProfileStripsModulePathAndUnionsBlocks(t *testing.T) {
	rep, lc, err := ParseBytesWithOptions([]byte(goProfile), Options{GoModulePath: "github.com/acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	y := lc["internal/x/y.go"]
	if y == nil {
		t.Fatalf("module path was not stripped; files = %v", keysOf(lc))
	}
	// 10-11 covered by the first block; 12 by both (count 1 and count 0) and therefore covered; 13-14
	// only by the uncovered block; 20 covered; nothing recorded for lines no block spans.
	for ln, want := range map[int]bool{10: true, 11: true, 12: true, 13: false, 14: false, 20: true} {
		if got, ok := y[ln]; !ok || got != want {
			t.Errorf("y.go line %d: got %v (recorded=%v), want %v", ln, got, ok, want)
		}
	}
	if _, recorded := y[15]; recorded {
		t.Error("line 15 is spanned by no block and must not be recorded")
	}
	if !lc["cmd/main.go"][6] {
		t.Error("cmd/main.go line 6 must be covered")
	}
	// Recorded: y.go 10-14 and 20, main.go 5-7 = 9 lines; covered: y.go 10,11,12,20 + main.go 5,6,7 = 7.
	if rep.TotalLines != 9 || rep.CoveredLines != 7 {
		t.Errorf("totals: got %d/%d, want 7/9", rep.CoveredLines, rep.TotalLines)
	}
}

func TestParseGoCoverProfileModes(t *testing.T) {
	for _, mode := range []string{"set", "count", "atomic"} {
		data := "mode: " + mode + "\nm/a.go:1.1,2.2 1 3\nm/a.go:3.1,3.9 1 0\n"
		_, lc, err := ParseBytesWithOptions([]byte(data), Options{GoModulePath: "m"})
		if err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
		if !lc["a.go"][1] || !lc["a.go"][2] || lc["a.go"][3] {
			t.Errorf("mode %s: line map wrong: %+v", mode, lc["a.go"])
		}
	}
}

func TestParseGoCoverProfileKeepsImportPathsWithoutAModule(t *testing.T) {
	_, lc, err := ParseBytes([]byte(goProfile))
	if err != nil {
		t.Fatal(err)
	}
	if lc["github.com/acme/app/internal/x/y.go"] == nil || lc["internal/x/y.go"] != nil {
		t.Errorf("without a module path the import path must be kept verbatim; files = %v", keysOf(lc))
	}
	// A module path that is not a prefix of the file changes nothing either.
	_, lc, err = ParseBytesWithOptions([]byte(goProfile), Options{GoModulePath: "github.com/other/mod"})
	if err != nil {
		t.Fatal(err)
	}
	if lc["github.com/acme/app/internal/x/y.go"] == nil {
		t.Errorf("a non-matching module path must not rewrite the file; files = %v", keysOf(lc))
	}
}

// TestParseGoCoverProfileFailsClosed: a coverprofile is written by one tool in one pass, so a line that
// does not parse means the file is not what it claims to be. It must not fall through to the lcov parser
// either, which would accept anything and report an empty, "successful" coverage.
func TestParseGoCoverProfileFailsClosed(t *testing.T) {
	for name, data := range map[string]string{
		"unknown mode":          "mode: bogus\nm/a.go:1.1,2.2 1 1\n",
		"too few fields":        "mode: set\nm/a.go:1.1,2.2 1\n",
		"no position":           "mode: set\nm/a.go 1 1\n",
		"span not start,end":    "mode: set\nm/a.go:1.1 1 1\n",
		"position not line.col": "mode: set\nm/a.go:1,2 1 1\n",
		"end before start":      "mode: set\nm/a.go:5.1,2.2 1 1\n",
		"line zero":             "mode: set\nm/a.go:0.1,2.2 1 1\n",
		"hit count not number":  "mode: set\nm/a.go:1.1,2.2 1 x\n",
		"negative hit count":    "mode: set\nm/a.go:1.1,2.2 1 -1\n",
		"negative statements":   "mode: set\nm/a.go:1.1,2.2 -1 1\n",
		// A block spanning more lines than any real basic block is a line asking the parser to size a
		// loop by a number the file chose; refused, not honoured. The last one would loop forever with a
		// `ln <= end` expansion even if it were within the bound.
		"block over the bound":    fmt.Sprintf("mode: set\nm/a.go:1.1,%d.1 1 1\n", maxGoCoverBlockLines+1),
		"profile over the bound":  overBoundProfile(),
		"block ending at max int": fmt.Sprintf("mode: set\nm/a.go:1.1,%d.1 1 1\n", math.MaxInt),
	} {
		t.Run(name, func(t *testing.T) {
			_, lc, err := ParseBytes([]byte(data))
			if err == nil {
				t.Fatalf("malformed profile was accepted; lines = %v", lc)
			}
		})
	}
}

func TestParseGoCoverProfileIsDetectedBeforeLCOV(t *testing.T) {
	// The same bytes through the lcov parser would yield nothing at all: no SF:/DA: records.
	if lc, err := parseLCOV([]byte(goProfile)); err != nil || len(lc) != 0 {
		t.Fatalf("precondition: lcov must see nothing in a coverprofile, got %v err=%v", lc, err)
	}
	_, lc, err := ParseBytes([]byte(goProfile))
	if err != nil || len(lc) == 0 {
		t.Fatalf("a coverprofile must be detected and parsed, got %v err=%v", lc, err)
	}
}

func keysOf(lc LineCoverage) []string {
	out := make([]string, 0, len(lc))
	for k := range lc {
		out = append(out, k)
	}
	return out
}

// overBoundProfile is a profile whose blocks are each within the per-block bound but together exceed
// the whole-profile bound.
func overBoundProfile() string {
	var b strings.Builder
	b.WriteString("mode: set\n")
	blocks := maxGoCoverLines/maxGoCoverBlockLines + 1
	for i := 0; i < blocks; i++ {
		start := i*maxGoCoverBlockLines + 1
		fmt.Fprintf(&b, "m/f%d.go:%d.1,%d.1 1 1\n", i, start, start+maxGoCoverBlockLines-1)
	}
	return b.String()
}

// TestParseGoCoverProfileExpandsExactlyToTheBound: a block exactly at the per-block bound, and a block
// ending on a large line, both parse in full — the bound refuses only what exceeds it.
func TestParseGoCoverProfileExpandsExactlyToTheBound(t *testing.T) {
	data := fmt.Sprintf("mode: set\nm/a.go:1.1,%d.1 1 1\nm/b.go:%d.1,%d.1 1 0\n", maxGoCoverBlockLines, maxGoCoverLines-3, maxGoCoverLines)
	_, lc, err := ParseBytesWithOptions([]byte(data), Options{GoModulePath: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if len(lc["a.go"]) != maxGoCoverBlockLines || !lc["a.go"][maxGoCoverBlockLines] {
		t.Fatalf("a block at the bound must expand in full, got %d lines", len(lc["a.go"]))
	}
	if len(lc["b.go"]) != 4 || lc["b.go"][maxGoCoverLines] {
		t.Fatalf("b.go: got %d lines, want 4 uncovered lines ending on %d", len(lc["b.go"]), maxGoCoverLines)
	}
}
