package coverage

import (
	"math"
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
