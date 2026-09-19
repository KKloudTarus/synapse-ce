package sastbench

import (
	"bytes"
	"strings"
	"testing"
)

func findScore(scores []CWEScore, cwe string) (CWEScore, bool) {
	for _, s := range scores {
		if s.CWE == cwe {
			return s, true
		}
	}
	return CWEScore{}, false
}

// TestScoreByCWEFileLevel scores an OWASP-shaped corpus (one vuln per file, unlocated cases) and checks the
// confusion matrix: a real case with a matching detection is a TP, a real case without one an FN, a safe case
// with a detection an FP, a safe case without one a TN.
func TestScoreByCWEFileLevel(t *testing.T) {
	cases := []LabeledCase{
		{Name: "t1", File: "T1.java", CWE: "CWE-78", Real: true},  // real, will be flagged -> TP
		{Name: "t2", File: "T2.java", CWE: "CWE-78", Real: true},  // real, not flagged -> FN
		{Name: "t3", File: "T3.java", CWE: "CWE-78", Real: false}, // safe, flagged -> FP
		{Name: "t4", File: "T4.java", CWE: "CWE-78", Real: false}, // safe, not flagged -> TN
	}
	detected := []Finding{
		{File: "T1.java", CWE: "CWE-78"},
		{File: "T3.java", CWE: "CWE-78"},
		{File: "T9.java", CWE: "CWE-89"}, // unscored CWE, ignored
	}
	scores := ScoreByCWE(detected, cases, []string{"CWE-78"}, -1)
	s, ok := findScore(scores, "CWE-78")
	if !ok {
		t.Fatalf("no CWE-78 score; got %+v", scores)
	}
	if s.TP != 1 || s.FN != 1 || s.FP != 1 || s.TN != 1 || s.Total != 4 {
		t.Fatalf("confusion matrix wrong: %+v", s)
	}
	if s.Precision != 0.5 || s.Recall != 0.5 {
		t.Errorf("precision/recall = %.3f/%.3f, want 0.5/0.5", s.Precision, s.Recall)
	}
}

// TestScoreByCWELineWindow: a line-anchored corpus (a good and a bad function in one file) must classify each
// by the line window, not by file-level CWE presence, so the safe good-case is not tainted by the bad-case's
// detection two lines away.
func TestScoreByCWELineWindow(t *testing.T) {
	cases := []LabeledCase{
		{Name: "bad", File: "F.java", Line: 40, CWE: "CWE-89", Real: true},   // detection at 41 (window 2) -> TP
		{Name: "good", File: "F.java", Line: 80, CWE: "CWE-89", Real: false}, // no nearby detection -> TN
	}
	detected := []Finding{{File: "F.java", Line: 41, CWE: "CWE-89"}}
	scores := ScoreByCWE(detected, cases, []string{"CWE-89"}, DefaultLineWindow)
	s, _ := findScore(scores, "CWE-89")
	if s.TP != 1 || s.TN != 1 || s.FP != 0 || s.FN != 0 {
		t.Fatalf("line-window classification wrong: %+v", s)
	}

	// A detection just outside the window of the bad case must NOT match it (would be an FN for the real case).
	far := []Finding{{File: "F.java", Line: 43, CWE: "CWE-89"}} // 43-40=3 > window 2
	s2, _ := findScore(ScoreByCWE(far, cases, []string{"CWE-89"}, DefaultLineWindow), "CWE-89")
	if s2.TP != 0 || s2.FN != 1 {
		t.Errorf("a detection outside the line window must not match the real case: %+v", s2)
	}
}

// TestScoreByCWEUnlocatedDetectionMatchesFileLevel: a detection with Line 0 (unlocated) matches any case for
// its CWE in the same file, so a line-anchored corpus is never under-credited by an unlocated engine.
func TestScoreByCWEUnlocatedDetectionMatchesFileLevel(t *testing.T) {
	cases := []LabeledCase{{Name: "bad", File: "F.java", Line: 12, CWE: "CWE-22", Real: true}}
	detected := []Finding{{File: "F.java", Line: 0, CWE: "CWE-22"}}
	s, _ := findScore(ScoreByCWE(detected, cases, []string{"CWE-22"}, DefaultLineWindow), "CWE-22")
	if s.TP != 1 {
		t.Errorf("an unlocated detection must match at file level: %+v", s)
	}
}

// TestCorpusDigestOrderIndependent: the digest binds a report to its answer key and must not depend on case
// order, so two runs over the same cases shuffled produce the same digest, while a changed case changes it.
func TestCorpusDigestOrderIndependent(t *testing.T) {
	a := []LabeledCase{
		{Name: "t1", File: "T1.java", CWE: "CWE-78", Real: true},
		{Name: "t2", File: "T2.java", CWE: "CWE-89", Real: false},
	}
	b := []LabeledCase{a[1], a[0]} // shuffled
	if CorpusDigest(a) != CorpusDigest(b) {
		t.Errorf("digest must be order-independent")
	}
	c := append([]LabeledCase(nil), a...)
	c[0].Real = false // a changed verdict must change the digest
	if CorpusDigest(a) == CorpusDigest(c) {
		t.Errorf("a changed case must change the digest")
	}
}

// TestReportRoundTripAndSchemaGate: a report survives encode/decode, and a wrong schema is refused so an
// incompatible baseline is never scored.
func TestReportRoundTripAndSchemaGate(t *testing.T) {
	rep := Report{
		Schema: ReportSchemaVersion, Engine: "synapse-owned", Corpus: "juliet-java", CorpusDigest: "abc", Stage: "propose",
		CWEs: []CWEScore{{CWE: "CWE-78", Total: 2, TP: 1, FN: 1, Recall: 0.5}},
	}
	var buf bytes.Buffer
	if err := EncodeReport(&buf, rep); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := LoadReport(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Engine != rep.Engine || len(got.CWEs) != 1 || got.CWEs[0].Recall != 0.5 {
		t.Errorf("round trip mismatch: %+v", got)
	}
	bad := strings.Replace(buf.String(), ReportSchemaVersion, "synapse-sast-report-v99", 1)
	if _, err := LoadReport(strings.NewReader(bad)); err == nil {
		t.Errorf("a wrong schema must be refused")
	}
}

// TestCheckRatchetByCWE: a recall below its floor and an all-flagging precision collapse each breach; a CWE
// with no floor is ungated, and the tripwire ignores a CWE with no labelled true cases.
func TestCheckRatchetByCWE(t *testing.T) {
	floors := CWEFloors{Recall: map[string]float64{"CWE-78": 0.40}, PrecisionTripwire: 0.30}
	report := Report{Schema: ReportSchemaVersion, CWEs: []CWEScore{
		{CWE: "CWE-78", TP: 1, FN: 4, FP: 0, Recall: 0.20, Precision: 1.0}, // recall 0.20 < 0.40 -> breach
		{CWE: "CWE-89", TP: 1, FN: 0, FP: 9, Recall: 1.0, Precision: 0.10}, // no floor, but precision 0.10 < tripwire and TP+FN>0 -> breach
		{CWE: "CWE-22", TP: 0, FN: 0, FP: 3, Recall: 0, Precision: 0.0},    // no true cases (TP+FN=0) -> tripwire ignores
	}}
	breaches := CheckRatchetByCWE(report, floors)
	if len(breaches) != 2 {
		t.Fatalf("want 2 breaches (CWE-78 recall, CWE-89 tripwire), got %d: %v", len(breaches), breaches)
	}
	joined := strings.Join(breaches, "\n")
	if !strings.Contains(joined, "CWE-78 recall") || !strings.Contains(joined, "CWE-89 precision") {
		t.Errorf("unexpected breaches: %v", breaches)
	}
	if strings.Contains(joined, "CWE-22") {
		t.Errorf("a CWE with no labelled true cases must not trip the precision wire: %v", breaches)
	}
}

// TestCheckRatchetByCWEBreachesOnDroppedFloor: a committed recall floor whose CWE is absent from the report
// (its adapter dropped coverage) must breach, so the ratchet cannot be bypassed by removing a CWE.
func TestCheckRatchetByCWEBreachesOnDroppedFloor(t *testing.T) {
	floors := CWEFloors{Recall: map[string]float64{"CWE-78": 0.40, "CWE-89": 0.70}}
	report := Report{Schema: ReportSchemaVersion, CWEs: []CWEScore{
		{CWE: "CWE-78", TP: 5, FN: 1, Recall: 0.83}, // meets its floor
		// CWE-89 has a committed floor but is absent from the report.
	}}
	breaches := CheckRatchetByCWE(report, floors)
	if len(breaches) != 1 || !strings.Contains(breaches[0], "CWE-89") || !strings.Contains(breaches[0], "absent") {
		t.Fatalf("a floored CWE absent from the report must breach; got %v", breaches)
	}
}

// TestImprovedOverBaselineFailsOnDroppedCWE: dropping a CWE the baseline covered is a coverage loss, not an
// improvement, even if a remaining CWE improves.
func TestImprovedOverBaselineFailsOnDroppedCWE(t *testing.T) {
	base := Report{Schema: ReportSchemaVersion, CorpusDigest: "d",
		CWEs: []CWEScore{{CWE: "CWE-78", Precision: 0.50}, {CWE: "CWE-89", Precision: 0.90}}}
	owned := Report{Schema: ReportSchemaVersion, CorpusDigest: "d",
		CWEs: []CWEScore{{CWE: "CWE-78", Precision: 0.80}}} // CWE-89 dropped
	improved, detail, err := ImprovedOverBaseline(owned, base, 1e-9)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if improved {
		t.Errorf("dropping a baseline CWE must fail the improvement check; detail %v", detail)
	}
	if !strings.Contains(strings.Join(detail, "\n"), "CWE-89 dropped") {
		t.Errorf("the dropped CWE must be reported; detail %v", detail)
	}
}

// TestCompareToBaselineRequiresSameCorpus: the head-to-head refuses reports bound to different corpora, and
// lists every CWE present in either report so a dropped adapter cannot hide a comparison.
func TestCompareToBaselineRequiresSameCorpus(t *testing.T) {
	owned := Report{Schema: ReportSchemaVersion, Engine: "synapse-owned", CorpusDigest: "d1",
		CWEs: []CWEScore{{CWE: "CWE-78", Recall: 0.6, Precision: 0.5}, {CWE: "CWE-89", Recall: 0.4, Precision: 0.9}}}
	base := Report{Schema: ReportSchemaVersion, Engine: "semgrep-ce", CorpusDigest: "d1",
		CWEs: []CWEScore{{CWE: "CWE-78", Recall: 0.5, Precision: 0.7}}} // no CWE-89

	if _, err := CompareToBaseline(owned, Report{Schema: ReportSchemaVersion, CorpusDigest: "other", CWEs: base.CWEs}); err == nil {
		t.Errorf("a comparison across different corpora must be refused")
	}
	lines, err := CompareToBaseline(owned, base)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "CWE-78: owned recall 0.600") || !strings.Contains(joined, "semgrep-ce recall 0.500") {
		t.Errorf("head-to-head missing the CWE-78 comparison: %v", lines)
	}
	if !strings.Contains(joined, "CWE-89: owned recall 0.400 / precision 0.900 vs semgrep-ce (no detections)") {
		t.Errorf("a CWE present only in owned must still be listed: %v", lines)
	}
}

// TestImprovedOverBaseline: post-triage acceptance requires no precision regression on any shared CWE and at
// least one strict improvement.
func TestImprovedOverBaseline(t *testing.T) {
	base := Report{Schema: ReportSchemaVersion, CorpusDigest: "d",
		CWEs: []CWEScore{{CWE: "CWE-78", Precision: 0.50}, {CWE: "CWE-89", Precision: 0.60}}}

	// Post-triage improves CWE-78 and holds CWE-89 -> improved.
	better := Report{Schema: ReportSchemaVersion, CorpusDigest: "d",
		CWEs: []CWEScore{{CWE: "CWE-78", Precision: 0.80}, {CWE: "CWE-89", Precision: 0.60}}}
	improved, _, err := ImprovedOverBaseline(better, base, 1e-9)
	if err != nil || !improved {
		t.Errorf("post-triage that improves one CWE and holds the rest must count as improved (got %v, err %v)", improved, err)
	}

	// A regression on any CWE fails even if another improves.
	mixed := Report{Schema: ReportSchemaVersion, CorpusDigest: "d",
		CWEs: []CWEScore{{CWE: "CWE-78", Precision: 0.80}, {CWE: "CWE-89", Precision: 0.40}}}
	improved, _, _ = ImprovedOverBaseline(mixed, base, 1e-9)
	if improved {
		t.Errorf("a precision regression on any CWE must fail the improvement check")
	}
}
