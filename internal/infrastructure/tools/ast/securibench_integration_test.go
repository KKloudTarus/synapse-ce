package ast

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

// securibenchScoredCWEs are the Securibench Micro vulnerability classes the owned Java engine models. The
// corpus is dominated by reflected XSS (CWE-79) with a handful of SQL (CWE-89) cases; redirect, header, and
// other unmodeled-sink markers are reported as unclassified rather than scored. CWE-78 is listed so a future
// command case would score, though the current corpus marks none on a modeled command sink.
var securibenchScoredCWEs = []string{"CWE-78", "CWE-79", "CWE-89"}

// securibenchLineWindow is 0 (exact line): unlike the OWASP head-to-head where the owned engine and a
// different tool attribute a flow to lines a step apart, here the same owned engine is scored against an
// answer key whose markers sit on the very sink line the engine reports, so an exact match is the faithful
// per-statement metric. A wider window would smear adjacent distinct test cases (borrowing a neighbor's
// detection as a true positive, or flipping a safe case to a false positive) and desensitize the ratchet.
const securibenchLineWindow = 0

// securibenchCorpusDigest pins the exact answer key the floors are calibrated against, so a changed or wrong
// Securibench checkout produces a loud failure instead of incomparable numbers. Override with
// SYNAPSE_SECURIBENCH_DIGEST for a deliberately re-pinned corpus (which must re-calibrate the floors).
const securibenchCorpusDigest = "cdb5a5304703b52bb59ed4a71793ada89c5d89b0e35680dd747cc65b5743ec52"

// TestSecuribenchScorecard scores the owned Java taint engine against the Securibench Micro corpus and
// enforces the per-CWE recall ratchet. The corpus is Apache-2.0 but not vendored (125 files); the test skips
// unless SYNAPSE_SECURIBENCH_DIR points at a checkout and SYNAPSE_AST_BIN at a java-facts-capable synapse-ast,
// mirroring the gated OWASP scorecard.
func TestSecuribenchScorecard(t *testing.T) {
	root := os.Getenv("SYNAPSE_SECURIBENCH_DIR")
	bin := os.Getenv("SYNAPSE_AST_BIN")
	if root == "" || bin == "" {
		t.Skip("set SYNAPSE_SECURIBENCH_DIR and SYNAPSE_AST_BIN (java-facts-capable) to run the Securibench scorecard")
	}
	srcRoot := root
	if st, err := os.Stat(filepath.Join(root, "src")); err == nil && st.IsDir() {
		srcRoot = filepath.Join(root, "src")
	}
	corpus, err := loadSecuribench(srcRoot)
	if err != nil {
		t.Fatalf("load securibench corpus: %v", err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatalf("no Securibench cases loaded from %s: is this a Securibench Micro checkout?", srcRoot)
	}
	// Key both cases and detections on the base filename (Securibench names are globally unique), so the
	// package-tree source and the flat-staged facts share a file key.
	cases := make([]sastbench.LabeledCase, len(corpus.Cases))
	for i, c := range corpus.Cases {
		c.File = filepath.Base(c.File)
		cases[i] = c
	}
	pin := securibenchCorpusDigest
	if o := strings.TrimSpace(os.Getenv("SYNAPSE_SECURIBENCH_DIGEST")); o != "" {
		pin = o
	}
	if got := sastbench.CorpusDigest(cases); got != pin {
		t.Fatalf("securibench answer-key digest = %s, want %s: the corpus does not match the pinned revision the floors are calibrated for (re-pin SYNAPSE_SECURIBENCH_DIGEST and re-calibrate floors)", got, pin)
	}

	detected := runJavaTaintLineAnchored(t, bin, srcRoot)
	if exportPath := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_PROPOSALS")); exportPath != "" {
		exportSecuribenchBlindedProposals(t, exportPath, srcRoot, pin, detected)
	}
	verdictPath := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_VERDICTS"))
	if diagnosticPath := strings.TrimSpace(os.Getenv("SYNAPSE_POST_TRIAGE_DIAGNOSTIC_REPORT")); diagnosticPath != "" {
		if verdictPath == "" {
			t.Fatal("SYNAPSE_POST_TRIAGE_DIAGNOSTIC_REPORT requires SYNAPSE_POST_TRIAGE_VERDICTS")
		}
		writeSecuribenchDiagnosticReport(t, diagnosticPath, postTriageSecuribenchReport(t, verdictPath, srcRoot, pin, detected, cases))
	} else if verdictPath != "" {
		verifySecuribenchPostTriage(t, verdictPath, srcRoot, pin, detected, cases)
	}
	scores := sastbench.ScoreByCWE(detected, cases, securibenchScoredCWEs, securibenchLineWindow)
	for _, s := range scores {
		t.Logf("securibench %s: total=%d tp=%d fp=%d fn=%d tn=%d precision=%.3f recall=%.3f",
			s.CWE, s.Total, s.TP, s.FP, s.FN, s.TN, s.Precision, s.Recall)
	}
	t.Logf("securibench unclassified (unmodeled-sink) markers: %d", corpus.Unclassified)

	report := sastbench.Report{
		Schema: sastbench.ReportSchemaVersion, Engine: "synapse-owned", Corpus: "securibench-micro",
		CorpusDigest: pin, Stage: "propose", LineWindow: securibenchLineWindow,
		ScoredCWEs: securibenchScoredCWEs, CWEs: scores,
	}
	breaches := sastbench.CheckRatchetByCWE(report, sastbench.DefaultSecuribenchFloors())
	if len(breaches) > 0 {
		t.Fatalf("securibench ratchet regression:\n%s", strings.Join(breaches, "\n"))
	}

	// When SYNAPSE_SEMGREP_SARIF points at a Semgrep SARIF report over the same corpus, score Semgrep on the
	// identical answer key and log the per-CWE comparison. The hosted benchmark always supplies this input and
	// rejects a missing or invalid report before this test; local scorecard runs may omit it. Semgrep remains
	// comparison data, so its score never controls the owned-engine ratchet above.
	if sarifPath := strings.TrimSpace(os.Getenv("SYNAPSE_SEMGREP_SARIF")); sarifPath != "" {
		compareSecuribenchToSemgrep(t, sarifPath, cases, pin, scores)
	}
}

// semgrepPin records the Semgrep CE version and local ruleset revision used by the required comparison lane.
// The lane rejects missing or invalid reports, while the resulting comparison remains outside the owned
// engine's accuracy ratchet.
const (
	semgrepCEVersion = "1.177.0"
	semgrepCERuleset = "semgrep/semgrep-rules@a84ff9cc2453ca91d581380de4b8b3f272f6f4be:java"
)

// compareSecuribenchToSemgrep scores a Semgrep SARIF report on the same Securibench answer key and logs the
// owned-vs-Semgrep head-to-head. It never fails the test (competitor data is not truth); it only fails if the
// SARIF file is set but unreadable, which is an operator error worth surfacing.
func compareSecuribenchToSemgrep(t *testing.T, sarifPath string, cases []sastbench.LabeledCase, corpusDigest string, owned []sastbench.CWEScore) {
	t.Helper()
	f, err := os.Open(sarifPath)
	if err != nil {
		t.Fatalf("open SYNAPSE_SEMGREP_SARIF %s: %v", sarifPath, err)
	}
	defer func() { _ = f.Close() }()
	sgFindings, skipped, err := parseSemgrepSARIF(f)
	if err != nil {
		t.Fatalf("parse semgrep sarif: %v", err)
	}
	sgScores := sastbench.ScoreByCWE(sgFindings, cases, securibenchScoredCWEs, securibenchLineWindow)
	ownedReport := sastbench.Report{Schema: sastbench.ReportSchemaVersion, Engine: "synapse-owned", CorpusDigest: corpusDigest, CWEs: owned}
	sgReport := sastbench.Report{
		Schema: sastbench.ReportSchemaVersion, Engine: "semgrep-ce " + semgrepCEVersion + " " + semgrepCERuleset,
		CorpusDigest: corpusDigest, CWEs: sgScores,
	}
	lines, cerr := sastbench.CompareToBaseline(ownedReport, sgReport)
	if cerr != nil {
		t.Fatalf("compare to semgrep baseline: %v", cerr)
	}
	t.Logf("securibench head-to-head (owned vs %s, %d semgrep findings unclassifiable):", sgReport.Engine, skipped)
	for _, line := range lines {
		t.Logf("  %s", line)
	}
}

// runJavaTaintLineAnchored stages every .java file in the corpus flat into one directory (Securibench base
// names are globally unique, so cross-file static-import resolution still works and intra-file flows are
// preserved) and returns the engine's detections as line-anchored Findings keyed by base filename.
func runJavaTaintLineAnchored(t *testing.T, bin, srcRoot string) []sastbench.Finding {
	t.Helper()
	var files []string
	err := filepath.Walk(srcRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".java") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	dir := t.TempDir()
	seen := map[string]bool{}
	for _, src := range files {
		base := filepath.Base(src)
		if seen[base] {
			t.Fatalf("duplicate base filename %s: base-name keying would collide", base)
		}
		seen[base] = true
		data, rerr := os.ReadFile(src)
		if rerr != nil {
			t.Fatalf("read corpus file %s: %v", src, rerr)
		}
		if werr := os.WriteFile(filepath.Join(dir, base), data, 0o644); werr != nil {
			t.Fatalf("stage corpus file %s: %v", base, werr)
		}
	}
	prov := New(bin)
	doc, avail, err := prov.JavaFacts(context.Background(), dir)
	if err != nil || !avail {
		t.Fatalf("java facts unavailable (need a java-facts-capable synapse-ast): err=%v avail=%v", err, avail)
	}
	if doc.Truncated {
		t.Fatalf("securibench facts truncated: the corpus exceeded the provider output cap in one batch; add batching")
	}
	g, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
	if err != nil {
		t.Fatalf("build java value graph: %v", err)
	}
	var out []sastbench.Finding
	for _, p := range g.Vulnerabilities() {
		out = append(out, sastbench.Finding{File: filepath.Base(p.SinkPos.File), Line: p.SinkPos.Line, CWE: p.CWE})
	}
	return out
}
