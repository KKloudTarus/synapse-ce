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

// juliet_integration_test.go scores the owned Java taint engine against the Juliet Java test suite through the
// generalized per-CWE sastbench reducer, mirroring the OWASP and Securibench scorecards. Juliet is large
// (thousands of single-file cases per CWE), so the facts are extracted in bounded batches (one synapse-ast
// call per chunk) and merged, unlike the single-shot Securibench run. The test is gated on SYNAPSE_JULIET_DIR
// (a find-sec-bugs/juliet-test-suite checkout) plus SYNAPSE_AST_BIN (a java-facts-capable synapse-ast) and
// content-pins the answer key by digest, so it skips cleanly in normal CI and its workflow orchestration is
// left to #1043, exactly like the OWASP and Securibench gates.

// julietScoredCWEs are the Juliet vulnerability classes the owned Java value-flow engine models. Only CWE-89
// (SQL injection) is scored today; the loader and reducer generalize to more classes as the engine models
// them and their floors are calibrated.
var julietScoredCWEs = []string{"CWE-89"}

// julietLineWindow is 0 (exact line): the owned engine anchors a SQL finding on the sink call, which is the
// exact line the answer key marks, so an exact match is the faithful per-statement metric. A wider window
// would let a detection in one Juliet method borrow the answer of an adjacent method's identical sink.
const julietLineWindow = 0

// julietCorpusDigest pins the exact answer key the floors are calibrated against, so a changed or wrong Juliet
// checkout produces a loud failure instead of incomparable numbers. Override with SYNAPSE_JULIET_DIGEST for a
// deliberately re-pinned corpus (which must re-calibrate the floors).
const julietCorpusDigest = "9670e78482c92d7ac7df6a56cc83368a78e27d8dada10e2d96e4a793fffd6753"

// julietFactsBatch bounds how many files go into one synapse-ast facts extraction, keeping each call under the
// provider output cap. Single-file Juliet cases are self-contained, so batching by file never splits a flow.
const julietFactsBatch = 40

// julietFloors is the checked-in recall ratchet, calibrated from a real run of the owned engine over the
// pinned corpus, plus a loose precision tripwire that catches an all-flagging degeneracy.
func julietFloors() sastbench.CWEFloors {
	// Calibrated from a real run of the owned Java value-flow engine over the pinned corpus: recall 0.304
	// (420/1380 true SQLi flaws across all single-file CWE-89 source/sink/flow variants), precision 1.000
	// (zero of 4385 safe traps flagged). The recall floor sits just under the measured value so any regression
	// fails while the deterministic run passes; the precision tripwire is a loose global floor that only trips
	// on an all-flagging degeneracy (measured precision is far above it).
	return sastbench.CWEFloors{
		Recall:            map[string]float64{"CWE-89": 0.30},
		PrecisionTripwire: 0.30,
	}
}

func TestJulietScorecard(t *testing.T) {
	root := os.Getenv("SYNAPSE_JULIET_DIR")
	bin := os.Getenv("SYNAPSE_AST_BIN")
	if root == "" || bin == "" {
		t.Skip("set SYNAPSE_JULIET_DIR (a find-sec-bugs/juliet-test-suite checkout) and SYNAPSE_AST_BIN (java-facts-capable) to run the Juliet scorecard")
	}
	corpus, err := loadJuliet(root)
	if err != nil {
		t.Fatalf("load juliet corpus: %v", err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatalf("no Juliet cases loaded from %s: is this a find-sec-bugs/juliet-test-suite checkout?", root)
	}
	pin := julietCorpusDigest
	if o := strings.TrimSpace(os.Getenv("SYNAPSE_JULIET_DIGEST")); o != "" {
		pin = o
	}
	if got := sastbench.CorpusDigest(corpus.Cases); got != pin {
		t.Fatalf("juliet answer-key digest = %s, want %s: the corpus does not match the pinned revision the floors are calibrated for (re-pin SYNAPSE_JULIET_DIGEST and re-calibrate floors)", got, pin)
	}

	files := julietModeledFiles(t, root)
	detected := runJulietJavaTaint(t, bin, files)
	scores := sastbench.ScoreByCWE(detected, corpus.Cases, julietScoredCWEs, julietLineWindow)
	for _, s := range scores {
		t.Logf("juliet %s: total=%d tp=%d fp=%d fn=%d tn=%d precision=%.3f recall=%.3f",
			s.CWE, s.Total, s.TP, s.FP, s.FN, s.TN, s.Precision, s.Recall)
	}
	t.Logf("juliet corpus: files=%d cases=%d unclassified=%d", corpus.Files, len(corpus.Cases), corpus.Unclassified)

	report := sastbench.Report{
		Schema: sastbench.ReportSchemaVersion, Engine: "synapse-owned", Corpus: "juliet-java",
		CorpusDigest: pin, Stage: "propose", LineWindow: julietLineWindow,
		ScoredCWEs: julietScoredCWEs, CWEs: scores,
	}
	breaches := sastbench.CheckRatchetByCWE(report, julietFloors())
	if len(breaches) > 0 {
		t.Fatalf("juliet ratchet regression:\n%s", strings.Join(breaches, "\n"))
	}
}

// julietModeledFiles re-walks the corpus and returns the absolute paths of the single-file modeled-CWE test
// cases, in the same filter the loader uses, so the facts run over exactly the files the answer key covers.
func julietModeledFiles(t *testing.T, root string) []string {
	t.Helper()
	testcases := root
	if st, err := os.Stat(filepath.Join(root, "src", "testcases")); err == nil && st.IsDir() {
		testcases = filepath.Join(root, "src", "testcases")
	}
	var files []string
	err := filepath.Walk(testcases, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}
		base := filepath.Base(path)
		if _, ok := julietSinkSpecForFile(base); ok && julietSingleFile(base) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk juliet files: %v", err)
	}
	sort.Strings(files)
	return files
}

// runJulietJavaTaint extracts Java facts in bounded batches and returns the owned engine's line-anchored
// findings across the whole corpus. Each batch stages its files flat into a temp dir (Juliet base names are
// globally unique), extracts facts once, builds the value graph, and collects its vulnerabilities.
func runJulietJavaTaint(t *testing.T, bin string, files []string) []sastbench.Finding {
	t.Helper()
	prov := New(bin)
	seen := map[string]bool{}
	var out []sastbench.Finding
	for start := 0; start < len(files); start += julietFactsBatch {
		end := start + julietFactsBatch
		if end > len(files) {
			end = len(files)
		}
		dir := t.TempDir()
		for _, src := range files[start:end] {
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
		doc, avail, err := prov.JavaFacts(context.Background(), dir)
		if err != nil || !avail {
			t.Fatalf("java facts unavailable (need a java-facts-capable synapse-ast): err=%v avail=%v", err, avail)
		}
		if doc.Truncated {
			t.Fatalf("juliet facts truncated at batch %d-%d: lower julietFactsBatch", start, end)
		}
		g, gerr := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
		if gerr != nil {
			t.Fatalf("build java value graph: %v", gerr)
		}
		for _, p := range g.Vulnerabilities() {
			out = append(out, sastbench.Finding{File: filepath.Base(p.SinkPos.File), Line: p.SinkPos.Line, CWE: p.CWE})
		}
	}
	return out
}
