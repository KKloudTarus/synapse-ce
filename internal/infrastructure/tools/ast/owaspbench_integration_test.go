package ast

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sastbench"
)

// TestOWASPBenchmarkScorecard scores the owned Java taint engine against the OWASP BenchmarkJava suite and
// enforces the per-category recall ratchet (EPIC #860 D5.8). The corpus is GPL v2, so it is NOT vendored:
// the test skips unless SYNAPSE_OWASP_BENCHMARK_DIR points at a local clone and SYNAPSE_AST_BIN points at a
// java-facts-capable synapse-ast (a CGO build). CI provisions both, mirroring the Postgres/Grype gated tests.
func TestOWASPBenchmarkScorecard(t *testing.T) {
	root := os.Getenv("SYNAPSE_OWASP_BENCHMARK_DIR")
	bin := os.Getenv("SYNAPSE_AST_BIN")
	if root == "" || bin == "" {
		t.Skip("set SYNAPSE_OWASP_BENCHMARK_DIR and SYNAPSE_AST_BIN (java-facts-capable) to run the OWASP scorecard")
	}
	// Pin the corpus version: the ratchet floors are calibrated for OWASP BenchmarkJava v1.2, so a different
	// (older/newer/modified) answer key would produce incomparable numbers that could pass the ratchet falsely.
	csvPath := findFile(root, "expectedresults-1.2.csv")
	testcode := filepath.Join(root, "src", "main", "java", "org", "owasp", "benchmark", "testcode")
	helpers := filepath.Join(root, "src", "main", "java", "org", "owasp", "benchmark", "helpers")
	if csvPath == "" {
		t.Fatalf("expectedresults-1.2.csv not found under %s: the ratchet floors are calibrated for OWASP BenchmarkJava v1.2; point SYNAPSE_OWASP_BENCHMARK_DIR at a v1.2 checkout", root)
	}
	cases := loadOWASPCases(t, csvPath)
	if len(cases) == 0 {
		t.Fatal("no scored-category cases parsed from the answer key")
	}
	// Completeness: every scored case must have its Java file present, or the run would silently score a
	// missing file as not-detected and corrupt the numbers.
	var missing []string
	for _, c := range cases {
		if _, err := os.Stat(filepath.Join(testcode, c.Name+".java")); err != nil {
			missing = append(missing, c.Name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d scored cases have no Java file under %s (corpus incomplete): %v", len(missing), testcode, firstN(missing, 5))
	}
	detected := runJavaTaintOverCorpus(t, bin, testcode, helpers)
	scores := sastbench.Score(detected, cases)
	for _, s := range scores {
		t.Logf("%-11s (%s): TP=%d FP=%d FN=%d TN=%d precision=%.3f recall=%.3f (propose-stage precision: no sanitizer modeling)", s.Category, s.CWE, s.TP, s.FP, s.FN, s.TN, s.Precision, s.Recall)
	}
	if breaches := sastbench.CheckRatchet(scores, sastbench.DefaultFloors()); len(breaches) > 0 {
		t.Fatalf("OWASP recall ratchet regressed: %v", breaches)
	}
}

func findFile(root, name string) string {
	var found string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == name && found == "" {
			found = p
		}
		return nil
	})
	return found
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

func loadOWASPCases(t *testing.T, csvPath string) []sastbench.Case {
	t.Helper()
	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	rd.Comment = '#'
	rows, err := rd.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var cases []sastbench.Case
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		cat := strings.TrimSpace(r[1])
		if _, ok := sastbench.ScoredCategories[cat]; !ok {
			continue
		}
		cases = append(cases, sastbench.Case{Name: strings.TrimSpace(r[0]), Category: cat, Real: strings.TrimSpace(r[2]) == "true"})
	}
	return cases
}

// runJavaTaintOverCorpus batches the test files (with helper classes for cross-file resolution) through the
// provider so no single facts document exceeds the provider's output cap, then unions the taint detections.
func runJavaTaintOverCorpus(t *testing.T, bin, testcode, helpers string) map[string]map[string]bool {
	t.Helper()
	ents, err := os.ReadDir(testcode)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".java") {
			files = append(files, filepath.Join(testcode, e.Name()))
		}
	}
	helperFiles, err := os.ReadDir(helpers)
	if err != nil {
		t.Fatalf("read OWASP helper classes at %s (needed for cross-file taint resolution): %v", helpers, err)
	}
	prov := New(bin)
	detected := map[string]map[string]bool{}
	const batch = 120
	for i := 0; i < len(files); i += batch {
		end := i + batch
		if end > len(files) {
			end = len(files)
		}
		bd := t.TempDir()
		copyInto := func(src, name string) {
			data, rerr := os.ReadFile(src)
			if rerr != nil {
				t.Fatalf("read corpus file %s: %v", src, rerr) // a dropped file would fake a not-detected result
			}
			if werr := os.WriteFile(filepath.Join(bd, name), data, 0o644); werr != nil {
				t.Fatalf("stage corpus file %s: %v", name, werr)
			}
		}
		for _, src := range files[i:end] {
			copyInto(src, filepath.Base(src))
		}
		for _, h := range helperFiles {
			if strings.HasSuffix(h.Name(), ".java") {
				copyInto(filepath.Join(helpers, h.Name()), h.Name())
			}
		}
		doc, avail, err := prov.JavaFacts(context.Background(), bd)
		if err != nil || !avail {
			t.Fatalf("java facts for batch [%d:%d] unavailable (need a java-facts-capable synapse-ast): err=%v avail=%v", i, end, err, avail)
		}
		g, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
		if err != nil {
			t.Fatalf("build java value graph for batch [%d:%d]: %v", i, end, err)
		}
		for _, p := range g.Vulnerabilities() {
			name := strings.TrimSuffix(filepath.Base(p.SinkPos.File), ".java")
			if detected[name] == nil {
				detected[name] = map[string]bool{}
			}
			detected[name][p.CWE] = true
		}
	}
	return detected
}
