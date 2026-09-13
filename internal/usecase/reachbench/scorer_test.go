package reachbench

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }

func TestScoreCountsAndRates(t *testing.T) {
	cases := []Case{
		{ID: "r1", Language: "go", Symbol: "a.B", Want: judgment.Reachable},
		{ID: "r2", Language: "go", Symbol: "a.C", Want: judgment.Reachable},
		{ID: "u1", Language: "go", Symbol: "a.D", Want: judgment.NotReachable},
		{ID: "u2", Language: "go", Symbol: "a.E", Want: judgment.NotReachable},
	}
	observed := map[string]judgment.ReachabilityState{
		"r1": judgment.Reachable,    // TP
		"r2": judgment.NotReachable, // FN (a missed reachable)
		"u1": judgment.Reachable,    // FP (false alarm)
		"u2": judgment.NotReachable, // TN
	}
	m := Score(cases, observed).ByLanguage["go"]
	if m.TP != 1 || m.FN != 1 || m.FP != 1 || m.TN != 1 || m.Total != 4 {
		t.Fatalf("counts = %+v", m)
	}
	if m.Recall != 0.5 { // TP/(TP+FN) = 1/2
		t.Errorf("recall = %v, want 0.5", m.Recall)
	}
	if m.Precision != 0.5 { // TP/(TP+FP) = 1/2
		t.Errorf("precision = %v, want 0.5", m.Precision)
	}
	if m.Coverage != 1.0 { // all four answered
		t.Errorf("coverage = %v, want 1.0", m.Coverage)
	}
}

// TestScoreMissingVerdictIsAMiss: a reachable case the engine did not answer (no verdict / unknown) counts
// as a MISS (FN), not silently ignored, so a missing verdict can never inflate recall.
func TestScoreMissingVerdictIsAMiss(t *testing.T) {
	cases := []Case{{ID: "r1", Language: "go", Symbol: "a.B", Want: judgment.Reachable}}
	m := Score(cases, map[string]judgment.ReachabilityState{}).ByLanguage["go"] // no verdict at all
	if m.FN != 1 || m.TP != 0 || m.Answered != 0 || m.Recall != 0 {
		t.Fatalf("an unanswered reachable case must be a miss: %+v", m)
	}
}

func TestCheckRecallFloor(t *testing.T) {
	report := Report{ByLanguage: map[string]Metrics{
		"go":     {Recall: 0.9, TP: 9, FN: 1}, // passes its floor (exercised)
		"python": {Recall: 0.5, TP: 1, FN: 1}, // below its floor
		"rust":   {Recall: 1.0, TP: 0, FN: 0}, // floored but has NO reachable cases: floor not exercised
	}}
	report.ByLanguage["javascript"] = Metrics{Recall: 1.0, TP: 2} // scored but unfloored
	floor := RecallFloor{"go": 0.8, "python": 0.75, "rust": 0.9, "ruby": 0.9}
	v := CheckRecallFloor(report, floor)
	// Violations: python (below), rust (no reachable cases), ruby (absent), javascript (unfloored).
	if len(v) != 4 {
		t.Fatalf("want 4 violations, got %d: %v", len(v), v)
	}
}

func TestCheckParity(t *testing.T) {
	syn := Report{ByLanguage: map[string]Metrics{"go": {Recall: 0.9}, "python": {Recall: 1.0}}}
	comp := Report{ByLanguage: map[string]Metrics{"go": {Recall: 0.95}, "python": {Recall: 0.5}, "rust": {Recall: 1.0}}}
	// go: Synapse 0.9 < competitor 0.95 -> loss. python: 1.0 >= 0.5 -> ok. rust: competitor scored it but
	// Synapse did not -> a head-to-head loss (not a silent skip).
	losses := CheckParity(syn, comp, "osv", 0.0)
	if len(losses) != 2 {
		t.Fatalf("want 2 parity losses (go below, rust absent), got %v", losses)
	}
}

func TestLoadCorpusValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := writeFile(p, body); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := LoadCorpus(write("dup.json", `[{"id":"x","language":"go","symbol":"a.B","want":"reachable"},{"id":"x","language":"go","symbol":"a.C","want":"reachable"}]`)); err == nil {
		t.Error("duplicate id must be rejected")
	}
	if _, err := LoadCorpus(write("badwant.json", `[{"id":"x","language":"go","symbol":"a.B","want":"unknown"}]`)); err == nil {
		t.Error("want=unknown (not a ground-truth label) must be rejected")
	}
	if _, err := LoadCorpus(write("missing.json", `[{"id":"x","language":"go","want":"reachable"}]`)); err == nil {
		t.Error("a missing symbol must be rejected")
	}
	good, err := LoadCorpus(write("good.json", `[{"id":"x","language":"go","symbol":"a.B","want":"reachable"}]`))
	if err != nil || len(good) != 1 {
		t.Fatalf("a valid corpus must load: %v", err)
	}
}

// TestReachabilityBenchmarkRatchet is the gated CI scorecard (EPIC #1042, 5.1): score the vendored labeled
// corpus against Synapse's recorded verdicts, enforce the per-language RECALL floor (only rises), and assert
// parity-or-better vs OSV-Scanner's recorded verdicts on the SAME corpus. The corpus is pinned by content
// hash so a silent edit cannot pass the ratchet falsely. A live engine run regenerates the verdicts file;
// this test scores whatever the file records, so the ratchet gates the engine as each language ships.
func TestReachabilityBenchmarkRatchet(t *testing.T) {
	corpusPath := filepath.Join("testdata", "corpus.json")
	// Pin the corpus content the floors are calibrated against.
	const wantCorpusSHA = corpusSHA
	if got, err := CorpusSHA256(corpusPath); err != nil || got != wantCorpusSHA {
		t.Fatalf("corpus sha256 = %q (err %v), want %q: re-calibrate floors if the corpus changed intentionally", got, err, wantCorpusSHA)
	}
	cases, err := LoadCorpus(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	synapse, err := LoadVerdicts(filepath.Join("testdata", "synapse_verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	synReport := Score(cases, synapse)
	if v := CheckRecallFloor(synReport, recallFloor); len(v) != 0 {
		t.Fatalf("recall ratchet violated:\n  %v", v)
	}
	osv, err := LoadVerdicts(filepath.Join("testdata", "osv_verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if losses := CheckParity(synReport, Score(cases, osv), "OSV-Scanner", 0.0); len(losses) != 0 {
		t.Fatalf("Synapse must be parity-or-better vs OSV-Scanner per language:\n  %v", losses)
	}
}

// recallFloor is the checked-in reachability recall ratchet. Raise an entry when accuracy improves; never
// lower one (a lowered floor hides a recall regression, i.e. a missed reachable vulnerability).
var recallFloor = RecallFloor{
	"go":         1.0,
	"python":     1.0,
	"javascript": 1.0,
}

// corpusSHA pins internal/usecase/reachbench/testdata/corpus.json so the floors stay calibrated to the exact
// labeled set. Regenerate with reachbench.CorpusSHA256 when the corpus changes intentionally.
const corpusSHA = "82ea5ff48a550644da691ed73493f0a38ea094401b08ec520c8b94fafc23f0cc"
