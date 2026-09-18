package cqbenchrun

import (
	"context"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/cqbench"
)

// fixturesDir is the corpus fixture root relative to this package.
const fixturesDir = "../../usecase/cqbench/testdata"

// TestRunOwnedOnDefaultCorpus runs the shipped owned engine over the embedded corpus and asserts the
// scorecard is well-formed and meets the checked-in ratchet. It is the owned half of the #1137 head-to-head;
// it runs in normal `go test` because the rule analyzer and duplication detector are pure Go (the synapse-ast
// sidecar is optional and only adds complexity/AST detections when present).
func TestRunOwnedOnDefaultCorpus(t *testing.T) {
	corpus := cqbench.DefaultCorpus()
	obs, skipped, err := RunOwned(context.Background(), corpus, fixturesDir)
	if err != nil {
		t.Fatalf("RunOwned: %v", err)
	}
	if len(obs) != len(corpus.Cases) {
		t.Fatalf("want one observation per case (%d), got %d", len(corpus.Cases), len(obs))
	}
	report, err := cqbench.Evaluate(OwnedEngine, corpus, obs)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	t.Logf("owned scorecard: %d cases, %d type cells, skipped=%v", report.Cases, len(report.Types), skipped)
	for _, cell := range report.Types {
		t.Logf("  %s/%s: TP=%d FP=%d FN=%d precision=%.3f recall=%.3f",
			cell.Language, cell.Type, cell.TP, cell.FP, cell.FN, cell.Precision, cell.Recall)
	}
	floors, tier := ratchetFloors(context.Background())
	t.Logf("ratchet tier: %s", tier)
	if breaches := cqbench.CheckRatchet(report, floors); len(breaches) != 0 {
		t.Fatalf("owned engine below %s ratchet floors:\n  %v", tier, breaches)
	}
}

// ratchetFloors returns the floor set matching the current run: the full-engine AST floors when the
// synapse-ast sidecar is available, otherwise the non-AST floors. The returned label names the tier for
// diagnostics so a breach message says which ratchet was enforced.
func ratchetFloors(ctx context.Context) (cqbench.Floors, string) {
	if SidecarAvailable(ctx) {
		return cqbench.DefaultFloorsAST(), "ast"
	}
	return cqbench.DefaultFloors(), "base"
}

// TestCodeQualityHeadToHead is the gated CI entry point for the #1137 owned-vs-SonarQube-CE head-to-head. It
// always enforces the owned engine's recall ratchet. When the CI workflow has run SonarQube CE over the same
// corpus and pointed SYNAPSE_CQBENCH_SONARQUBE_EXPORT at the reduced export, it also scores that baseline and
// records the head-to-head; the owned report and the baseline report are written to the paths named by
// SYNAPSE_CQBENCH_OWNED_REPORT / SYNAPSE_CQBENCH_SONARQUBE_REPORT when set, for upload as CI artifacts. The
// comparison is recorded, not gated: the acceptance is "a green job records Synapse vs SonarQube CE", and the
// owned ratchet is the regression gate.
func TestCodeQualityHeadToHead(t *testing.T) {
	corpus := cqbench.DefaultCorpus()
	obs, skipped, err := RunOwned(context.Background(), corpus, fixturesDir)
	if err != nil {
		t.Fatalf("RunOwned: %v", err)
	}
	owned, err := cqbench.Evaluate(OwnedEngine, corpus, obs)
	if err != nil {
		t.Fatalf("Evaluate owned: %v", err)
	}
	if len(skipped) != 0 {
		t.Logf("owned findings skipped (unmapped): %v", skipped)
	}
	floors, tier := ratchetFloors(context.Background())
	t.Logf("ratchet tier: %s", tier)
	if breaches := cqbench.CheckRatchet(owned, floors); len(breaches) != 0 {
		t.Fatalf("owned engine below %s ratchet floors:\n  %v", tier, breaches)
	}
	writeReport(t, os.Getenv("SYNAPSE_CQBENCH_OWNED_REPORT"), owned)

	exportPath := os.Getenv("SYNAPSE_CQBENCH_SONARQUBE_EXPORT")
	if exportPath == "" {
		t.Log("no SonarQube export provided (SYNAPSE_CQBENCH_SONARQUBE_EXPORT unset); owned ratchet only")
		return
	}
	f, err := os.Open(exportPath)
	if err != nil {
		t.Fatalf("open SonarQube export: %v", err)
	}
	defer func() { _ = f.Close() }()
	baseObs, err := cqbench.SonarQubeObservations(corpus, f)
	if err != nil {
		t.Fatalf("reduce SonarQube export: %v", err)
	}
	baseline, err := cqbench.Evaluate("sonarqube-ce", corpus, baseObs)
	if err != nil {
		t.Fatalf("Evaluate SonarQube baseline: %v", err)
	}
	writeReport(t, os.Getenv("SYNAPSE_CQBENCH_SONARQUBE_REPORT"), baseline)
	lines, err := cqbench.CompareToBaseline(owned, baseline)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	t.Log("code-quality head-to-head (owned vs SonarQube CE):")
	for _, line := range lines {
		t.Logf("  %s", line)
	}
}

func writeReport(t *testing.T, path string, report cqbench.Report) {
	t.Helper()
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create report %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := cqbench.EncodeReport(f, report); err != nil {
		t.Fatalf("encode report %q: %v", path, err)
	}
}

// TestOwnedDetectsGoTodo pins that the owned engine detects the labelled TODO code smell in the go-todo
// fixture, so the corpus case is a real recall measurement rather than a vacuous pass.
func TestOwnedDetectsGoTodo(t *testing.T) {
	corpus := cqbench.DefaultCorpus()
	obs, _, err := RunOwned(context.Background(), corpus, fixturesDir)
	if err != nil {
		t.Fatalf("RunOwned: %v", err)
	}
	var todoCase *cqbench.CaseObservation
	for i := range obs {
		if obs[i].Case == "go-todo-comment" {
			todoCase = &obs[i]
		}
	}
	if todoCase == nil {
		t.Fatal("go-todo-comment case not observed")
	}
	found := false
	for _, iss := range todoCase.Issues {
		if iss.File == "sample.go" && iss.Type == cqbench.TypeCodeSmell {
			found = true
		}
	}
	if !found {
		t.Fatalf("owned engine did not detect the TODO code smell in the go-todo fixture: %+v", todoCase.Issues)
	}
}
