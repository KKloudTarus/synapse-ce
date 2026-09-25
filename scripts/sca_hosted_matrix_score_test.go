//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestScoreMatrixRejectsMissingPinnedSBOM(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "owned")
	if err := os.WriteFile(binary, []byte("scanner"), 0o600); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join("..", "internal", "usecase", "scabench", "corpus")
	err := scoreMatrix(
		filepath.Join(corpus, "catalog.json"), filepath.Join(corpus, "oracle.json"),
		filepath.Join(corpus, "ratchet.json"), root, root, binary,
		"sha256:"+strings.Repeat("a", 64), strings.Repeat("b", 40), filepath.Join(root, "score.json"),
	)
	if err == nil || !strings.Contains(err.Error(), "SBOM pin mismatch") {
		t.Fatalf("missing pinned SBOM must fail closed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "score.json")); !os.IsNotExist(err) {
		t.Fatalf("a failed matrix must not publish a passing score, stat error: %v", err)
	}
}

func TestNumericalBreachesRejectsIncompleteAndRegressedCells(t *testing.T) {
	minimumCovered, minimumAffected, minimumNegative := 2, 1, 1
	maximumZero, minimumRatio := 0, 1.0
	floor := bench.RatchetFloor{
		MinimumCovered: &minimumCovered, MinimumAffectedRelations: &minimumAffected,
		MinimumNegativeRelations: &minimumNegative, MinimumPrecision: &minimumRatio,
		MinimumRecall: &minimumRatio, MaximumFalsePositives: &maximumZero,
		MaximumFalseNegatives: &maximumZero, MaximumUnknown: &maximumZero,
		MaximumIncomplete: &maximumZero, MaximumUnsupported: &maximumZero,
	}
	metrics := bench.EngineResult{
		Covered: 1, AffectedRelations: 1, NegativeRelations: 1,
		MetricsComplete: false, FalseNegatives: 1, Precision: &minimumRatio, Recall: &minimumRatio,
	}
	breaches := numericalBreaches(metrics, bench.ObservationIncomplete, floor)
	for _, expected := range []string{"incomplete_scan", "covered", "false_negatives"} {
		found := false
		for _, breach := range breaches {
			if breach == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing breach %q in %v", expected, breaches)
		}
	}
	unsupportedMax := 1
	floor.Mode = bench.FloorGateModeUnsupportedOnly
	floor.MaximumUnsupported = &unsupportedMax
	metrics = bench.EngineResult{Covered: 1, Unsupported: 1, MetricsComplete: true}
	if got := numericalBreaches(metrics, bench.ObservationUnsupported, floor); len(got) != 1 || got[0] != "unsupported_contract" {
		t.Fatalf("a covered cell cannot masquerade as unsupported: %v", got)
	}
}
