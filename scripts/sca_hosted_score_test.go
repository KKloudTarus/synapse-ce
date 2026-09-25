//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestCheckOwnedFloorFailsOnMissedFinding(t *testing.T) {
	covered, affected, negative := 3, 2, 1
	zero := 0
	one := 1.0
	actual := bench.EngineResult{Engine: bench.EngineOwned, Covered: covered, AffectedRelations: affected, NegativeRelations: negative,
		TruePositives: 2, MetricsComplete: true, Precision: &one, Recall: &one}
	floor := bench.RatchetFloor{MinimumCovered: &covered, MinimumAffectedRelations: &affected,
		MinimumNegativeRelations: &negative, MinimumPrecision: &one, MinimumRecall: &one,
		MaximumFalsePositives: &zero, MaximumFalseNegatives: &zero, MaximumUnknown: &zero,
		MaximumIncomplete: &zero, MaximumUnsupported: &zero}
	if breaches := checkFloor(actual, floor); len(breaches) != 0 {
		t.Fatalf("passing owned result breached floor: %v", breaches)
	}
	actual.TruePositives--
	actual.FalseNegatives++
	half := 0.5
	actual.Recall = &half
	if breaches := checkFloor(actual, floor); len(breaches) == 0 {
		t.Fatal("a missing target finding must fail the owned floor")
	}
}

func TestAcceptedReferenceTracksCommittedRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accepted.json")
	write := func(runID string) {
		t.Helper()
		content := `{"accepted":true,"schema_version":"synapse-sca-trusted-acceptance-report-v1","workflow_run_id":"` + runID + `","input_digests":{"catalog":"catalog","oracle":"oracle","ratchet":"ratchet"}}`
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("123")
	if got, err := acceptedReference(path, "catalog", "oracle", "ratchet"); err != nil || got != "123" {
		t.Fatalf("first capture run: %q, %v", got, err)
	}
	write("456")
	if got, err := acceptedReference(path, "catalog", "oracle", "ratchet"); err != nil || got != "456" {
		t.Fatalf("refreshed capture run: %q, %v", got, err)
	}
	if _, err := acceptedReference(path, "changed", "oracle", "ratchet"); err == nil || !strings.Contains(err.Error(), "pins differ") {
		t.Fatalf("changed corpus must reject stale capture: %v", err)
	}
}

func TestHostedOwnedFloorRejectsOtherModes(t *testing.T) {
	floor := bench.RatchetFloor{Mode: bench.FloorGateModeUnsupportedOnly}
	if err := validateOwnedFloor(floor); err == nil {
		t.Fatal("unsupported-only floor cannot use the hosted accuracy scorer")
	}
	floor.Mode = bench.FloorGateModeAccuracy
	floor.AllowUndefinedPrecision = true
	if err := validateOwnedFloor(floor); err == nil {
		t.Fatal("undefined precision cannot use the hosted accuracy scorer")
	}
}
