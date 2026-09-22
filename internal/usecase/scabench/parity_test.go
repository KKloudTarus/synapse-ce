package scabench

import (
	"strings"
	"testing"
)

func recallPtr(v float64) *float64 { return &v }

func mkEngineResult(e Engine, recall float64, complete bool) EngineResult {
	er := EngineResult{Engine: e, MetricsComplete: complete}
	if complete {
		er.Recall = recallPtr(recall)
	}
	return er
}

// TestOwnedBeatsEachComparatorPasses: owned out-recalls every comparator -> flip allowed.
func TestOwnedBeatsEachComparatorPasses(t *testing.T) {
	res := Result{Engines: []EngineResult{
		mkEngineResult(EngineOwned, 1.0, true),
		mkEngineResult(EngineGrype, 0.90, true),
		mkEngineResult(EngineTrivy, 0.85, true),
		mkEngineResult(EngineOSVScanner, 0.95, true),
	}}
	ok, detail, err := OwnedBeatsEachComparator(res)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(detail.Breaches) != 0 {
		t.Errorf("owned should beat all comparators, got ok=%v breaches=%v", ok, detail.Breaches)
	}
	if len(detail.ComparedEngines) != 3 {
		t.Errorf("all three comparators should be compared, got %v", detail.ComparedEngines)
	}
}

// TestOwnedRecallParityAtEqualPasses: equal recall is parity, not a breach.
func TestOwnedRecallParityAtEqualPasses(t *testing.T) {
	res := Result{Engines: []EngineResult{
		mkEngineResult(EngineOwned, 0.90, true),
		mkEngineResult(EngineGrype, 0.90, true),
	}}
	ok, _, err := OwnedBeatsEachComparator(res)
	if err != nil || !ok {
		t.Errorf("equal recall must pass (parity), got ok=%v err=%v", ok, err)
	}
}

// TestFlipBlockedWhenComparatorOutRecallsOwnedDespiteAbsoluteFloor is the amendment's required NEGATIVE gate:
// the owned engine meets a high absolute recall floor (0.80) yet a comparator out-recalls it, so the owned-only
// flip must remain blocked. This is the market-leading guard: an absolute floor alone is insufficient.
func TestFlipBlockedWhenComparatorOutRecallsOwnedDespiteAbsoluteFloor(t *testing.T) {
	const absoluteRecallFloor = 0.80
	ownedRecall := 0.80 // passes the absolute floor exactly
	res := Result{Engines: []EngineResult{
		mkEngineResult(EngineOwned, ownedRecall, true),
		mkEngineResult(EngineGrype, 0.92, true), // grype out-recalls owned
		mkEngineResult(EngineTrivy, 0.70, true),
	}}
	if ownedRecall < absoluteRecallFloor {
		t.Fatal("precondition: owned must pass the absolute floor for this test to be meaningful")
	}
	ok, detail, err := OwnedBeatsEachComparator(res)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("flip must be BLOCKED: owned recall %.2f passes the absolute floor but grype out-recalls it", ownedRecall)
	}
	if len(detail.Breaches) != 1 {
		t.Fatalf("exactly grype should breach, got %v", detail.Breaches)
	}
}

// TestOwnedRecallUndefinedFailsClosed: no owned metrics -> cannot justify the flip.
func TestOwnedRecallUndefinedFailsClosed(t *testing.T) {
	// owned present but metrics incomplete
	res := Result{Engines: []EngineResult{
		mkEngineResult(EngineOwned, 0, false),
		mkEngineResult(EngineGrype, 0.90, true),
	}}
	if ok, _, err := OwnedBeatsEachComparator(res); ok || err == nil {
		t.Errorf("incomplete owned metrics must fail closed (ok=false, err set), got ok=%v err=%v", ok, err)
	}
	// owned entirely absent
	res2 := Result{Engines: []EngineResult{mkEngineResult(EngineGrype, 0.90, true)}}
	if ok, _, err := OwnedBeatsEachComparator(res2); ok || err == nil {
		t.Errorf("absent owned engine must fail closed, got ok=%v err=%v", ok, err)
	}
}

// TestUnmeasuredComparatorIsNotABaseline: a comparator with incomplete metrics is skipped, not a false pass or
// a false breach.
func TestUnmeasuredComparatorIsNotABaseline(t *testing.T) {
	res := Result{Engines: []EngineResult{
		mkEngineResult(EngineOwned, 0.88, true),
		mkEngineResult(EngineGrype, 0.85, true),
		mkEngineResult(EngineTrivy, 0, false),      // not run on this matrix
		mkEngineResult(EngineOSVScanner, 0, false), // not run on this matrix
	}}
	ok, detail, err := OwnedBeatsEachComparator(res)
	if err != nil || !ok {
		t.Errorf("owned beats the one measured comparator; unmeasured ones are skipped, got ok=%v err=%v", ok, err)
	}
	if len(detail.ComparedEngines) != 1 || detail.ComparedEngines[0] != EngineGrype {
		t.Errorf("only grype was measured and should be compared, got %v", detail.ComparedEngines)
	}
}

func TestMeasuredPerTargetRecallParityRejectsComparatorOutRecallDespitePermissiveFloors(t *testing.T) {
	catalog := validCatalog()
	oracle := validOracle(
		validCase("affected", "CVE-2024-1111", TruthAffected),
		validCase("fixed", "CVE-2024-2222", TruthFixed),
	)
	observations := make([]Observation, 0, len(Engines()))
	for _, engine := range Engines() {
		observation := completeObservation(catalog, engine)
		if engine != EngineOwned {
			observation = withFinding(observation, "CVE-2024-1111")
		}
		observations = append(observations, observation)
	}
	result, err := Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	ratchet := completeRatchet(result, result.Runs[0])
	for index := range ratchet.Floors {
		ratchet.Floors[index].AllowUndefinedPrecision = true
	}
	gated, err := ApplyRatchet(result, ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if gated.Gate == nil || !gated.Gate.Passed {
		t.Fatal("permissive policy floors must pass before the measured parity check")
	}
	if err := ValidateMeasuredPerTargetRecallParity(gated, []string{"image"}); err == nil || !strings.Contains(err.Error(), "exceeds owned recall") {
		t.Fatalf("measured comparator recall above owned recall was accepted: %v", err)
	}
}

func TestMeasuredPerTargetRecallParityExcludesUnsupportedComparatorOnlyWithCapabilityIdentity(t *testing.T) {
	result, _ := mixedMatrixResult(t)
	targets := []string{"debian", "suse"}
	if err := ValidateMeasuredPerTargetRecallParity(result, targets); err != nil {
		t.Fatalf("valid unsupported comparator cell rejected: %v", err)
	}
	for index := range result.RunMetrics {
		metric := &result.RunMetrics[index]
		if metric.Run.TargetID == "suse" && metric.Run.Engine == EngineOSVScanner {
			metric.Run.CapabilityDigest = ""
			break
		}
	}
	if err := ValidateMeasuredPerTargetRecallParity(result, targets); err == nil || !strings.Contains(err.Error(), "capability") {
		t.Fatalf("unsupported comparator without a capability identity was accepted: %v", err)
	}
}

func TestMeasuredPerTargetRecallParityRejectsUnsupportedComparatorWithForeignCapability(t *testing.T) {
	result, _ := mixedMatrixResult(t)
	for index := range result.RunMetrics {
		metric := &result.RunMetrics[index]
		if metric.Run.TargetID == "debian" && metric.Run.Engine == EngineGrype {
			metric.Run.State = ObservationUnsupported
			metric.Run.CapabilityKind = CapabilityKindOSVScannerSUSERPM
			metric.Run.CapabilityDigest = "sha256:" + strings.Repeat("a", 64)
			metric.Metrics = EngineResult{Engine: EngineGrype, Unsupported: 1, MetricsComplete: true}
			break
		}
	}
	if err := ValidateMeasuredPerTargetRecallParity(result, []string{"debian", "suse"}); err == nil {
		t.Fatal("unsupported comparator carrying another engine's capability identity was excluded from parity")
	}
}

func TestMeasuredPerTargetRecallParityFailsClosedForMalformedCells(t *testing.T) {
	base, _ := mixedMatrixResult(t)
	targets := []string{"debian", "suse"}
	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{
			name: "missing cell",
			mutate: func(result *Result) {
				result.RunMetrics = result.RunMetrics[1:]
			},
		},
		{
			name: "duplicate cell",
			mutate: func(result *Result) {
				result.RunMetrics = append(result.RunMetrics, result.RunMetrics[0])
			},
		},
		{
			name: "unknown state",
			mutate: func(result *Result) {
				result.RunMetrics[0].Run.State = ObservationUnknown
			},
		},
		{
			name: "incomplete metrics",
			mutate: func(result *Result) {
				for index := range result.RunMetrics {
					metric := &result.RunMetrics[index]
					if metric.Run.State == ObservationComplete {
						metric.Metrics.MetricsComplete = false
						metric.Metrics.Precision = nil
						metric.Metrics.Recall = nil
						return
					}
				}
			},
		},
		{
			name: "malformed engine",
			mutate: func(result *Result) {
				result.RunMetrics[0].Metrics.Engine = Engine("unknown")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := base
			result.RunMetrics = append([]RunMetric(nil), base.RunMetrics...)
			test.mutate(&result)
			if err := ValidateMeasuredPerTargetRecallParity(result, targets); err == nil {
				t.Fatal("malformed measured recall cell was accepted")
			}
		})
	}
}
