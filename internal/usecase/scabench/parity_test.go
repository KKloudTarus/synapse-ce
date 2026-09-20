package scabench

import "testing"

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
