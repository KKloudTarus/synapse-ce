package scabench

import (
	"os"
	"strings"
	"testing"
)

// TestOwnedRecallParityOnCommittedRatchet wires OwnedBeatsEachComparator to the committed SCA oracle ratchet.
// The one accepted SLES/Grype gap stays explicit until a trusted measured cycle proves it can be removed.
func TestOwnedRecallParityOnCommittedRatchet(t *testing.T) {
	file, err := os.Open("corpus/ratchet.json")
	if err != nil {
		t.Fatalf("open committed ratchet: %v", err)
	}
	defer func() { _ = file.Close() }()
	ratchet, err := DecodeRatchet(file)
	if err != nil {
		t.Fatalf("decode committed ratchet: %v", err)
	}

	byTarget := map[string][]EngineResult{}
	for _, floor := range ratchet.Floors {
		if floor.MinimumRecall == nil {
			continue
		}
		byTarget[floor.Expected.TargetID] = append(byTarget[floor.Expected.TargetID], EngineResult{
			Engine:          floor.Expected.Engine,
			MetricsComplete: true,
			Recall:          floor.MinimumRecall,
		})
	}
	if len(byTarget) == 0 {
		t.Fatal("committed ratchet has no per-engine recall floors to check parity against")
	}

	// No tracked owned-vs-comparator recall debt remains. Architecture-qualified RPM evidence is carried on
	// the affected identity and enforced at match time, so owned covers every reviewed SLES affected relation
	// (16/16) rather than only the not-yet-fixed subset (8/16) it could represent before. Add an entry here
	// only alongside measured evidence that the breach is real and intended.
	knownDebt := map[string]bool{}
	sawKnown := map[string]bool{}
	for target, engines := range byTarget {
		ok, detail, parityErr := OwnedBeatsEachComparator(Result{Engines: engines})
		if parityErr != nil {
			t.Errorf("target %s: owned recall is undefined in the committed floors: %v", target, parityErr)
			continue
		}
		if ok {
			continue
		}
		for _, breach := range detail.Breaches {
			comparator := strings.Fields(breach)[0]
			key := target + "|" + comparator
			if !knownDebt[key] {
				t.Errorf("new owned-vs-comparator recall regression on target %s: %s", target, breach)
			}
			sawKnown[key] = true
		}
	}
	for key := range knownDebt {
		if !sawKnown[key] {
			t.Errorf("tracked parity debt %q no longer breaches committed floors; remove it only after measured parity passes", key)
		}
	}
}

// committedOwnedAccuracyFloor is the reviewed owned-engine threshold policy for every accuracy target the
// corpus pins. It exists because ValidateRatchetTightening only protects targets present in
// corpus/ratchet-baseline.json, and that baseline holds 8 floors covering debian and sles only. A target added
// afterwards -- rhel-9-8-ubi-amd64 is the first -- is anchored by nothing: TestOwnedRecallParityOnCommittedRatchet
// compares floors against each other, and TestCandidateRatchetPreservesHistoricalFloorPolicy iterates the
// baseline. Lowering such a floor is the exact "quietly move the bar to match a disappointing capture" edit the
// ratchet exists to prevent, so the reviewed numbers are stated here and asserted.
//
// Raising a floor is a tightening and needs no edit here beyond the new value. LOWERING one is a policy
// reversal: change it only with the measured evidence and the review that justify it.
var committedOwnedAccuracyFloor = map[string]struct {
	Recall            float64
	Precision         float64
	MaxFalseNegatives int
	MaxFalsePositives int
}{
	"debian-12-13-slim-amd64":        {Recall: 1, Precision: 1, MaxFalseNegatives: 0, MaxFalsePositives: 0},
	"rhel-9-8-ubi-amd64":             {Recall: 1, Precision: 1, MaxFalseNegatives: 0, MaxFalsePositives: 0},
	"sles-15-6-bci-base-45-31-amd64": {Recall: 1, Precision: 1, MaxFalseNegatives: 0, MaxFalsePositives: 0},
}

// TestCommittedOwnedAccuracyFloorsAreNotLoosened pins the owned engine's reviewed thresholds on every accuracy
// target, including targets added after the accepted baseline. Without it, an edit that relaxes recall,
// precision, or an error ceiling to match a weak capture passes the whole package.
func TestCommittedOwnedAccuracyFloorsAreNotLoosened(t *testing.T) {
	ratchet := decodeRatchetFile(t, "corpus/ratchet.json")

	seen := map[string]bool{}
	for _, floor := range ratchet.Floors {
		if floor.Expected.Engine != EngineOwned || floor.Mode.effective() != FloorGateModeAccuracy {
			continue
		}
		target := floor.Expected.TargetID
		want, reviewed := committedOwnedAccuracyFloor[target]
		if !reviewed {
			t.Errorf("owned accuracy floor for target %q is not covered by the reviewed threshold policy; add its reviewed numbers to committedOwnedAccuracyFloor so the floor cannot be lowered unnoticed", target)
			continue
		}
		seen[target] = true
		if floor.MinimumRecall == nil || *floor.MinimumRecall < want.Recall {
			t.Errorf("target %s: committed owned minimum recall %v is below the reviewed floor %v", target, floor.MinimumRecall, want.Recall)
		}
		if floor.MinimumPrecision == nil || *floor.MinimumPrecision < want.Precision {
			t.Errorf("target %s: committed owned minimum precision %v is below the reviewed floor %v", target, floor.MinimumPrecision, want.Precision)
		}
		if floor.AllowUndefinedPrecision {
			t.Errorf("target %s: owned policy must not allow undefined precision", target)
		}
		if floor.MaximumFalseNegatives == nil || *floor.MaximumFalseNegatives > want.MaxFalseNegatives {
			t.Errorf("target %s: committed owned maximum false negatives %v exceeds the reviewed ceiling %d", target, floor.MaximumFalseNegatives, want.MaxFalseNegatives)
		}
		if floor.MaximumFalsePositives == nil || *floor.MaximumFalsePositives > want.MaxFalsePositives {
			t.Errorf("target %s: committed owned maximum false positives %v exceeds the reviewed ceiling %d", target, floor.MaximumFalsePositives, want.MaxFalsePositives)
		}
	}
	for target := range committedOwnedAccuracyFloor {
		if !seen[target] {
			t.Errorf("reviewed owned threshold policy names target %q, which the committed ratchet carries no owned accuracy floor for; remove the stale entry or restore the floor", target)
		}
	}
}

// TestCommittedRatchetHasOneFloorForEveryCatalogEngineTarget checks the committed policy structure only.
// Ratchet floors are release policy, not runtime measurements; measured recall parity is enforced on run metrics
// during the trusted cycle.
func TestCommittedRatchetHasOneFloorForEveryCatalogEngineTarget(t *testing.T) {
	catalogFile, err := os.Open("corpus/catalog.json")
	if err != nil {
		t.Fatalf("open committed catalog: %v", err)
	}
	defer func() { _ = catalogFile.Close() }()
	catalog, err := DecodeCatalog(catalogFile)
	if err != nil {
		t.Fatalf("decode committed catalog: %v", err)
	}
	ratchetFile, err := os.Open("corpus/ratchet.json")
	if err != nil {
		t.Fatalf("open committed ratchet: %v", err)
	}
	defer func() { _ = ratchetFile.Close() }()
	ratchet, err := DecodeRatchet(ratchetFile)
	if err != nil {
		t.Fatalf("decode committed ratchet: %v", err)
	}
	if got, want := len(ratchet.Floors), len(catalog.Targets)*len(Engines()); got != want {
		t.Fatalf("committed ratchet floors = %d, want %d", got, want)
	}
	floors := make(map[observationKey]RatchetFloor, len(ratchet.Floors))
	for _, floor := range ratchet.Floors {
		floors[observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}] = floor
	}
	for _, target := range catalog.Targets {
		for _, engine := range Engines() {
			if _, found := floors[observationKey{Engine: engine, TargetID: target.ID}]; !found {
				t.Errorf("committed ratchet omits policy floor for engine %q target %q", engine, target.ID)
			}
		}
	}
}

func TestCommittedOracleIncludesAdditionalRPMCoverage(t *testing.T) {
	catalogFile, err := os.Open("corpus/catalog.json")
	if err != nil {
		t.Fatalf("open committed catalog: %v", err)
	}
	defer func() { _ = catalogFile.Close() }()
	catalog, err := DecodeCatalog(catalogFile)
	if err != nil {
		t.Fatalf("decode committed catalog: %v", err)
	}
	oracleFile, err := os.Open("corpus/oracle.json")
	if err != nil {
		t.Fatalf("open committed oracle: %v", err)
	}
	defer func() { _ = oracleFile.Close() }()
	oracle, err := DecodeOracle(oracleFile)
	if err != nil {
		t.Fatalf("decode committed oracle: %v", err)
	}

	rpmTargets := map[string]bool{}
	for _, target := range catalog.Targets {
		for _, component := range target.Components {
			if strings.HasPrefix(component.PURL, "pkg:rpm/redhat/") || strings.HasPrefix(component.PURL, "pkg:rpm/oracle/") || strings.HasPrefix(component.PURL, "pkg:rpm/ol/") {
				rpmTargets[target.ID] = true
				break
			}
		}
	}
	if len(rpmTargets) == 0 {
		t.Fatal("committed benchmark must include a Red Hat or Oracle RPM target in addition to SLES")
	}

	for targetID := range rpmTargets {
		positive := false
		negative := false
		for _, testCase := range oracle.Cases {
			if testCase.TargetID != targetID || testCase.Provenance != ProvenanceIndependent || testCase.ReviewStatus != ReviewApproved || len(testCase.Citations) == 0 || testCase.ExpectedCoverage[EngineOwned] != CoverageCovered {
				continue
			}
			switch testCase.Truth {
			case TruthAffected:
				positive = true
			case TruthFixed, TruthNotAffected:
				negative = true
			}
		}
		if positive && negative {
			return
		}
	}
	t.Fatal("additional RPM target must contain provenance-backed covered positive and negative cases")
}
