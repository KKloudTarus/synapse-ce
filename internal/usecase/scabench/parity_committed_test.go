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
