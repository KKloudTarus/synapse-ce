package scabench

import (
	"encoding/json"
	"os"
	"testing"
)

// TestCommittedCorpusEvidenceCurrency binds the current corpus to the accepted comparison.
// Historical ratchet-baseline.json remains frozen as a record of earlier policy.
func TestCommittedCorpusEvidenceCurrency(t *testing.T) {
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

	committed := decodeRatchetFile(t, "corpus/ratchet.json")
	if committed.CatalogRevision != catalog.Revision {
		t.Fatalf("committed ratchet catalog revision %q does not match catalog %q", committed.CatalogRevision, catalog.Revision)
	}

	catalogDigest, err := DigestCatalog(catalog)
	if err != nil {
		t.Fatalf("digest committed catalog: %v", err)
	}
	if committed.CatalogDigest != catalogDigest {
		t.Fatalf("committed ratchet catalog digest %q does not match canonical committed catalog digest %q", committed.CatalogDigest, catalogDigest)
	}
	oracleDigest, err := DigestOracle(oracle)
	if err != nil {
		t.Fatalf("digest committed oracle: %v", err)
	}
	if committed.OracleDigest != oracleDigest {
		t.Fatalf("committed ratchet oracle digest %q does not match canonical committed oracle digest %q", committed.OracleDigest, oracleDigest)
	}

	ratchetDigest, err := DigestRatchet(committed)
	if err != nil {
		t.Fatalf("digest committed ratchet: %v", err)
	}
	policyBytes, err := os.ReadFile("corpus/cycle-policy.json")
	if err != nil {
		t.Fatalf("read committed cycle policy: %v", err)
	}
	captureBytes, err := os.ReadFile("testdata/accepted-capture.json")
	if err != nil {
		t.Fatalf("read accepted comparison: %v", err)
	}
	var capture struct {
		SchemaVersion string            `json:"schema_version"`
		Accepted      bool              `json:"accepted"`
		Observations  int               `json:"observations"`
		InputDigests  map[string]string `json:"input_digests"`
	}
	if err := json.Unmarshal(captureBytes, &capture); err != nil {
		t.Fatalf("decode accepted comparison: %v", err)
	}
	if capture.SchemaVersion != "synapse-sca-trusted-acceptance-report-v1" || !capture.Accepted || capture.Observations != 24 {
		t.Fatalf("comparison is not an accepted 24-observation capture: schema=%q accepted=%t observations=%d", capture.SchemaVersion, capture.Accepted, capture.Observations)
	}
	for name, current := range map[string]string{
		"catalog": catalogDigest,
		"oracle":  oracleDigest,
		"ratchet": ratchetDigest,
		"policy":  SHA256Digest(policyBytes),
	} {
		if capture.InputDigests[name] != current {
			t.Errorf("accepted comparison %s digest %q does not match committed %q", name, capture.InputDigests[name], current)
		}
	}
}

// TestCommittedRatchetCoversEveryBaselineTarget keeps a revalidation from quietly dropping a target
// that already had accepted evidence. Removing a floor is a coverage regression that no threshold
// comparison would catch, because a floor that is absent is never compared.
func TestCommittedRatchetCoversEveryBaselineTarget(t *testing.T) {
	baseline := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	committed := decodeRatchetFile(t, "corpus/ratchet.json")

	present := make(map[observationKey]struct{}, len(committed.Floors))
	for _, floor := range committed.Floors {
		present[observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}] = struct{}{}
	}
	for _, floor := range baseline.Floors {
		key := observationKey{Engine: floor.Expected.Engine, TargetID: floor.Expected.TargetID}
		if _, exists := present[key]; !exists {
			t.Errorf("committed ratchet drops the accepted floor for engine %q target %q", key.Engine, key.TargetID)
		}
	}
}

// TestCommittedRatchetTargetsAreAllOracleBacked keeps a floor from resting on a target the oracle does
// not describe. A floor whose target has no oracle case cannot be measured, so it would read as
// protection while gating nothing — the same defect class as the unsatisfiable RHEL floor.
func TestCommittedRatchetTargetsAreAllOracleBacked(t *testing.T) {
	committed := decodeRatchetFile(t, "corpus/ratchet.json")
	oracleFile, err := os.Open("corpus/oracle.json")
	if err != nil {
		t.Fatalf("open committed oracle: %v", err)
	}
	defer func() { _ = oracleFile.Close() }()
	oracle, err := DecodeOracle(oracleFile)
	if err != nil {
		t.Fatalf("decode committed oracle: %v", err)
	}

	described := make(map[string]int, len(oracle.Cases))
	for _, oracleCase := range oracle.Cases {
		described[oracleCase.TargetID]++
	}
	for _, floor := range committed.Floors {
		if described[floor.Expected.TargetID] == 0 {
			t.Errorf("ratchet floor for target %q has no oracle case, so it can never be measured", floor.Expected.TargetID)
		}
	}
}
