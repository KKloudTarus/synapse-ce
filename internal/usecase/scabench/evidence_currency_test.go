package scabench

import (
	"os"
	"strings"
	"testing"
)

// acceptedTrustedCaptureIdentity is the corpus identity of the last trusted capture that was accepted
// as evidence.
//
// These values are transcribed from `corpus/ratchet-baseline.json`, which
// TestHistoricalRatchetBaselineMatchesAcceptedSnapshot byte-pins to the accepted snapshot. They are
// repeated here as literals rather than read from that file on purpose: the point of the assertion
// below is to notice when the committed corpus moves away from accepted evidence, and reading both
// sides from files that move together would make the comparison vacuous.
const (
	acceptedCaptureCatalogRevision = "same-sbom-linux-20260915"
	acceptedCaptureCatalogDigest   = "sha256:d4f20730f1f4c5cdaf2fdbe7aecb11d8b1ec9b3be1a3c014189d10337cffe0ae"
	acceptedCaptureOracleDigest    = "sha256:fe8d04122b7996c9dd5a835defe128827e131332ce9408a890a475c73548582b"
)

// acknowledgedEvidenceDebt records that the committed corpus has outrun its accepted evidence, and
// names what must be revalidated.
//
// This is deliberately a stated debt rather than a passing test. Implementation completeness and
// evidence currency drifted apart silently twice: the catalog revision moved 20260915 -> 20260921 ->
// 20260922 and the oracle digest moved fe8d0412 -> 750dae1c -> a6d7092b, each time after the evidence
// resting on the older identity had been accepted. Nothing failed, because no test compared the two.
//
// Clearing this debt means running a trusted capture against the current corpus and promoting its
// identity here and into `corpus/ratchet-baseline.json`. Until then the floors on targets added after
// the baseline rest on no accepted measurement.
const acknowledgedEvidenceDebt = `The committed corpus has moved past its accepted evidence.

Accepted trusted capture (corpus/ratchet-baseline.json, 8 floors, Debian and SLES only):
  catalog_revision  same-sbom-linux-20260915
  oracle_digest     sha256:fe8d0412...

Committed corpus (corpus/ratchet.json, 12 floors, adds rhel-9-8-ubi-amd64):
  catalog_revision  same-sbom-linux-20260922
  oracle_digest     sha256:8012364a...

The oracle digest moved from sha256:a6d7092b under ADR 0010, which re-cited the
CVE-2026-22185 / openldap case from the binary-aware CSAF VEX to the package-granular
Red Hat Security Data API record. Truth and expected coverage are unchanged, so the
measured outcome is unchanged; only the evidence the label rests on was corrected.

Consequences, all currently true:
  - ValidateRatchetTightening cannot be applied to the committed pair: it requires an identical
    catalog revision and an identical oracle digest, and both differ.
  - TestCandidateRatchetPreservesHistoricalFloorPolicy iterates the baseline's floors, so floors on
    targets added after the baseline are covered by no monotonicity check.
  - The rhel-9-8-ubi-amd64 floors have never been satisfied by an accepted capture.

Revalidation is tracked as EPIC #1034 wave 2 item 9.`

// TestCommittedCorpusEvidenceCurrency reports whether the committed corpus still matches the identity
// of the last accepted trusted capture.
//
// This is the protection the EPIC register asked for. It is the same class of check as requiring an
// absent committed floor to fail rather than pass quietly: a corpus that has outrun its evidence
// should say so on every test run rather than be rediscovered during an audit.
//
// While the debt above stands the test documents it instead of failing, because the divergence is
// known, deliberate, and already tracked — failing here would turn a standing condition into
// permanent red that carries no new information. The assertions that follow keep that exemption from
// becoming a way to hide a second, different divergence.
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

	baseline := decodeRatchetFile(t, "corpus/ratchet-baseline.json")
	committed := decodeRatchetFile(t, "corpus/ratchet.json")

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

	// The accepted identity recorded here must still describe the pinned baseline. If someone advances
	// the baseline without advancing these constants, the comparison below would silently start
	// measuring against the wrong evidence.
	if baseline.CatalogRevision != acceptedCaptureCatalogRevision {
		t.Fatalf("accepted capture catalog revision %q no longer matches the pinned baseline %q; update the constant and the debt note together",
			acceptedCaptureCatalogRevision, baseline.CatalogRevision)
	}
	if baseline.CatalogDigest != acceptedCaptureCatalogDigest {
		t.Fatalf("accepted capture catalog digest %q no longer matches the pinned baseline %q", acceptedCaptureCatalogDigest, baseline.CatalogDigest)
	}
	if baseline.OracleDigest != acceptedCaptureOracleDigest {
		t.Fatalf("accepted capture oracle digest %q no longer matches the pinned baseline %q", acceptedCaptureOracleDigest, baseline.OracleDigest)
	}

	current := committed.CatalogRevision == acceptedCaptureCatalogRevision &&
		committed.CatalogDigest == acceptedCaptureCatalogDigest &&
		committed.OracleDigest == acceptedCaptureOracleDigest
	if current {
		// The corpus caught up with its evidence, so the recorded debt is stale and must be removed
		// rather than left to assert something that is no longer true.
		if strings.Contains(acknowledgedEvidenceDebt, "has moved past its accepted evidence") {
			t.Fatal("the committed corpus now matches its accepted evidence; remove acknowledgedEvidenceDebt and the exemption in this test")
		}
		return
	}

	// Divergence is expected today. Report it so every run states the corpus's true evidence standing.
	t.Log(acknowledgedEvidenceDebt)

	// The exemption covers exactly the divergence described above. A corpus that has moved somewhere
	// else has not been reviewed, so it must fail rather than inherit this acknowledgement.
	const (
		acknowledgedCommittedRevision    = "same-sbom-linux-20260922"
		acknowledgedCommittedOracleDiges = "sha256:8012364a316d6ae05c350d1d5ce0d8730b3ec28163822a0ff41aa7b76d4096ea"
	)
	if committed.CatalogRevision != acknowledgedCommittedRevision {
		t.Fatalf("committed catalog revision %q is not the acknowledged divergence %q; revalidate the corpus or update the debt note",
			committed.CatalogRevision, acknowledgedCommittedRevision)
	}
	if committed.OracleDigest != acknowledgedCommittedOracleDiges {
		t.Fatalf("committed oracle digest %q is not the acknowledged divergence %q; the oracle changed after this debt was reviewed",
			committed.OracleDigest, acknowledgedCommittedOracleDiges)
	}
}

// TestAcknowledgedEvidenceDebtNamesItsRevalidation keeps the debt note from decaying into a bare
// statement that something is wrong. The note is the only place a reader learns why
// ValidateRatchetTightening cannot run on the committed pair, so it must keep saying so.
func TestAcknowledgedEvidenceDebtNamesItsRevalidation(t *testing.T) {
	for _, required := range []string{
		"ValidateRatchetTightening",
		"rhel-9-8-ubi-amd64",
		"#1034",
		acceptedCaptureCatalogRevision,
	} {
		if !strings.Contains(acknowledgedEvidenceDebt, required) {
			t.Errorf("the evidence debt note must mention %q", required)
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
