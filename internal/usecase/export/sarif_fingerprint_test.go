package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func wantFingerprint(dedupKey string) string {
	sum := sha256.Sum256([]byte(dedupKey))
	return hex.EncodeToString(sum[:])
}

// Every result names the finding it reports with the identity Synapse itself deduplicates on, so an
// importer, a code-scanning service or this repository's own SARIF ingest can tell a result it has seen
// before from a new one, whichever runner produced the file and wherever the checkout was.
func TestSARIFResultsCarryTheFindingIdentityAsAPartialFingerprint(t *testing.T) {
	findings := firstPartyFindings()
	log := buildSARIF(findings, "v9", SARIFOptions{Manifest: demoManifests})
	results := log.Runs[0].Results
	if len(results) != len(findings) {
		t.Fatalf("results = %d, want %d", len(results), len(findings))
	}
	seen := map[string]string{}
	for i, r := range results {
		got := r.PartialFingerprints[sarifFingerprintKey]
		if want := wantFingerprint(findings[i].DedupKey); got != want {
			t.Errorf("result %q: partialFingerprints[%q] = %q, want sha256(%q) = %q", r.RuleID, sarifFingerprintKey, got, findings[i].DedupKey, want)
		}
		if len(r.PartialFingerprints) != 1 {
			t.Errorf("result %q: partialFingerprints = %v, want exactly the %q entry", r.RuleID, r.PartialFingerprints, sarifFingerprintKey)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("results %q and %q share fingerprint %q", other, r.RuleID, got)
		}
		seen[got] = r.RuleID
	}
}

// The fingerprint depends on the finding's identity alone: not on the order of the findings, the tool
// version, or what the optional resolvers return. A second run over the same code produces the same values.
func TestSARIFFingerprintIsStableAcrossRuns(t *testing.T) {
	first := buildSARIF(firstPartyFindings(), "v9", SARIFOptions{Manifest: demoManifests})
	reversed := firstPartyFindings()
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	second := buildSARIF(reversed, "v10", SARIFOptions{})
	byKey := map[string]string{}
	for _, r := range second.Runs[0].Results {
		byKey[r.RuleID] = r.PartialFingerprints[sarifFingerprintKey]
	}
	for _, r := range first.Runs[0].Results {
		if got, want := byKey[r.RuleID], r.PartialFingerprints[sarifFingerprintKey]; got != want || want == "" {
			t.Errorf("result %q: fingerprint %q in one run and %q in the other", r.RuleID, want, got)
		}
	}
}

// An importer takes a fingerprint as the tool's word that two results are the same one, and a decision
// recorded against one follows the fingerprint. Two results that share a dedup key would therefore share a
// decision nobody made for the second, so neither gets a fingerprint; a result without one is still a
// valid result, identified by its rule and location instead. A finding without a dedup key has no
// identity to state.
func TestSARIFFingerprintIsNeverShared(t *testing.T) {
	findings := []finding.Finding{
		{ID: "a", Title: "Hardcoded secret (src/a.go:3)", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSecret, DedupKey: "secret:generic-secret:src/a.go:3"},
		{ID: "b", Title: "Hardcoded secret (src/a.go:3)", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSecret, DedupKey: "secret:generic-secret:src/a.go:3"},
		{ID: "c", Title: "Hardcoded secret (src/a.go:9)", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Kind: finding.KindSecret, DedupKey: "secret:generic-secret:src/a.go:9"},
		{ID: "d", Title: "A finding with no identity", Severity: shared.SeverityLow, Status: finding.StatusOpen, Kind: finding.KindSAST, DedupKey: "  "},
	}
	results := buildSARIF(findings, "v9", SARIFOptions{}).Runs[0].Results
	for i, want := range []bool{false, false, true, false} {
		_, has := results[i].PartialFingerprints[sarifFingerprintKey]
		if has != want {
			t.Errorf("finding %q (dedup key %q): has fingerprint = %v, want %v", findings[i].ID, findings[i].DedupKey, has, want)
		}
	}
}

// A result with no fingerprint must not serialize an empty partialFingerprints object.
func TestSARIFOmitsAnEmptyPartialFingerprints(t *testing.T) {
	out, err := MarshalSARIF([]finding.Finding{{ID: "d", Title: "No identity", Severity: shared.SeverityLow, Status: finding.StatusOpen, Kind: finding.KindSAST}}, "v9", SARIFOptions{})
	if err != nil {
		t.Fatalf("MarshalSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	result := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	if _, present := result["partialFingerprints"]; present {
		t.Errorf("result without an identity serialized partialFingerprints: %v", result["partialFingerprints"])
	}
}
