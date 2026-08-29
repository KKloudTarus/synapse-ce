package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestZeroRiskAndEvidenceOmittedFromJSON: a scan path that does not compute risk/evidence (e.g. the CLI)
// must not emit "RiskScore":0 / "EvidenceScore":0, which reads as a broken tool; when computed they stay.
func TestZeroRiskAndEvidenceOmittedFromJSON(t *testing.T) {
	zero, err := json.Marshal(Finding{Title: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(zero), "RiskScore") || strings.Contains(string(zero), "EvidenceScore") {
		t.Fatalf("zero RiskScore/EvidenceScore must be omitted from JSON: %s", zero)
	}
	scored, err := json.Marshal(Finding{Title: "x", RiskScore: 42, EvidenceScore: 80})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(scored), "RiskScore") || !strings.Contains(string(scored), "EvidenceScore") {
		t.Fatalf("computed RiskScore/EvidenceScore must be present: %s", scored)
	}
}
