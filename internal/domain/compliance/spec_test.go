package compliance

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestEvaluate(t *testing.T) {
	findings := []finding.Finding{
		{Title: "SQL injection in login", CWE: "CWE-89", Severity: shared.SeverityHigh, Kind: finding.KindSAST},
		{Title: "Hardcoded AWS key", Kind: finding.KindSecret, Severity: shared.SeverityCritical},
		{Title: "Dockerfile runs as root", Kind: finding.KindMisconfig, Severity: shared.SeverityHigh},
	}
	rep := Evaluate(BaselineSpec(), findings)

	byID := map[string]ControlResult{}
	for _, r := range rep.Results {
		byID[r.Control.ID] = r
	}
	// SAB-INJ-1 fails via CWE-89, with the finding title as evidence.
	if inj := byID["SAB-INJ-1"]; inj.Passed || len(inj.Evidence) != 1 || inj.Evidence[0] != "SQL injection in login" {
		t.Errorf("SAB-INJ-1 must FAIL on CWE-89 with evidence, got %+v", inj)
	}
	// SAB-SECRET-1 fails via Kind=secret.
	if byID["SAB-SECRET-1"].Passed {
		t.Error("SAB-SECRET-1 must FAIL on a secret finding")
	}
	// SAB-IAC-1 fails via Kind=misconfig.
	if byID["SAB-IAC-1"].Passed {
		t.Error("SAB-IAC-1 must FAIL on a misconfig finding")
	}
	// SAB-SEV-1 fails via the critical secret finding.
	if byID["SAB-SEV-1"].Passed {
		t.Error("SAB-SEV-1 must FAIL when any finding is critical")
	}
	// SAB-CRYPTO-1 passes (no crypto CWE present).
	if !byID["SAB-CRYPTO-1"].Passed {
		t.Error("SAB-CRYPTO-1 must PASS when no crypto weakness is present")
	}
	if rep.Failed < 4 || rep.Passed+rep.Failed != len(rep.Results) {
		t.Errorf("tally mismatch: passed=%d failed=%d results=%d", rep.Passed, rep.Failed, len(rep.Results))
	}
}

func TestEvaluateCleanScanAllPass(t *testing.T) {
	rep := Evaluate(BaselineSpec(), nil)
	if rep.Failed != 0 || rep.Passed != len(BaselineSpec().Controls) {
		t.Errorf("a finding-free scan must pass every control, got passed=%d failed=%d", rep.Passed, rep.Failed)
	}
}

func TestBaselineSpecControlIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range BaselineSpec().Controls {
		if c.ID == "" || c.Title == "" {
			t.Errorf("control has empty id/title: %+v", c)
		}
		if seen[c.ID] {
			t.Errorf("duplicate control id %q", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestCWENormalizationInJoin(t *testing.T) {
	// A finding CWE written as a bare number or lower-case must still match a "CWE-89" control key.
	spec := Spec{ID: "t", Controls: []SpecControl{{ID: "C1", Title: "inj", CWEs: []string{"CWE-89"}}}}
	for _, cwe := range []string{"89", "cwe-89", "CWE-089"} {
		rep := Evaluate(spec, []finding.Finding{{Title: "x", CWE: cwe}})
		if rep.Results[0].Passed {
			t.Errorf("CWE %q must match control key CWE-89 (normalized)", cwe)
		}
	}
}
