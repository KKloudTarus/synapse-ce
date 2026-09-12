package compliance

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"testing"
)

// TestControlsForSASTCWEs: the CWEs the pattern-SAST analyzer emits today all map (so a SAST finding always
// carries compliance tags), to their published OWASP 2021 categories.
func TestControlsForSASTCWEs(t *testing.T) {
	cases := map[string]string{
		"CWE-327": "A02:2021", // weak crypto → Cryptographic Failures
		"CWE-295": "A02:2021", // improper cert validation → Cryptographic Failures
		"CWE-798": "A07:2021", // hardcoded creds → Identification and Authentication Failures
	}
	for cwe, wantOWASP := range cases {
		got := ControlsFor(cwe)
		if len(got) == 0 {
			t.Fatalf("%s must map to at least one control", cwe)
		}
		if !hasControl(got, "OWASP-2021", wantOWASP) {
			t.Errorf("%s: want OWASP %s, got %+v", cwe, wantOWASP, got)
		}
		if !hasControl(got, "ISO-27001-2022", "A.8.28") {
			t.Errorf("%s: every code-weakness CWE maps to ISO A.8.28 (secure coding), got %+v", cwe, got)
		}
	}
}

// TestControlsForInjectionClasses: the injection family maps to OWASP A03 + PCI 6.2.4 (an enumerated class).
func TestControlsForInjectionClasses(t *testing.T) {
	for _, cwe := range []string{"CWE-89", "CWE-79", "CWE-78", "CWE-94"} {
		got := ControlsFor(cwe)
		if !hasControl(got, "OWASP-2021", "A03:2021") {
			t.Errorf("%s must map to OWASP A03 Injection, got %+v", cwe, got)
		}
		if !hasControl(got, "PCI-DSS-4.0", "6.2.4") {
			t.Errorf("%s (an injection class PCI 6.2.4 enumerates) must map to PCI 6.2.4, got %+v", cwe, got)
		}
	}
}

// TestControlsForNotOverClaimedPCI: SSRF / deserialization / cert-validation are NOT in PCI 6.2.4's
// enumerated list, so the table must NOT claim PCI for them (no fabricated mapping).
func TestControlsForNotOverClaimedPCI(t *testing.T) {
	for _, cwe := range []string{"CWE-918", "CWE-502", "CWE-295"} {
		if hasControl(ControlsFor(cwe), "PCI-DSS-4.0", "6.2.4") {
			t.Errorf("%s must NOT claim PCI 6.2.4 (not in its enumerated list)", cwe)
		}
	}
	if !hasControl(ControlsFor("CWE-918"), "OWASP-2021", "A10:2021") {
		t.Error("CWE-918 must map to OWASP A10 SSRF")
	}
}

// TestControlsForNormalization: the lookup tolerates case + a bare number + whitespace; deterministic order.
func TestControlsForNormalization(t *testing.T) {
	canonical := ControlsFor("CWE-89")
	for _, variant := range []string{"cwe-89", " CWE-89 ", "89", "Cwe-89", "CWE-089", "089"} {
		if g := ControlsFor(variant); len(g) != len(canonical) || g[0] != canonical[0] {
			t.Errorf("ControlsFor(%q) must equal the canonical lookup, got %+v", variant, g)
		}
	}
	// deterministic order: framework then id
	got := ControlsFor("CWE-89")
	for i := 1; i < len(got); i++ {
		if got[i-1].Framework > got[i].Framework {
			t.Errorf("controls must be sorted by framework: %+v", got)
		}
	}
}

// TestControlsForUnmappedAndEmpty: an unmapped or non-CWE token returns nil – never a guessed mapping.
func TestControlsForUnmappedAndEmpty(t *testing.T) {
	for _, in := range []string{"", "  ", "CWE-99999", "not-a-cwe", "CWE-", "CWE-abc", "+89", "-1", "CWE 89"} {
		if got := ControlsFor(in); got != nil {
			t.Errorf("ControlsFor(%q) must be nil (unmapped/invalid), got %+v", in, got)
		}
	}
}

func hasControl(cs []Control, framework, id string) bool {
	for _, c := range cs {
		if c.Framework == framework && c.ID == id {
			return true
		}
	}
	return false
}

// EPIC #860 D6.6: a misconfiguration rule maps to its published CIS Benchmark control (verbatim id+title),
// an unmapped rule yields none, and ControlsForFinding unions the CWE-mapped and rule-mapped controls.
func TestControlsForRuleAndFinding(t *testing.T) {
	// a mapped AWS rule -> the exact CIS AWS control
	aws := ControlsForRule("cloudformation-rds-unencrypted")
	if len(aws) != 1 || aws[0].Framework != "CIS-AWS-3.0" || aws[0].ID != "2.3.1" {
		t.Fatalf("rds rule must map to CIS-AWS-3.0 2.3.1, got %+v", aws)
	}
	// a mapped K8s rule
	k8s := ControlsForRule("kubernetes-privileged")
	if len(k8s) != 1 || k8s[0].Framework != "CIS-Kubernetes-1.10" || k8s[0].ID != "5.2.2" {
		t.Fatalf("privileged rule must map to CIS-Kubernetes-1.10 5.2.2, got %+v", k8s)
	}
	// an unmapped rule (broader than any single CIS control) yields nothing, never a guess
	if got := ControlsForRule("cloudformation-open-security-group"); got != nil {
		t.Errorf("a rule with no exact CIS match must map to nothing, got %+v", got)
	}
	if got := ControlsForRule(""); got != nil {
		t.Errorf("empty rule key must map to nothing, got %+v", got)
	}
	// ControlsForFinding unions the CWE controls (OWASP/PCI/ISO) with the rule's CIS control
	both := ControlsForFinding("CWE-311", "cloudformation-rds-unencrypted")
	if !hasControl(both, "CIS-AWS-3.0", "2.3.1") {
		t.Errorf("ControlsForFinding must include the rule's CIS control, got %+v", both)
	}
}

// Rollup aggregates a finding set into a per-framework rollup, counting each finding once per framework.
func TestComplianceRollup(t *testing.T) {
	findings := []finding.Finding{
		{RuleKey: "kubernetes-privileged"},          // CIS-Kubernetes-1.10 5.2.2
		{RuleKey: "kubernetes-host-network"},        // CIS-Kubernetes-1.10 5.2.5
		{RuleKey: "cloudformation-rds-unencrypted"}, // CIS-AWS-3.0 2.3.1
		{CWE: "CWE-89"},           // OWASP/PCI/ISO
		{RuleKey: "no-such-rule"}, // maps to nothing
	}
	roll := Rollup(findings)
	got := map[string]FrameworkCoverage{}
	for _, fc := range roll {
		got[fc.Framework] = fc
	}
	if k := got["CIS-Kubernetes-1.10"]; k.Findings != 2 || len(k.Controls) != 2 {
		t.Errorf("K8s rollup: want 2 findings / 2 controls, got %+v", k)
	}
	if a := got["CIS-AWS-3.0"]; a.Findings != 1 || len(a.Controls) != 1 {
		t.Errorf("AWS rollup: want 1 finding / 1 control, got %+v", a)
	}
	if _, ok := got["OWASP-2021"]; !ok {
		t.Errorf("CWE-mapped OWASP framework must appear in the rollup, got %v", roll)
	}
}
