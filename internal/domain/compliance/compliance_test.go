package compliance

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
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

// Rollup aggregates a finding set into a per-framework rollup: each framework reports FAILED controls (a
// finding mapped) alongside its full assessable-control list (the rest NOT_ASSESSED), and counts each finding
// once per framework. A NOT_ASSESSED control is never a pass.
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

	statusOf := func(fc FrameworkCoverage, id string) (ComplianceStatus, bool) {
		for _, cs := range fc.Controls {
			if cs.Control.ID == id {
				return cs.Status, true
			}
		}
		return "", false
	}

	k := got["CIS-Kubernetes-1.10"]
	if k.Findings != 2 || k.Failed != 2 {
		t.Errorf("K8s rollup: want 2 findings / 2 failed controls, got %+v", k)
	}
	// The full assessable set is listed (denominator), not just the two failed controls.
	if k.Assessable <= 2 || len(k.Controls) != k.Assessable {
		t.Errorf("K8s rollup must list ALL assessable controls (denominator), got assessable=%d controls=%d", k.Assessable, len(k.Controls))
	}
	if st, ok := statusOf(k, "5.2.2"); !ok || st != ControlFailed {
		t.Errorf("K8s 5.2.2 must be FAILED, got %q ok=%v", st, ok)
	}
	// A mapped-but-untouched K8s control is NOT_ASSESSED, never a pass.
	if st, ok := statusOf(k, "5.2.6"); !ok || st != ControlNotAssessed {
		t.Errorf("K8s 5.2.6 (mapped, no finding) must be NOT_ASSESSED, got %q ok=%v", st, ok)
	}

	if a := got["CIS-AWS-3.0"]; a.Findings != 1 || a.Failed != 1 {
		t.Errorf("AWS rollup: want 1 finding / 1 failed control, got %+v", a)
	}
	if _, ok := got["OWASP-2021"]; !ok {
		t.Errorf("CWE-mapped OWASP framework must appear in the rollup, got %v", roll)
	}
}

// TestInterpretiveFrameworksExcluded enforces the #1041 DEFER decision (docs/adr/0009): the curated mapping
// tables use ONLY supported frameworks, and NEVER an interpretive framework (NIST 800-53 / HIPAA / SOC 2 /
// full PCI DSS). This pins the exclusion so an interpretive framework cannot be added without meeting the
// reopening bar (direct per-entry human review + authoritative versioned catalog + provenance).
func TestInterpretiveFrameworksExcluded(t *testing.T) {
	used := map[string]bool{}
	for _, cs := range cweControls {
		for _, c := range cs {
			used[c.Framework] = true
		}
	}
	for _, cs := range ruleControls {
		for _, c := range cs {
			used[c.Framework] = true
		}
	}
	// Every mapped framework must be in the closed supported set.
	for f := range used {
		if !FrameworkSupported(f) {
			t.Errorf("framework %q is mapped but not in the supported set (an interpretive/uncurated mapping): update SupportedFrameworks and the ADR, or remove it", f)
		}
	}
	// No interpretive framework may appear, in any spelling.
	for _, bad := range []string{"NIST-800-53", "NIST-800-53r5", "NIST", "HIPAA", "SOC2", "SOC-2", "PCI-DSS-Full"} {
		if used[bad] || FrameworkSupported(bad) {
			t.Errorf("interpretive framework %q must stay excluded (DEFER decision, ADR 0009); adding it needs the reopening bar", bad)
		}
	}
	// The supported set must be exactly the mapped set (no orphan listed-but-unmapped framework claiming coverage).
	for _, f := range SupportedFrameworks() {
		if !used[f] {
			t.Errorf("framework %q is listed as supported but maps no control; it must not be advertised as assessed", f)
		}
	}
	// Pin the CLOSED set to the exact five curated frameworks. This is what forces the reopening bar: adding
	// ANY new framework (an interpretive one, or a new spelling like NIST-800-53-Rev5) to both a mapping table
	// AND supportedFrameworks still fails here until this literal list and the ADR are updated deliberately.
	wantFrameworks := []string{"CIS-AWS-3.0", "CIS-Kubernetes-1.10", "ISO-27001-2022", "OWASP-2021", "PCI-DSS-4.0"}
	if got := SupportedFrameworks(); !reflect.DeepEqual(got, wantFrameworks) {
		t.Fatalf("supported framework set drifted: got %v, want exactly %v (update ADR 0009 and this list to change the closed set)", got, wantFrameworks)
	}
}
