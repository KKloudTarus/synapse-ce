package compliance

import (
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
