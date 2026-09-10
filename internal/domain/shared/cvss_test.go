package shared

import (
	"math"
	"testing"
)

func TestCVSSv3BaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		ok     bool
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},  // critical
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, true},  // low
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, true}, // scope changed → 10.0
		{"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, true},  // v3.0
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", 0, false},              // v4 is not a v3 vector
		{"not-a-vector", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := CVSSv3BaseScore(c.vector)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.vector, ok, c.ok)
			continue
		}
		if ok && math.Abs(got-c.want) > 0.05 {
			t.Errorf("%s: score=%.2f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSSv2BaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		ok     bool
	}{
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, true},                  // the classic remote partial triple
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, true},        // grype prefixes v2 vectors
		{"(AV:L/AC:H/Au:N/C:C/I:C/A:C)", 6.2, true},                // NVD parentheses form
		{"AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3, true},                  // reflected XSS shape
		{"AV:N/AC:L/Au:N/C:N/I:N/A:N", 0, true},                    // no impact scores 0
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0, false}, // v3 is not v2
		{"AV:N/AC:L/Au:N/C:P/I:P", 0, false},                       // missing metric
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := CVSSv2BaseScore(c.vector)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.vector, ok, c.ok)
			continue
		}
		if ok && math.Abs(got-c.want) > 0.05 {
			t.Errorf("%s: score=%.2f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSSBaseScorePrefersV4ThenV3ThenV2(t *testing.T) {
	if s, ok := CVSSBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"); !ok || math.Abs(s-10.0) > 0.05 {
		t.Fatalf("v4 = %v %v", s, ok)
	}
	if s, ok := CVSSBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); !ok || math.Abs(s-9.8) > 0.05 {
		t.Fatalf("v3 = %v %v", s, ok)
	}
	if s, ok := CVSSBaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P"); !ok || math.Abs(s-7.5) > 0.05 {
		t.Fatalf("v2 = %v %v", s, ok)
	}
	if _, ok := CVSSBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"); ok {
		t.Fatal("an incomplete v4 vector must not score")
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{9.8, SeverityCritical}, {9.0, SeverityCritical},
		{8.9, SeverityHigh}, {7.0, SeverityHigh},
		{6.9, SeverityMedium}, {4.0, SeverityMedium},
		{3.9, SeverityLow}, {0.1, SeverityLow},
		{0.0, SeverityInfo},
	}
	for _, c := range cases {
		if got := SeverityFromScore(c.score); got != c.want {
			t.Errorf("SeverityFromScore(%.1f) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestSeverityFromLabel(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL": SeverityCritical, "critical": SeverityCritical,
		"HIGH": SeverityHigh, "High": SeverityHigh,
		"MODERATE": SeverityMedium, "MEDIUM": SeverityMedium,
		"LOW": SeverityLow, " low ": SeverityLow,
		"": SeverityUnknown, "bogus": SeverityUnknown,
	}
	for label, want := range cases {
		if got := SeverityFromLabel(label); got != want {
			t.Errorf("SeverityFromLabel(%q) = %q, want %q", label, got, want)
		}
	}
}

// TestCVSSv40BaseScore validates the CVSS v4.0 port against ground-truth scores produced by the
// FIRST.org reference calculator (the published cvss_lookup / max_composed / max_severity tables and
// the cvss_score interpolation). The vectors span the max (10.0), the no-impact shortcut (0.0),
// single-dimension impacts, and threat/environmental modifiers.
func TestCVSSv40BaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		ok     bool
	}{
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10, true},                 // macro 000100
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0, true},                  // macro 002201
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 6.9, true},                // macro 002201
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 1, true},                  // macro 212201
		{"CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1, true},                // macro 101200
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, true},                // macro 000200
		{"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.3, true},                // macro 100100
		{"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 2.3, true},                // macro 112201
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 1, true},                  // macro 212201
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L", 9.3, true},                // macro 001100
		{"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:H/SA:N", 5.6, true},                // macro 211100
		{"CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:L/SI:N/SA:H", 7, true},                  // macro 111100
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", 7.9, true},                // macro 002101
		{"CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 8.6, true},                // macro 200100
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 5.1, true},                // macro 102201
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U", 9.1, true},            // macro 000120
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P", 9.3, true},            // macro 000110
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L", 9.6, true}, // macro 000101
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S", 10, true},           // macro 000000
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:P/E:U/CR:L", 5.5, true}, // macro 200120
	}
	for _, c := range cases {
		got, ok := CVSSv40BaseScore(c.vector)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.vector, ok, c.ok)
			continue
		}
		if ok && math.Abs(got-c.want) > 0.001 {
			t.Errorf("%s: score=%.2f, want %.1f", c.vector, got, c.want)
		}
	}
}

// TestCVSSv40BaseScoreRejectsMalformed asserts that a vector missing a mandatory base metric, carrying
// an out-of-set value, using an unknown metric key, repeating a metric, or lacking the v4.0 prefix is
// rejected rather than silently scored.
func TestCVSSv40BaseScoreRejectsMalformed(t *testing.T) {
	bad := []string{
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",                                    // missing VC..SA
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H",           // missing SA
		"CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",      // AV:X is not a base value
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/ZZ:Q", // unknown metric
		"CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // duplicate AV
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                         // v3, not v4
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/SI:L", // duplicate SI
		"",
	}
	for _, v := range bad {
		if s, ok := CVSSv40BaseScore(v); ok {
			t.Errorf("malformed %q scored %.1f, want (0,false)", v, s)
		}
	}
}
