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
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", 0, false},              // v4 not scored
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

func TestCVSSBaseScorePrefersV3ThenV2(t *testing.T) {
	if s, ok := CVSSBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); !ok || math.Abs(s-9.8) > 0.05 {
		t.Fatalf("v3 = %v %v", s, ok)
	}
	if s, ok := CVSSBaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P"); !ok || math.Abs(s-7.5) > 0.05 {
		t.Fatalf("v2 = %v %v", s, ok)
	}
	if _, ok := CVSSBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"); ok {
		t.Fatal("v4 scored")
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
